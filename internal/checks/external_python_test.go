package checks

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ispwatch/collector/internal/checkpackages"
)

const externalTestID = "11111111-1111-4111-8111-111111111111"
const externalTestHostUUID = "22222222-2222-4222-8222-222222222222"

func signedExternalCheck(t *testing.T, script string) *externalPythonCheck {
	t.Helper()
	python := strings.TrimSpace(os.Getenv("TELVYN_TEST_PYTHON"))
	if python == "" {
		var err error
		python, err = exec.LookPath("python3")
		if err != nil {
			python, err = exec.LookPath("python")
		}
		if err != nil {
			t.Skip("Python runtime not installed")
		}
	}
	if !filepath.IsAbs(python) {
		t.Fatalf("Python test runtime must be absolute: %q", python)
	}
	base := t.TempDir()
	root, trust := filepath.Join(base, "packages"), filepath.Join(base, "trust")
	dir := filepath.Join(root, "proxmox", "1.0.0")
	for _, path := range []string{dir, trust} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{"runner.py": []byte(script), "common.py": []byte("VALUE = 1\n")}
	hashes := map[string]string{}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		hashes[name] = hex.EncodeToString(digest[:])
	}
	manifest := checkpackages.Manifest{
		Name: "proxmox", Version: "1.0.0", KeyID: "release", ProtocolVersion: 1,
		Runtime: "python3", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		IsolationMode: "approved-unisolated", Checks: []string{"proxmox"}, Files: hashes,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(trust, "release.pub"), []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(private, raw))), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TELVYN_EXTERNAL_PACKAGE_DIR", root)
	t.Setenv("TELVYN_EXTERNAL_TRUST_DIR", trust)
	t.Setenv("TELVYN_EXTERNAL_PYTHON", python)
	t.Setenv("TELVYN_EXTERNAL_EXECUTION_MODE", "approved-unisolated")
	t.Setenv("TELVYN_EXTERNAL_APPROVED_ENDPOINTS", "https://example.invalid")
	cfg := &collectorv1.CheckConfig{
		CheckId: externalTestID, CheckType: "external.python", HostId: "host-7", Enabled: true,
		Interval:   durationpb.New(time.Minute),
		Params:     map[string]string{"package": "proxmox", "version": "1.0.0", "check": "proxmox", "endpoint": "https://example.invalid"},
		StaticTags: map[string]string{"tenant_id": "tenant-a", "host_uuid": externalTestHostUUID},
	}
	check, err := newExternalPythonCheck(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return check.(*externalPythonCheck)
}

func TestExternalSignedPythonTwice(t *testing.T) {
	script := `import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import VALUE
from datetime import datetime, timezone
request = json.load(sys.stdin)
now = datetime.now(timezone.utc).isoformat()
tags = dict(request["static_tags"])
tags.update({"provider": "proxmox", "resource_type": "qemu", "instance_id": request["instance_id"]})
print(json.dumps({"protocol_version": 1, "status": "ok", "coverage": {"resources": VALUE}, "error": None,
"metrics": [{"name": "telvyn.proxmox.up", "value": 1, "type": "gauge", "unit": "boolean", "timestamp": now, "resource_id": "qemu/100", "tags": tags}],
"inventory": [{"resource_id": "qemu/100", "type": "qemu", "name": "VM 100", "state": "running", "parent_id": None, "observed_at": now}]}))
`
	check := signedExternalCheck(t, script)
	for i := 0; i < 2; i++ {
		metrics, err := check.Run(context.Background())
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if len(metrics) != 1 || metrics[0].GetValue() != 1 || metrics[0].GetHostId() != "host-7" ||
			metrics[0].GetTags()["tenant_id"] != "tenant-a" || metrics[0].GetTags()["host_uuid"] != externalTestHostUUID {
			t.Fatalf("run %d wrong metrics: %+v", i, metrics)
		}
	}
	inventory, coverage, status := check.InventorySnapshot()
	if len(inventory) != 1 || inventory[0].ResourceID != "qemu/100" || status != "ok" || !strings.Contains(string(coverage), `"resources":1`) {
		t.Fatalf("unexpected local inventory: %+v %s %s", inventory, coverage, status)
	}
	if _, err := os.Stat(filepath.Join(check.packageDir, "proxmox", "1.0.0", "__pycache__")); !os.IsNotExist(err) {
		t.Fatalf("Python wrote bytecode into signed package: %v", err)
	}
}

func TestExternalDeadline(t *testing.T) {
	check := signedExternalCheck(t, "import time\ntime.sleep(5)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := check.Run(ctx); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("deadline not enforced: %v", err)
	}
}

func TestExternalInvalidJSONAndRequiredValue(t *testing.T) {
	if _, _, _, _, err := mapExternalResponse([]byte(`{"protocol_version":1}`+" garbage"), externalTestID, "host-7", "proxmox", nil); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, _, _, _, err := mapExternalResponse([]byte(`{bad`), externalTestID, "host-7", "proxmox", nil); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	base := map[string]any{"protocol_version": 1, "status": "ok", "coverage": map[string]any{}, "inventory": []any{},
		"metrics": []any{map[string]any{"name": "telvyn.proxmox.up", "type": "gauge", "unit": "boolean", "timestamp": now, "resource_id": "qemu/100", "tags": map[string]string{"provider": "proxmox"}}}}
	raw, _ := json.Marshal(base)
	if _, _, _, _, err := mapExternalResponse(raw, externalTestID, "host-7", "proxmox", nil); err == nil {
		t.Fatal("metric without value accepted as zero")
	}
	metric := base["metrics"].([]any)[0].(map[string]any)
	metric["value"] = 0
	metric["tags"] = map[string]string{"provider": "proxmox", "tenant_id": "other-tenant"}
	raw, _ = json.Marshal(base)
	if _, _, _, _, err := mapExternalResponse(raw, externalTestID, "host-7", "proxmox", map[string]string{"tenant_id": "tenant-a"}); err == nil {
		t.Fatal("runner overrode core tenant tag")
	}
	metric["tags"] = map[string]string{"provider": "proxmox", "tenant_id": "tenant-a"}
	raw, _ = json.Marshal(base)
	metrics, _, _, _, err := mapExternalResponse(raw, externalTestID, "host-7", "proxmox", map[string]string{"tenant_id": "tenant-a"})
	if err != nil || len(metrics) != 1 || metrics[0].GetValue() != 0 {
		t.Fatalf("real zero rejected: %v %+v", err, metrics)
	}
}
