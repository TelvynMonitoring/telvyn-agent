package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ispwatch/collector/internal/checkpackages"
	"github.com/ispwatch/collector/internal/inventory"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const externalInputLimit = 1 << 20
const externalOutputLimit = 2 << 20
const externalStderrLimit = 4 << 10

var externalUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`)

type externalPythonCheck struct {
	id, hostID, packageName, packageVersion, checkName string
	packageDir, trustDir, python                       string
	interval                                           time.Duration
	params, staticTags                                 map[string]string
	mu                                                 sync.RWMutex
	inventory                                          []ExternalInventory
	coverage                                           json.RawMessage
	status                                             string
	configVersion                                      int64
	report                                             *inventory.Snapshot
}

type externalRequest struct {
	ProtocolVersion int               `json:"protocol_version"`
	InstanceID      string            `json:"instance_id"`
	Params          map[string]string `json:"params"`
	StaticTags      map[string]string `json:"static_tags"`
}

func newExternalPythonCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	if cfg == nil || !externalUUID.MatchString(cfg.GetCheckId()) {
		return nil, errors.New("external.python: check_id must be a UUID")
	}
	if strings.TrimSpace(cfg.GetHostId()) == "" {
		return nil, errors.New("external.python: core host_id required")
	}
	params := cfg.GetParams()
	configVersion, _ := strconv.ParseInt(params[inventory.ConfigVersionParam], 10, 64)
	name, version, check := params["package"], params["version"], params["check"]
	root := os.Getenv("TELVYN_EXTERNAL_PACKAGE_DIR")
	trust := os.Getenv("TELVYN_EXTERNAL_TRUST_DIR")
	python := os.Getenv("TELVYN_EXTERNAL_PYTHON")
	if root == "" {
		root = "/opt/telvyn/integrations/packages"
	}
	if trust == "" {
		trust = "/opt/telvyn/integrations/trust"
	}
	if python == "" {
		python = "/usr/bin/python3"
	}
	if os.Getenv("TELVYN_EXTERNAL_EXECUTION_MODE") != "approved-unisolated" {
		return nil, errors.New("external.python: required isolation mode unsupported; local admin opt-in required")
	}
	if !filepath.IsAbs(python) {
		return nil, errors.New("external.python: local Python executable must be absolute")
	}
	resolvedPython, err := filepath.EvalSymlinks(python)
	if err != nil {
		return nil, errors.New("external.python: Python runtime unavailable")
	}
	info, err := os.Stat(resolvedPython)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("external.python: Python runtime unavailable")
	}
	if _, err := checkpackages.Verify(root, trust, name, version, check); err != nil {
		return nil, fmt.Errorf("external.python: package rejected: %w", err)
	}
	requestParams := make(map[string]string, len(params))
	for key, value := range params {
		switch strings.ToLower(key) {
		case "package", "version", "check", inventory.ConfigVersionParam:
			continue
		case "package_dir", "trust_dir", "trusted_keys", "python", "python_exe", "isolation_mode", "execution_mode", "ingest_token", "tenant_id", "host_uuid", "host_id", "instance_id":
			return nil, errors.New("external.python: reserved remote parameter")
		}
		requestParams[key] = value
	}
	endpoint := requestParams["endpoint"]
	approved := false
	for _, allowed := range strings.Split(os.Getenv("TELVYN_EXTERNAL_APPROVED_ENDPOINTS"), ",") {
		if endpoint != "" && endpoint == strings.TrimSpace(allowed) {
			approved = true
			break
		}
	}
	if !approved {
		return nil, errors.New("external.python: endpoint not locally approved")
	}
	staticTags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		if key == "host_uuid" && !externalUUID.MatchString(value) {
			return nil, errors.New("external.python: invalid core host_uuid")
		}
		if key == "instance_id" && value != cfg.GetCheckId() {
			return nil, errors.New("external.python: core instance_id mismatch")
		}
		if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "password") || strings.Contains(strings.ToLower(key), "token") {
			return nil, errors.New("external.python: secret in static tags")
		}
		staticTags[key] = value
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = time.Minute
	}
	return &externalPythonCheck{
		id: cfg.GetCheckId(), hostID: cfg.GetHostId(), packageName: name,
		packageVersion: version, checkName: check, packageDir: root,
		trustDir: trust, python: resolvedPython, interval: interval,
		params: requestParams, staticTags: staticTags,
		configVersion: configVersion,
	}, nil
}

func (c *externalPythonCheck) ID() string              { return c.id }
func (c *externalPythonCheck) Interval() time.Duration { return c.interval }
func (c *externalPythonCheck) Tags() map[string]string { return c.staticTags }

// InventorySnapshot exposes validated local data; InventoryReport is the bounded wire payload.
func (c *externalPythonCheck) InventorySnapshot() ([]ExternalInventory, json.RawMessage, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]ExternalInventory(nil), c.inventory...), append(json.RawMessage(nil), c.coverage...), c.status
}

func (c *externalPythonCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	started := time.Now().UTC().Format(time.RFC3339Nano)
	c.mu.Lock()
	c.inventory, c.coverage, c.status = nil, json.RawMessage(`{}`), "error"
	c.report = c.makeInventoryReport(started) // A failed run is incomplete, never an old success.
	c.mu.Unlock()
	runner, err := checkpackages.Verify(c.packageDir, c.trustDir, c.packageName, c.packageVersion, c.checkName)
	if err != nil {
		return nil, errors.New("external.python: package verification failed")
	}
	request, err := json.Marshal(externalRequest{1, c.id, c.params, c.staticTags})
	if err != nil || len(request) > externalInputLimit {
		return nil, errors.New("external.python: request too large")
	}
	output, err := invokeExternal(ctx, c.python, runner, c.checkName, request)
	if err != nil {
		return nil, err
	}
	metrics, inventory, coverage, status, err := mapExternalResponse(output, c.id, c.hostID, c.checkName, c.staticTags)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.inventory, c.coverage, c.status = inventory, coverage, status
	c.report = c.makeInventoryReport(started)
	c.mu.Unlock()
	return metrics, nil
}

// InventoryReport is independent of metrics; failures carry an incomplete empty snapshot.
func (c *externalPythonCheck) InventoryReport() *inventory.Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.report == nil {
		return nil
	}
	report := *c.report
	report.Resources = append([]inventory.Resource{}, c.report.Resources...)
	report.Coverage = append(json.RawMessage(nil), c.report.Coverage...)
	return &report
}

func (c *externalPythonCheck) makeInventoryReport(observed string) *inventory.Snapshot {
	if c.checkName != "proxmox" || c.configVersion <= 0 {
		return nil
	}
	host, err := strconv.ParseInt(c.hostID, 10, 64)
	if err != nil || host <= 0 {
		return nil
	}
	var coverage struct {
		Complete    bool   `json:"inventory_complete"`
		Truncated   bool   `json:"result_truncated"`
		ClusterMode string `json:"cluster_mode"`
		Endpoint    string `json:"cluster_status_endpoint"`
	}
	if json.Unmarshal(c.coverage, &coverage) != nil {
		return nil
	}
	if coverage.ClusterMode != "clustered" && coverage.ClusterMode != "standalone" {
		coverage.ClusterMode = "unknown"
	}
	if coverage.Endpoint != "available" && coverage.Endpoint != "invalid" {
		coverage.Endpoint = "unavailable"
	}
	encoded, _ := json.Marshal(map[string]string{"cluster_status_endpoint": coverage.Endpoint})
	return &inventory.Snapshot{ProtocolVersion: 1, CheckID: c.id, ConfigVersion: c.configVersion,
		HostID: c.hostID, Provider: c.checkName, ObservedAt: observed, ClusterMode: coverage.ClusterMode,
		Complete:  c.status != "error" && coverage.Complete && !coverage.Truncated && coverage.ClusterMode != "unknown",
		Resources: append([]inventory.Resource{}, c.inventory...), Coverage: encoded}
}

// invokeExternal is replaceable only within package tests. No shell is used;
// -I excludes user-site and PYTHONPATH. This is not an OS sandbox.
var invokeExternal = func(ctx context.Context, python, runner, check string, request []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, python, "-I", "-B", runner, "--check", check)
	cmd.Dir = filepath.Dir(runner)
	cmd.Env = []string{"LANG=C.UTF-8", "TZ=UTC"}
	cmd.Stdin = bytes.NewReader(request)
	stdout := &externalLimitedWriter{limit: externalOutputLimit}
	stderr := &externalLimitedWriter{limit: externalStderrLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("external.python: deadline: %w", ctx.Err())
		}
		if stdout.exceeded || stderr.exceeded {
			return nil, errors.New("external.python: output limit exceeded")
		}
		return nil, errors.New("external.python: runner failed") // never expose stderr/credentials
	}
	return stdout.Bytes(), nil
}

type externalLimitedWriter struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (w *externalLimitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.Len()
	if len(p) > remaining {
		w.exceeded = true
		if remaining > 0 {
			_, _ = w.Buffer.Write(p[:remaining])
		}
		return remaining, io.ErrShortWrite
	}
	return w.Buffer.Write(p)
}

func init() { Default.Register("external.python", newExternalPythonCheck) }
