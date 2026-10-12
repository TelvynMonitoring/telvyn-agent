package checks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/inventory"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func TestExternalInventoryReportEmptyAndFailure(t *testing.T) {
	c := signedExternalCheck(t, "pass\n")
	c.hostID, c.configVersion = "42", 17
	previous := invokeExternal
	t.Cleanup(func() { invokeExternal = previous })
	fail := false
	invokeExternal = func(_ context.Context, _, _, _ string, request []byte) ([]byte, error) {
		if fail {
			return nil, errors.New("synthetic failure")
		}
		var input externalRequest
		if err := json.Unmarshal(request, &input); err != nil {
			t.Fatal(err)
		}
		if _, exists := input.Params[inventory.ConfigVersionParam]; exists {
			t.Fatal("core version sent to runner")
		}
		return []byte(`{"protocol_version":1,"status":"ok","metrics":[],"inventory":[],"coverage":{"inventory_complete":true,"cluster_mode":"standalone","cluster_status_endpoint":"available","node_details":{"secret":"not-forwarded"}}}`), nil
	}
	before := time.Now()
	metrics, err := c.Run(context.Background())
	if err != nil || len(metrics) != 0 {
		t.Fatalf("empty run: %v", err)
	}
	report := c.InventoryReport()
	if report == nil || !report.Complete || report.Resources == nil || len(report.Resources) != 0 ||
		report.ConfigVersion != 17 || report.HostID != "42" || report.ClusterMode != "standalone" {
		t.Fatalf("bad report: %+v", report)
	}
	at, err := time.Parse(time.RFC3339Nano, report.ObservedAt)
	if err != nil || at.Before(before) || at.After(time.Now()) {
		t.Fatal("invalid run timestamp")
	}
	if string(report.Coverage) != `{"cluster_status_endpoint":"available"}` {
		t.Fatalf("unsafe coverage: %s", report.Coverage)
	}
	fail = true
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	report = c.InventoryReport()
	if report == nil || report.Complete || len(report.Resources) != 0 || report.ClusterMode != "unknown" {
		t.Fatal("failed run reused success")
	}
}

func TestExternalInventoryReportCompletenessAndCopy(t *testing.T) {
	c := &externalPythonCheck{id: externalTestID, hostID: "42", checkName: "proxmox", configVersion: 17, status: "partial",
		inventory: []ExternalInventory{{ResourceID: "qemu/101", Type: "qemu", Name: "cold", State: "stopped"}},
		coverage:  json.RawMessage(`{"inventory_complete":true,"cluster_mode":"clustered","cluster_status_endpoint":"available"}`)}
	c.report = c.makeInventoryReport(time.Now().UTC().Format(time.RFC3339Nano))
	if !c.report.Complete {
		t.Fatal("partial metrics should not invalidate a complete inventory")
	}
	copy := c.InventoryReport()
	copy.Resources[0].Name = "changed"
	if c.report.Resources[0].Name != "cold" {
		t.Fatal("mutable snapshot alias")
	}
	c.coverage = json.RawMessage(`{"inventory_complete":true,"result_truncated":true,"cluster_mode":"clustered"}`)
	if c.makeInventoryReport(copy.ObservedAt).Complete {
		t.Fatal("truncated snapshot marked complete")
	}
	c.configVersion = 0
	if c.makeInventoryReport(copy.ObservedAt) != nil {
		t.Fatal("unknown config version sent")
	}
}

type inventoryTestCheck struct {
	*countingCheck
	report inventory.Snapshot
}

func (c *inventoryTestCheck) InventoryReport() *inventory.Snapshot {
	copy := c.report
	return &copy
}

func TestExternalInventorySchedulerSendsWithoutMetrics(t *testing.T) {
	for _, failed := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		rt, _ := makeRuntime(ctx, nil)
		c := &inventoryTestCheck{countingCheck: &countingCheck{id: externalTestID, interval: time.Hour},
			report: inventory.Snapshot{CheckID: externalTestID, Complete: true, Resources: []inventory.Resource{}}}
		if failed {
			c.runFunc = func(context.Context) ([]*collectorv1.Metric, error) { return nil, errors.New("fail") }
		}
		calls := 0
		rt.SetExternalInventoryPusher(func(postCtx context.Context, report inventory.Snapshot) error {
			calls++
			if _, ok := postCtx.Deadline(); !ok {
				t.Error("unbounded push")
			}
			if report.Complete == failed {
				t.Error("wrong completeness")
			}
			cancel()
			return errors.New("delivery failure must not leak payload")
		})
		rt.runOneCheck(ctx, c)
		cancel()
		if calls != 1 {
			t.Fatalf("pushes=%d", calls)
		}
	}
}

