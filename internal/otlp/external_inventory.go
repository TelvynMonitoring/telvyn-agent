package otlp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/ispwatch/collector/internal/inventory"
)

// PostExternalInventory sends a validated snapshot separately from metrics. A
// successful empty resources array is meaningful and must not be suppressed.
func (e *IngestExporter) PostExternalInventory(ctx context.Context, report inventory.Snapshot) error {
	host, err := strconv.ParseInt(report.HostID, 10, 64)
	if err != nil || host <= 0 || report.HostID != strconv.FormatInt(host, 10) || report.ProtocolVersion != 1 ||
		!inventoryUUID.MatchString(report.CheckID) || report.ConfigVersion <= 0 || report.Provider != "proxmox" || len(report.Resources) > inventory.MaxResources {
		return errors.New("invalid external inventory envelope")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.ObservedAt); err != nil {
		return errors.New("invalid external inventory observation")
	}
	if report.ClusterMode != "clustered" && report.ClusterMode != "standalone" && report.ClusterMode != "unknown" {
		return errors.New("invalid external inventory cluster mode")
	}
	if report.Resources == nil {
		report.Resources = []inventory.Resource{}
	}
	body, err := json.Marshal(report)
	if err != nil || len(body) > inventory.MaxBodyBytes {
		return errors.New("external inventory exceeds body limit")
	}
	return e.PostRaw(ctx, "proxmox/inventory", "application/json", body)
}

var inventoryUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)
