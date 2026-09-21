package otlp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// DatabaseContractVersion is the first stable wire contract for structured
// database telemetry. Older backends ignore these extra fields; newer
// backends use them to reject incompatible signals explicitly.
const DatabaseContractVersion = "1.0"

const (
	DatabaseSignalQueryMetrics      = "db.query.metrics"
	DatabaseSignalCatalogSnapshot   = "db.catalog.snapshot"
	DatabaseSignalDiagnostics       = "db.diagnostics.snapshot"
	DatabaseSignalExplainPlan       = "db.explain.plan"
	DatabaseSignalInstanceDiscovery = "db.instance.discovery"
	DatabaseSignalCapabilities      = "db.capabilities.snapshot"
	DatabaseSignalCollectorRuntime  = "db.collector.runtime"
)

// DatabaseSignalEnvelope is embedded in every structured database payload.
// Identity fields remain in each payload because their cardinality and scope
// differ (instance-wide versus logical database).
type DatabaseSignalEnvelope struct {
	ContractVersion string `json:"contract_version"`
	Signal          string `json:"signal"`
	Engine          string `json:"engine"`
	CollectedAt     string `json:"collected_at"`
}

func databaseEnvelope(signal, engine string, current DatabaseSignalEnvelope) DatabaseSignalEnvelope {
	current.ContractVersion = DatabaseContractVersion
	current.Signal = signal
	if strings.TrimSpace(current.Engine) == "" {
		current.Engine = engine
	}
	if strings.TrimSpace(current.CollectedAt) == "" {
		current.CollectedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return current
}

type DatabaseCapability struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type DatabaseCapabilitiesPayload struct {
	DatabaseSignalEnvelope
	InstallationID string               `json:"installation_id"`
	DatabaseID     string               `json:"database_id,omitempty"`
	DBServer       string               `json:"db_server"`
	DBName         string               `json:"db_name,omitempty"`
	ServerVersion  string               `json:"server_version,omitempty"`
	Capabilities   []DatabaseCapability `json:"capabilities"`
	Errors         []string             `json:"errors,omitempty"`
}

func (e *IngestExporter) PostDatabaseCapabilities(ctx context.Context, payload DatabaseCapabilitiesPayload) error {
	if installationID := e.databaseInstallationID(); installationID != "" {
		payload.InstallationID = installationID
	}
	if payload.InstallationID == "" || payload.DBServer == "" {
		return fmt.Errorf("database capabilities: installation_id e db_server são obrigatórios")
	}
	payload.DatabaseSignalEnvelope = databaseEnvelope(
		DatabaseSignalCapabilities, "postgres", payload.DatabaseSignalEnvelope,
	)
	if payload.Capabilities == nil {
		payload.Capabilities = []DatabaseCapability{}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "db/capabilities", "application/json", body)
}

type DatabaseCollectorRuntimePayload struct {
	DatabaseSignalEnvelope
	InstallationID string `json:"installation_id"`
	DatabaseID     string `json:"database_id,omitempty"`
	CheckID        string `json:"check_id"`
	CheckSignal    string `json:"check_signal"`
	OK             bool   `json:"ok"`
	TimedOut       bool   `json:"timed_out"`
	DurationMS     int64  `json:"duration_ms"`
	ObservedAt     string `json:"observed_at"`
	Error          string `json:"error,omitempty"`
}

func (e *IngestExporter) PostDatabaseCollectorRuntime(ctx context.Context, payload DatabaseCollectorRuntimePayload) error {
	if installationID := e.databaseInstallationID(); installationID != "" {
		payload.InstallationID = installationID
	}
	if payload.InstallationID == "" || payload.CheckID == "" || payload.CheckSignal == "" {
		return fmt.Errorf("database runtime: installation_id, check_id e check_signal são obrigatórios")
	}
	payload.DatabaseSignalEnvelope = databaseEnvelope(
		DatabaseSignalCollectorRuntime, "postgres", payload.DatabaseSignalEnvelope,
	)
	if payload.ObservedAt == "" {
		payload.ObservedAt = payload.CollectedAt
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return e.PostRaw(ctx, "db/runtime", "application/json", body)
}
