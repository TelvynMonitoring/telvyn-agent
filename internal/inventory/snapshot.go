// Package inventory defines the bounded external-check inventory wire contract.
package inventory

import "encoding/json"

const MaxResources = 1000
const MaxBodyBytes = 512 << 10
const ConfigVersionParam = "_config_version"

type Resource struct {
	ResourceID string `json:"resource_id"`
	Type       string `json:"type"`
	Name       string `json:"name"`
	State      string `json:"state"`
	ParentID   string `json:"parent_id,omitempty"`
	ObservedAt string `json:"observed_at"`
}

// Complete refers to credential-visible resources, not proof of provider deletion.
// The backend binds check/host/collector through the token and config version.
type Snapshot struct {
	ProtocolVersion int             `json:"protocol_version"`
	CheckID         string          `json:"check_id"`
	ConfigVersion   int64           `json:"config_version"`
	HostID          string          `json:"host_id"`
	Provider        string          `json:"provider"`
	ObservedAt      string          `json:"observed_at"`
	Complete        bool            `json:"complete"`
	ClusterMode     string          `json:"cluster_mode"`
	Resources       []Resource      `json:"resources"`
	Coverage        json.RawMessage `json:"coverage,omitempty"`
}
