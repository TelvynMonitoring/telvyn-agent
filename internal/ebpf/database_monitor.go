package ebpf

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// DatabaseMonitorMatcher resolves an observed PostgreSQL server endpoint to
// the immutable database-monitor id configured by the portal. Returning an
// empty value means the endpoint is unknown or ambiguous and must not be
// attributed to a database monitor.
type DatabaseMonitorMatcher interface {
	MatchPostgresEndpoint(ip string, port uint16) string
}

// DatabaseMonitorRegistry is populated from the authoritative config-pull
// delta. It deliberately maps only unambiguous IP:port endpoints: the wire
// protocol at this point does not expose the database name, so two monitored
// databases sharing an endpoint cannot safely receive the same workload p95.
type DatabaseMonitorRegistry struct {
	mu       sync.RWMutex
	byCheck  map[string]postgresMonitorTarget
	bySocket map[string]string
}

type postgresMonitorTarget struct {
	monitorID string
	endpoints []string
}

// NewDatabaseMonitorRegistry creates an empty registry. It is safe to share
// between the config-pull goroutine and the eBPF bridge hot path.
func NewDatabaseMonitorRegistry() *DatabaseMonitorRegistry {
	return &DatabaseMonitorRegistry{
		byCheck:  make(map[string]postgresMonitorTarget),
		bySocket: make(map[string]string),
	}
}

// ApplyPostgresServerDelta applies the same config-pull delta used by the
// scheduler. Only postgres.server entries with the three explicit identity
// tags are eligible. A malformed or incomplete target removes any older
// mapping for that check instead of guessing.
func (r *DatabaseMonitorRegistry) ApplyPostgresServerDelta(added []*collectorv1.CheckConfig, deletedIDs []string) {
	if r == nil {
		return
	}

	updates := make(map[string]postgresMonitorTarget, len(added))
	for _, cfg := range added {
		if cfg == nil || cfg.GetCheckId() == "" {
			continue
		}
		if target, ok := postgresTargetFromConfig(cfg); ok {
			updates[cfg.GetCheckId()] = target
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range deletedIDs {
		delete(r.byCheck, id)
	}
	for _, cfg := range added {
		if cfg != nil && cfg.GetCheckId() != "" {
			// An update can change type or lose one of the identity tags.
			delete(r.byCheck, cfg.GetCheckId())
		}
	}
	for id, target := range updates {
		r.byCheck[id] = target
	}
	r.rebuildSocketsLocked()
}

// MatchPostgresEndpoint returns a monitor id only when exactly one configured
// monitor owns this observed server IP:port. It never falls back to a hostname
// or to a check id because those would permit false attribution.
func (r *DatabaseMonitorRegistry) MatchPostgresEndpoint(ip string, port uint16) string {
	if r == nil || port == 0 {
		return ""
	}
	key := endpointKey(ip, port)
	if key == "" {
		return ""
	}
	r.mu.RLock()
	monitorID := r.bySocket[key]
	r.mu.RUnlock()
	return monitorID
}

func (r *DatabaseMonitorRegistry) rebuildSocketsLocked() {
	// An endpoint remains blank when two different monitor ids claim it. The
	// bridge treats blank exactly like absent, preserving correctness over
	// coverage for monitors that point to the same Postgres instance.
	next := make(map[string]string)
	for _, target := range r.byCheck {
		for _, endpoint := range target.endpoints {
			previous, exists := next[endpoint]
			switch {
			case !exists:
				next[endpoint] = target.monitorID
			case previous != target.monitorID:
				next[endpoint] = ""
			}
		}
	}
	r.bySocket = next
}

func postgresTargetFromConfig(cfg *collectorv1.CheckConfig) (postgresMonitorTarget, bool) {
	if !strings.EqualFold(strings.TrimSpace(cfg.GetCheckType()), "postgres.server") {
		return postgresMonitorTarget{}, false
	}
	tags := cfg.GetStaticTags()
	monitorID := strings.TrimSpace(tags["db_monitor_id"])
	server := strings.TrimSpace(tags["db_server"])
	portNumber, err := strconv.ParseUint(strings.TrimSpace(tags["db_port"]), 10, 16)
	if monitorID == "" || server == "" || err != nil || portNumber == 0 {
		return postgresMonitorTarget{}, false
	}

	endpoints := resolveServerEndpoints(server, uint16(portNumber))
	if len(endpoints) == 0 {
		return postgresMonitorTarget{}, false
	}
	return postgresMonitorTarget{monitorID: monitorID, endpoints: endpoints}, true
}

func resolveServerEndpoints(server string, port uint16) []string {
	server = strings.Trim(strings.TrimSpace(server), "[]")
	if ip := net.ParseIP(server); ip != nil {
		if endpoint := endpointKey(ip.String(), port); endpoint != "" {
			return []string{endpoint}
		}
		return nil
	}

	// eBPF reports a numeric peer IP. Resolve a configured DNS target once on
	// the config delta; timeout keeps a bad resolver from blocking scheduling.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", server)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{}, len(ips))
	result := make([]string, 0, len(ips))
	for _, ip := range ips {
		endpoint := endpointKey(ip.String(), port)
		if endpoint == "" {
			continue
		}
		if _, already := seen[endpoint]; already {
			continue
		}
		seen[endpoint] = struct{}{}
		result = append(result, endpoint)
	}
	return result
}

func endpointKey(ip string, port uint16) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || port == 0 {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		parsed = v4
	}
	return net.JoinHostPort(parsed.String(), strconv.Itoa(int(port)))
}
