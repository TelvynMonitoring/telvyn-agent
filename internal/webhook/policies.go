package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ispwatch/collector/internal/k8smeta"
)

// Central selections are scoped to this cluster and an exact application image.
// A new application image requires reviewing its runtime compatibility again.
type runtimePolicy struct {
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
	Language  string `json:"language"`
	Image     string `json:"image"`
}

func (s *Server) pollRuntimePolicies(ctx context.Context) {
	if s.cfg.Cluster == "" {
		return
	}
	packages := map[string]string{}
	for language, image := range map[string]string{"node": s.cfg.NodeAgentImage, "python": s.cfg.PythonAgentImage, "dotnet": s.cfg.DotnetAgentImage, "ruby": s.cfg.RubyAgentImage, "php": s.cfg.PhpAgentImage} {
		if image != "" {
			packages[language] = image
		}
	}
	body, _ := json.Marshal(map[string]any{"cluster": s.cfg.Cluster, "packages": packages})
	base := strings.TrimSuffix(strings.TrimRight(s.cfg.IngestURL, "/"), "/api/ingest/v1")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/ingest/v1/k8s/runtime-instrumentation", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		s.cfg.Log.Debug("runtime policy poll failed", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.cfg.Log.Debug("runtime policy poll refused", "status", resp.StatusCode)
		return
	}
	var result struct {
		Entries []runtimePolicy `json:"entries"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&result); err != nil {
		return
	}
	s.mu.Lock()
	s.runtimePolicies = result.Entries
	s.runtimePoliciesAt = time.Now()
	s.mu.Unlock()
}

func (s *Server) runtimeSelection(pod podMeta, namespace string) (runtimePolicy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Do not keep applying a revoked selection indefinitely during an outage.
	if time.Since(s.runtimePoliciesAt) > time.Minute {
		return runtimePolicy{}, false
	}
	for _, owner := range pod.Metadata.OwnerReferences {
		if owner.Kind != "ReplicaSet" {
			continue
		}
		workload := k8smeta.WorkloadOf(owner.Name + "-00000")
		for _, policy := range s.runtimePolicies {
			if policy.Namespace != namespace || policy.Workload != workload {
				continue
			}
			for _, c := range pod.Spec.Containers {
				if c.Name == policy.Container && c.Image == policy.Image {
					return policy, true
				}
			}
		}
	}
	return runtimePolicy{}, false
}
