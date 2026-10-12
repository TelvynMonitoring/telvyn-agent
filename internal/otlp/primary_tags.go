package otlp

import (
	"encoding/json"
	"fmt"
	"github.com/ispwatch/collector/internal/apm/primarytags"
	"sort"
	"strings"

	metricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

const verifiedPrimaryPrefix = "telvyn.verified_primary."

// SetVerifiedPrimaryIdentity accepts local collector configuration, never SDK attributes.
func (h *HTTPReceiver) SetVerifiedPrimaryIdentity(host, cluster string) {
	h.verifiedHost, h.verifiedCluster = strings.TrimSpace(host), strings.TrimSpace(cluster)
}
func (h *HTTPReceiver) SetVerifiedHostTags(tags map[string]string) {
	h.primaryMu.Lock()
	defer h.primaryMu.Unlock()
	h.verifiedHostTags = map[string]string{}
	for key, value := range tags {
		h.verifiedHostTags[key] = value
	}
}
func (h *HTTPReceiver) ApplyPrimaryTags(keys []string) error {
	if len(keys) > 2 {
		return fmt.Errorf("maximum two primary tags")
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] || !primarytags.ValidKey(key) {
			return fmt.Errorf("invalid primary tags")
		}
		seen[key] = true
	}
	h.primaryMu.Lock()
	h.primaryKeys = append([]string(nil), keys...)
	h.primaryMu.Unlock()
	return nil
}
func (h *HTTPReceiver) PrimaryTagSources() []string {
	h.primaryMu.RLock()
	sources := map[string]bool{}
	for key := range h.verifiedHostTags {
		sources["host.tag."+key] = true
	}
	h.primaryMu.RUnlock()
	if resolver, ok := h.resolver.(interface{ PrimaryTagSources() []string }); ok {
		for _, key := range resolver.PrimaryTagSources() {
			if primarytags.ValidKey(key) {
				sources[key] = true
			}
		}
	}
	result := []string{}
	for key := range sources {
		result = append(result, key)
	}
	sort.Strings(result)
	if len(result) > 256 {
		result = result[:256]
	}
	return result
}
func (h *HTTPReceiver) primaryMetadata(clientIP string) map[string]string {
	var namespace, pod, node string
	resolved := false
	if h.resolver != nil {
		namespace, pod, _, node, resolved = h.resolver.ResolveIPMeta(clientIP)
	}
	values := verifiedPrimary(h.verifiedHost, h.verifiedCluster, namespace, node, resolved)
	labels := map[string]string{}
	if resolved {
		if resolver, ok := h.resolver.(interface {
			LabelsForPod(string, string) map[string]string
		}); ok {
			labels = resolver.LabelsForPod(namespace, pod)
		}
	}
	h.primaryMu.RLock()
	defer h.primaryMu.RUnlock()
	for _, key := range h.primaryKeys {
		value := ""
		if strings.HasPrefix(key, "host.tag.") {
			value = h.verifiedHostTags[strings.TrimPrefix(key, "host.tag.")]
		} else if strings.HasPrefix(key, "kube_label.") {
			value = labels[strings.TrimPrefix(key, "kube_label.")]
		}
		if value != "" && primarytags.ValidValue(value) {
			values[verifiedPrimaryPrefix+key] = value
		}
	}
	return values
}

func verifiedPrimary(host, cluster, namespace, node string, resolved bool) map[string]string {
	values := map[string]string{}
	if host != "" {
		values[verifiedPrimaryPrefix+"host"] = host
	}
	if cluster != "" {
		values[verifiedPrimaryPrefix+"kube_cluster_name"] = cluster
	}
	if resolved {
		if namespace != "" {
			values[verifiedPrimaryPrefix+"kube_namespace"] = namespace
		}
		if node != "" {
			values[verifiedPrimaryPrefix+"kube_node"] = node
		}
	}
	return values
}

// Preserve all unknown OTLP fields and raw IDs while replacing reserved metadata.
func stampJSONPrimary(raw json.RawMessage, values map[string]string) (json.RawMessage, bool) {
	doc := map[string]json.RawMessage{}
	if len(raw) > 0 && string(raw) != "null" {
		if json.Unmarshal(raw, &doc) != nil {
			return raw, false
		}
	}
	var attributes []json.RawMessage
	if field := doc["attributes"]; len(field) > 0 {
		if json.Unmarshal(field, &attributes) != nil {
			return raw, false
		}
	}
	clean := make([]json.RawMessage, 0, len(attributes)+len(values))
	changed := false
	for _, attribute := range attributes {
		var identity struct {
			Key string `json:"key"`
		}
		if json.Unmarshal(attribute, &identity) == nil && (strings.HasPrefix(identity.Key, verifiedPrimaryPrefix) || strings.HasPrefix(identity.Key, "apm_primary_")) {
			changed = true
			continue
		}
		clean = append(clean, attribute)
	}
	for key, value := range values {
		encoded, _ := json.Marshal(map[string]any{"key": key, "value": map[string]string{"stringValue": value}})
		clean = append(clean, encoded)
		changed = true
	}
	if !changed {
		return raw, false
	}
	doc["attributes"], _ = json.Marshal(clean)
	encoded, err := json.Marshal(doc)
	if err != nil {
		return raw, false
	}
	return encoded, true
}

func stripPrimaryProto(attributes []*commonpb.KeyValue) ([]*commonpb.KeyValue, bool) {
	clean := make([]*commonpb.KeyValue, 0, len(attributes))
	changed := false
	for _, attribute := range attributes {
		if strings.HasPrefix(attribute.GetKey(), verifiedPrimaryPrefix) || strings.HasPrefix(attribute.GetKey(), "apm_primary_") {
			changed = true
			continue
		}
		clean = append(clean, attribute)
	}
	return clean, changed
}

func (h *HTTPReceiver) stampMetricsPrimary(request *metricspb.ExportMetricsServiceRequest, clientIP string) {
	values := h.primaryMetadata(clientIP)
	for _, resource := range request.ResourceMetrics {
		if resource == nil {
			continue
		}
		if resource.Resource == nil {
			resource.Resource = &resourcepb.Resource{}
		}
		resource.Resource.Attributes, _ = stripPrimaryProto(resource.Resource.Attributes)
		for key, value := range values {
			resource.Resource.Attributes = append(resource.Resource.Attributes, kv(key, value))
		}
		for _, scope := range resource.ScopeMetrics {
			if scope == nil {
				continue
			}
			for _, metric := range scope.Metrics {
				for _, point := range metric.GetGauge().GetDataPoints() {
					if point == nil {
						continue
					}
					point.Attributes, _ = stripPrimaryProto(point.Attributes)
				}
				for _, point := range metric.GetSum().GetDataPoints() {
					if point == nil {
						continue
					}
					point.Attributes, _ = stripPrimaryProto(point.Attributes)
				}
				for _, point := range metric.GetHistogram().GetDataPoints() {
					if point == nil {
						continue
					}
					point.Attributes, _ = stripPrimaryProto(point.Attributes)
				}
				for _, point := range metric.GetExponentialHistogram().GetDataPoints() {
					if point == nil {
						continue
					}
					point.Attributes, _ = stripPrimaryProto(point.Attributes)
				}
				for _, point := range metric.GetSummary().GetDataPoints() {
					if point == nil {
						continue
					}
					point.Attributes, _ = stripPrimaryProto(point.Attributes)
				}
			}
		}
	}
}

func (h *HTTPReceiver) stampPrimaryProto(request *tracepb.ExportTraceServiceRequest, clientIP string) bool {
	values := h.primaryMetadata(clientIP)
	changed := false
	for _, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		if resource.Resource == nil {
			resource.Resource = &resourcepb.Resource{}
		}
		var removed bool
		resource.Resource.Attributes, removed = stripPrimaryProto(resource.Resource.Attributes)
		changed = changed || removed
		for key, value := range values {
			resource.Resource.Attributes = append(resource.Resource.Attributes, kv(key, value))
			changed = true
		}
		for _, scope := range resource.ScopeSpans {
			if scope == nil {
				continue
			}
			for _, span := range scope.Spans {
				if span == nil {
					continue
				}
				span.Attributes, removed = stripPrimaryProto(span.Attributes)
				changed = changed || removed
			}
		}
	}
	return changed
}
