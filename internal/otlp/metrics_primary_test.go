package otlp

import (
	metricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricdata "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"strings"
	"testing"
)

func TestMetricsPrimaryJSONRemovesSpoofAndPreservesExemplars(t *testing.T) {
	h := &HTTPReceiver{}
	h.SetVerifiedPrimaryIdentity("real-host", "")
	raw := []byte(`{"resourceMetrics":[{"resource":{"attributes":[{"key":"telvyn.verified_primary.host","value":{"stringValue":"fake"}}]},"scopeMetrics":[{"metrics":[{"name":"jvm.cpu","gauge":{"dataPoints":[{"asDouble":1,"attributes":[{"key":"apm_primary_686f7374","value":{"stringValue":"fake"}}],"exemplars":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef"}]}]}}]}]}]}`)
	stamped, err := h.stampMetricsJSON(raw, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	body := string(stamped)
	if strings.Contains(body, "fake") || !strings.Contains(body, "real-host") || !strings.Contains(body, "0123456789abcdef0123456789abcdef") {
		t.Fatal(body)
	}
	h.SetVerifiedPrimaryIdentity("", "")
	stamped, err = h.stampMetricsJSON(raw, "127.0.0.1")
	if err != nil || strings.Contains(string(stamped), "telvyn.verified_primary.host") {
		t.Fatal("unknown origin must not inherit SDK identity")
	}
}
func TestMetricsPrimaryProtobufStripsPointOverrides(t *testing.T) {
	h := &HTTPReceiver{}
	h.SetVerifiedPrimaryIdentity("real-host", "")
	point := &metricdata.NumberDataPoint{Attributes: []*commonpb.KeyValue{kv("telvyn.verified_primary.host", "fake"), kv("apm_primary_686f7374", "fake")}}
	request := &metricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricdata.ResourceMetrics{{Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{kv("telvyn.verified_primary.host", "fake")}}, ScopeMetrics: []*metricdata.ScopeMetrics{{Metrics: []*metricdata.Metric{{Data: &metricdata.Metric_Gauge{Gauge: &metricdata.Gauge{DataPoints: []*metricdata.NumberDataPoint{point}}}}}}}}}}
	h.stampMetricsPrimary(request, "127.0.0.1")
	if len(point.Attributes) != 0 || request.ResourceMetrics[0].Resource.Attributes[0].Value.GetStringValue() != "real-host" {
		t.Fatal(request)
	}
}
