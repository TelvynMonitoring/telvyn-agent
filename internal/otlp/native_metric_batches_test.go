package otlp

import (
	metricscolpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"strings"
	"testing"
)

func TestNativeMetricBodiesKeepAllPointsAndLimits(t *testing.T) {
	metrics := make([]*metricspb.Metric, 2501)
	for i := range metrics {
		metrics[i] = &metricspb.Metric{Name: "postgres.table.rows", Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: float64(i)}}}}}}
	}
	request := &metricscolpb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: metrics}}}}}
	bodies, err := nativeMetricBodies(request)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, body := range bodies {
		if len(body) > 1024*1024 {
			t.Fatal("byte bound exceeded")
		}
		var parsed metricscolpb.ExportMetricsServiceRequest
		if err := protojson.Unmarshal(body, &parsed); err != nil {
			t.Fatal(err)
		}
		points := parsed.ResourceMetrics[0].ScopeMetrics[0].Metrics
		if len(points) > 1000 {
			t.Fatal("point bound exceeded")
		}
		for _, point := range points {
			if point.GetGauge().DataPoints[0].GetAsDouble() != float64(seen) {
				t.Fatal("point lost or duplicated")
			}
			seen++
		}
	}
	if seen != len(metrics) || len(request.ResourceMetrics[0].ScopeMetrics[0].Metrics) != len(metrics) {
		t.Fatal("input changed or points lost")
	}
	metrics[0].Name = strings.Repeat("x", 1024*1024+1)
	if _, err := nativeMetricBodies(request); err == nil {
		t.Fatal("oversize single metric must fail explicitly")
	}
}
