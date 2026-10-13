package telvyn

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func disabled() bool { return strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") }

func Start(ctx context.Context) (func(context.Context) error, error) {
	if disabled() {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx, resource.WithFromEnv(), resource.WithTelemetrySDK())
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(safeExporter{exporter}), sdktrace.WithSpanProcessor(completionLogs{}))
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	return provider.Shutdown, nil
}

func Handler(next http.Handler) http.Handler {
	if disabled() {
		return next
	}
	return otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if r.Pattern != "" {
			route := r.Pattern
			if _, path, ok := strings.Cut(route, " "); ok {
				route = path
			}
			if path := strings.IndexByte(route, '/'); path >= 0 {
				route = route[path:]
			}
			span := trace.SpanFromContext(r.Context())
			span.SetName(r.Method + " " + route)
			span.SetAttributes(attribute.String("http.route", route))
		}
	}), "http.server")
}

func RecordError(ctx context.Context, err error) {
	if err == nil || disabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

type safeSpan struct {
	sdktrace.ReadOnlySpan
	attributes []attribute.KeyValue
}

func (s safeSpan) Attributes() []attribute.KeyValue { return s.attributes }

type safeExporter struct{ sdktrace.SpanExporter }

func (e safeExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	clean := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		attributes := make([]attribute.KeyValue, 0, len(span.Attributes()))
		for _, attr := range span.Attributes() {
			switch string(attr.Key) {
			case "url.query":
				continue
			case "http.url", "http.target", "url.full":
				attr.Value = attribute.StringValue(strings.SplitN(attr.Value.AsString(), "?", 2)[0])
			}
			attributes = append(attributes, attr)
		}
		attributes = append(attributes, attribute.String("telvyn.sdk.name", "telvyn-go-agent"), attribute.String("telvyn.sdk.version", "0.1.0"), attribute.String("process.runtime.version", runtime.Version()))
		clean = append(clean, safeSpan{span, attributes})
	}
	return e.SpanExporter.ExportSpans(ctx, clean)
}

type completionLogs struct{}

func (completionLogs) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (completionLogs) Shutdown(context.Context) error                  { return nil }
func (completionLogs) ForceFlush(context.Context) error                { return nil }
func (completionLogs) OnEnd(span sdktrace.ReadOnlySpan) {
	if span.SpanKind() != trace.SpanKindServer || !span.SpanContext().IsValid() {
		return
	}
	entry := map[string]any{"service": os.Getenv("OTEL_SERVICE_NAME"), "level": "info", "message": "HTTP request completed", "trace_id": span.SpanContext().TraceID().String(), "span_id": span.SpanContext().SpanID().String()}
	for _, attr := range span.Attributes() {
		switch string(attr.Key) {
		case "http.method", "http.request.method":
			entry["method"] = attr.Value.AsString()
		case "http.status_code", "http.response.status_code":
			status := attr.Value.AsInt64()
			entry["status"] = status
			if status >= 500 {
				entry["level"] = "error"
			}
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(entry)
}
