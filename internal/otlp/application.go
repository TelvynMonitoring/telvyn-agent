package otlp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

func (h *HTTPReceiver) SetDebugConfig(reader func(context.Context, string, string, string) ([]byte, error)) {
	h.debugConfig = reader
}

func (h *HTTPReceiver) SetSDKRemoteConfig(reader func(context.Context, string, string, string) ([]byte, error)) {
	h.sdkRemoteConfig = reader
}

func (e *IngestExporter) DebugConfig(ctx context.Context, service, env, version string) ([]byte, error) {
	return e.applicationConfig(ctx, "debug/config", service, env, version)
}

// SDKRemoteConfig returns the remote configuration (profiling and security) of a service/env.
func (e *IngestExporter) SDKRemoteConfig(ctx context.Context, service, env, version string) ([]byte, error) {
	return e.applicationConfig(ctx, "sdk/remote-config", service, env, version)
}

func (e *IngestExporter) applicationConfig(ctx context.Context, signal, service, env, version string) ([]byte, error) {
	if !e.signalAllowed(signal) {
		return nil, errors.New("APM signal disabled")
	}
	query := url.Values{"service": {service}, "env": {env}, "version": {version}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.base+"/"+signal+"?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	response, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s status %d", signal, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || !json.Valid(body) {
		return nil, errors.New("invalid " + signal)
	}
	return body, nil
}

func (h *HTTPReceiver) handleDebugConfig(w http.ResponseWriter, r *http.Request) {
	h.serveApplicationConfig(w, r, h.debugConfig)
}

func (h *HTTPReceiver) handleSDKRemoteConfig(w http.ResponseWriter, r *http.Request) {
	h.serveApplicationConfig(w, r, h.sdkRemoteConfig)
}

func (h *HTTPReceiver) serveApplicationConfig(w http.ResponseWriter, r *http.Request, reader func(context.Context, string, string, string) ([]byte, error)) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if (key != "service" && key != "env" && key != "version") || len(values) != 1 || len(values[0]) > 255 || strings.IndexFunc(values[0], unicode.IsControl) >= 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if strings.TrimSpace(query.Get("service")) == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if reader == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := reader(r.Context(), query.Get("service"), query.Get("env"), query.Get("version"))
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

func (h *HTTPReceiver) handleApplicationReport(w http.ResponseWriter, r *http.Request) {
	signal := "sdk/configuration"
	if r.URL.Path == "/v1/debug" {
		signal = "debug"
	} else if r.URL.Path == "/v1/debug/config/applied" {
		signal = "debug/config/applied"
	}
	h.serveOTLP(w, r, "/v1/"+signal, func(body []byte, ct, clientIP string) (int, error) {
		if ct != "application/json" {
			return http.StatusUnsupportedMediaType, errors.New("application report requires JSON")
		}
		if len(body) > 64<<10 {
			return http.StatusRequestEntityTooLarge, errors.New("application report too large")
		}
		var report map[string]json.RawMessage
		if json.Unmarshal(body, &report) != nil || report == nil {
			return http.StatusBadRequest, errors.New("application report required")
		}
		for key := range report {
			allowed := key == "service" || key == "host" || key == "environment" || key == "service_version"
			if signal == "debug" {
				allowed = allowed || key == "snapshots"
			} else if signal == "debug/config/applied" {
				allowed = allowed || key == "config_version" || key == "session" || key == "statuses"
			} else {
				allowed = allowed || key == "sdk_name" || key == "sdk_version" || key == "runtime" || key == "configurations"
			}
			if !allowed {
				return http.StatusBadRequest, errors.New("unsupported application field")
			}
		}
		if h.forwardRaw == nil {
			return http.StatusServiceUnavailable, errors.New("application forwarding unavailable")
		}
		if err := h.forwardRaw(signal, "application/json", body); err != nil {
			return http.StatusBadGateway, err
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"forwarded":true}`))
		return http.StatusOK, nil
	})
}
