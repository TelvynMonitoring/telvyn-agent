package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/ispwatch/collector/internal/snmp"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// stubRunner implementa snmpGenericRunner em memoria — substitui o
// snmp.Client real (sem UDP) nos unit tests.
type stubRunner struct {
	sysOID   string
	sysErr   error
	collect  func(ctx context.Context, profile *snmp.Profile, hostID string, staticTags map[string]string) ([]*collectorv1.Metric, error)
	closed   bool
	getCalls int
}

func (s *stubRunner) GetSysObjectID(ctx context.Context) (string, error) {
	s.getCalls++
	if s.sysErr != nil {
		return "", s.sysErr
	}
	return s.sysOID, nil
}

func (s *stubRunner) Collect(ctx context.Context, profile *snmp.Profile, hostID string, staticTags map[string]string) ([]*collectorv1.Metric, error) {
	if s.collect != nil {
		return s.collect(ctx, profile, hostID, staticTags)
	}
	// Por default emite uma metrica sintetica com o nome do perfil pra
	// que o caller consiga assertar qual perfil foi resolvido.
	return []*collectorv1.Metric{{
		MetricName: "snmp.test.resolved",
		HostId:     hostID,
		Tags: map[string]string{
			"profile": profile.Name,
		},
		Source: "snmp",
	}}, nil
}

func (s *stubRunner) CollectDeviceMetadata(ctx context.Context, profile *snmp.Profile) map[string]string {
	return map[string]string{}
}

func (s *stubRunner) Close() error     { s.closed = true; return nil }
func (s *stubRunner) Requests() uint64 { return 4 }

func newStubSnmpClientFactory(r *stubRunner, err error) snmpClientFactory {
	return func(p snmp.Params) (snmpGenericRunner, error) {
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

func baseCfg(params map[string]string) *collectorv1.CheckConfig {
	return &collectorv1.CheckConfig{
		CheckId:   "snmp.generic-test-1",
		CheckType: "snmp.generic",
		HostId:    "host-abc",
		Interval:  durationpb.New(30 * time.Second),
		Params:    params,
		StaticTags: map[string]string{
			"tenant": "acme",
		},
	}
}

func TestSnmpGeneric_Factory_ExplicitProfile(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":    "127.0.0.1:1161",
		"profile":   "linux-net-snmp",
		"version":   "v2c",
		"community": "public",
	})
	runner := &stubRunner{}
	check, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(runner, nil))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if check.ID() != "snmp.generic-test-1" {
		t.Errorf("ID=%q", check.ID())
	}
	if check.Interval() != 30*time.Second {
		t.Errorf("Interval=%v", check.Interval())
	}
	if check.Tags()["tenant"] != "acme" {
		t.Errorf("tenant tag perdida")
	}
}

func TestSnmpGeneric_Factory_AutoProfile(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":    "127.0.0.1:1161",
		"profile":   "auto",
		"version":   "v2c",
		"community": "public",
	})
	// Stub retorna sysObjectID do net-snmp Linux.
	runner := &stubRunner{sysOID: "1.3.6.1.4.1.8072.3.2.10"}
	check, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(runner, nil))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.getCalls != 2 {
		t.Errorf("getCalls=%d want 2 (profile + reachability)", runner.getCalls)
	}
	if len(metrics) == 0 {
		t.Fatal("Run sem metrics")
	}
	if metrics[0].Tags["profile"] != "linux-net-snmp" {
		t.Errorf("auto-detect resolveu profile=%q want linux-net-snmp", metrics[0].Tags["profile"])
	}

	// Segunda Run mantém o perfil cacheado, mas verifica disponibilidade.
	if _, err := check.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.getCalls != 3 {
		t.Errorf("getCalls=%d want 3 (one fresh reachability probe)", runner.getCalls)
	}
}

func TestSnmpGeneric_Factory_AutoProfile_FallbackGeneric(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":    "127.0.0.1:1161",
		"profile":   "auto",
		"version":   "v2c",
		"community": "public",
	})
	// sysObjectID desconhecido — deve cair em generic-snmpv2.
	runner := &stubRunner{sysOID: "1.3.6.1.4.1.99999.42"}
	check, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(runner, nil))
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	metrics, err := check.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if metrics[0].Tags["profile"] != "generic-snmpv2" {
		t.Errorf("fallback resolveu=%q want generic-snmpv2", metrics[0].Tags["profile"])
	}
}

func TestSnmpGeneric_Factory_UnknownProfile(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":    "127.0.0.1:1161",
		"profile":   "vendor-nao-existe",
		"version":   "v2c",
		"community": "public",
	})
	_, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(&stubRunner{}, nil))
	if err == nil {
		t.Fatal("profile invalido deveria erro early")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("erro=%q nao menciona unknown profile", err.Error())
	}
}

func TestSnmpGeneric_Factory_MissingTarget(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"profile":   "linux-net-snmp",
		"version":   "v2c",
		"community": "public",
	})
	_, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(&stubRunner{}, nil))
	if err == nil {
		t.Fatal("target ausente deveria erro")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("erro=%q nao menciona target", err.Error())
	}
}

func TestSnmpGeneric_Factory_MissingCommunity_V2c(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":  "127.0.0.1:1161",
		"profile": "linux-net-snmp",
		"version": "v2c",
	})
	_, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(&stubRunner{}, nil))
	if err == nil {
		t.Fatal("community ausente em v2c deveria erro")
	}
	if !strings.Contains(err.Error(), "community") {
		t.Errorf("erro=%q nao menciona community", err.Error())
	}
}

func TestSnmpGeneric_Run_AutoDetectError(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":    "127.0.0.1:1161",
		"profile":   "auto",
		"version":   "v2c",
		"community": "public",
	})
	runner := &stubRunner{sysErr: errors.New("udp timeout")}
	check, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(runner, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, err = check.Run(context.Background())
	if err == nil {
		t.Fatal("sysObjectID falhou — Run deveria propagar erro")
	}
	if !strings.Contains(err.Error(), "auto-detect") {
		t.Errorf("erro=%q nao menciona auto-detect", err.Error())
	}
}

func TestSnmpExecutionVersionAndFamilyCoverage(t *testing.T) {
	for _, failed := range []bool{false, true} {
		runner := &stubRunner{sysOID: "1.3.6.1.4.1.8072", collect: func(context.Context, *snmp.Profile, string, map[string]string) ([]*collectorv1.Metric, error) {
			if failed {
				return nil, errors.New("OID failure")
			}
			return []*collectorv1.Metric{{MetricName: "snmp.sys_uptime", Value: 100}}, nil
		}}
		check, err := newSnmpGenericCheckWithFactory(baseCfg(map[string]string{"target": "127.0.0.1:1161", "profile": "linux-net-snmp", "community": "public", "_config_version": "42"}), newStubSnmpClientFactory(runner, nil))
		if err != nil {
			t.Fatal(err)
		}
		metrics, runErr := check.Run(context.Background())
		if (runErr != nil) != failed {
			t.Fatal(runErr)
		}
		values := map[string]float64{}
		for _, metric := range metrics {
			values[metric.MetricName] = metric.Value
			if strings.HasPrefix(metric.MetricName, "snmp.collector.config_") && metric.Tags["config_version"] != "42" {
				t.Fatal(metric.Tags)
			}
		}
		if values["snmp.collector.config_version_executed"] != 42 {
			t.Fatal(values)
		}
		if failed {
			if values["snmp.collector.config_execution_success"] != 0 {
				t.Fatal(values)
			}
		} else {
			if values["snmp.collector.config_execution_success"] != 1 || values["snmp.collector.profile_metric_expected"] <= values["snmp.collector.profile_metric_observed"] {
				t.Fatal(values)
			}
		}
	}
}

func TestSnmpDiagnosticsDistinguishReachabilityFromProfileFailure(t *testing.T) {
	for _, online := range []bool{true, false} {
		runner := &stubRunner{sysOID: "1.3.6.1.4.1.8072", collect: func(context.Context, *snmp.Profile, string, map[string]string) ([]*collectorv1.Metric, error) {
			return nil, errors.New("no profile samples")
		}}
		if !online {
			runner.sysErr = errors.New("timeout")
		}
		check, err := newSnmpGenericCheckWithFactory(baseCfg(map[string]string{"target": "127.0.0.1:1161", "profile": "linux-net-snmp", "community": "public"}), newStubSnmpClientFactory(runner, nil))
		if err != nil {
			t.Fatal(err)
		}
		metrics, err := check.Run(context.Background())
		if err == nil {
			t.Fatal("collection error must remain an error")
		}
		values := map[string]float64{}
		for _, metric := range metrics {
			values[metric.MetricName] = metric.Value
		}
		up := 0.0
		if online {
			up = 1
		}
		if values["snmp.device.reachable"] != up || values["snmp.device.unreachable"] != 1-up || values["snmp.collector.up"] != 0 || values["snmp.collector.requests"] != 4 || values["snmp.collector.submitted_metrics"] != 0 {
			t.Fatal(values)
		}
	}
}

func TestSnmpFailureDiagnosticsReachRuntimeWithoutMaskingError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &stubRunner{sysErr: errors.New("timeout"), collect: func(context.Context, *snmp.Profile, string, map[string]string) ([]*collectorv1.Metric, error) {
		return nil, errors.New("timeout")
	}}
	cfg := baseCfg(map[string]string{"target": "127.0.0.1:1161", "profile": "linux-net-snmp", "community": "public"})
	cfg.Enabled = true
	registry := NewRegistry()
	registry.Register("snmp.generic", func(config *collectorv1.CheckConfig) (Check, error) {
		return newSnmpGenericCheckWithFactory(config, newStubSnmpClientFactory(runner, nil))
	})
	runtime, output := makeRuntime(ctx, registry)
	runtime.Reload([]*collectorv1.CheckConfig{cfg})
	defer runtime.Reload(nil)
	timeout := time.After(3 * time.Second)
	var diagnostic, failure bool
	for !diagnostic || !failure {
		select {
		case batch := <-output:
			for _, metric := range batch {
				if metric.MetricName == "snmp.device.unreachable" && metric.Value == 1 {
					diagnostic = true
				}
				if metric.MetricName == "ispwatch.check.errors" {
					failure = true
				}
			}
		case <-timeout:
			t.Fatalf("diagnostic=%v error=%v", diagnostic, failure)
		}
	}
}

func TestSnmpGeneric_AutoRegistered(t *testing.T) {
	f, ok := Default.Get("snmp.generic")
	if !ok || f == nil {
		t.Fatal("snmp.generic nao auto-registrou em Default")
	}
}

func TestSnmpGeneric_V3Params(t *testing.T) {
	cfg := baseCfg(map[string]string{
		"target":        "10.0.0.1",
		"profile":       "linux-net-snmp",
		"version":       "v3",
		"v3_user":       "snmpv3user",
		"v3_auth_proto": "SHA256",
		"v3_auth_pass":  "auth-pass",
		"v3_priv_proto": "AES256",
		"v3_priv_pass":  "priv-pass",
	})
	check, err := newSnmpGenericCheckWithFactory(cfg, newStubSnmpClientFactory(&stubRunner{}, nil))
	if err != nil {
		t.Fatalf("v3 factory: %v", err)
	}
	if check == nil {
		t.Fatal("nil check")
	}
}
