package main

import (
	"reflect"
	"testing"
)

func TestCollectorCapabilitiesForSnmpAgent(t *testing.T) {
	t.Setenv("TELVYN_AGENT_KIND", "snmp")
	t.Setenv("TELVYN_SNMP", "1")
	t.Setenv("TELVYN_ICMP", "true")
	t.Setenv("TELVYN_LLDP", "0")
	t.Setenv("TELVYN_SSH", "off")

	want := []string{"metrics", "checks", "snmp", "icmp"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("collectorCapabilities() = %v, want %v", got, want)
	}
}

func TestCollectorCapabilitiesForLinuxAgentDefaultsToNetwork(t *testing.T) {
	t.Setenv("TELVYN_AGENT_KIND", "linux")

	want := []string{"metrics", "checks", "snmp", "icmp", "lldp", "ssh", "ssh_readonly_v1"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("collectorCapabilities() = %v, want %v", got, want)
	}
}

func TestCollectorCapabilitiesForLinuxAgentCanOptOut(t *testing.T) {
	t.Setenv("TELVYN_AGENT_KIND", "linux")
	t.Setenv("TELVYN_SSH", "0")
	t.Setenv("TELVYN_LLDP", "off")

	want := []string{"metrics", "checks", "snmp", "icmp"}
	if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
		t.Fatalf("collectorCapabilities() = %v, want %v", got, want)
	}
}

func TestCollectorCapabilitiesForOtherKindsStayBase(t *testing.T) {
	for _, kind := range []string{"docker", "k8s.node", ""} {
		t.Setenv("TELVYN_AGENT_KIND", kind)
		t.Setenv("TELVYN_ICMP", "1")

		want := []string{"metrics", "checks"}
		if got := collectorCapabilities(); !reflect.DeepEqual(got, want) {
			t.Fatalf("kind %q: collectorCapabilities() = %v, want %v", kind, got, want)
		}
	}
}

func TestCollectorInstallModeUsesExplicitRuntime(t *testing.T) {
	t.Setenv("TELVYN_AGENT_KIND", "snmp")
	t.Setenv("TELVYN_INSTALL_MODE", "docker")
	if got := collectorInstallMode(); got != "docker" {
		t.Fatalf("collectorInstallMode() = %q, want docker", got)
	}
}
