package snmp

import "testing"

func TestFiberhomeProfileDoesNotExcludeSubscriberOrOtherSlotInterfaces(t *testing.T) {
	profile := LoadProfileForTest(t, "fiberhome-an5516")
	names := map[string]bool{}
	for _, item := range profile.Metrics {
		if item.MIB != "IF-MIB" {
			continue
		}
		if item.Filter != nil {
			t.Fatal("IF-MIB coverage must not exclude FE/ONU/other slots")
		}
		if item.Symbol != nil {
			names[item.Symbol.Name] = true
		}
		for _, symbol := range item.Symbols {
			names[symbol.Name] = true
		}
	}
	for _, name := range []string{"ifNumber", "snmp.if.in_octets", "snmp.if.out_octets", "snmp.if.in_discards", "snmp.if.out_discards", "snmp.if.in_errors", "snmp.if.out_errors", "snmp.if.mtu", "snmp.if.speed", "snmp.if.high_speed"} {
		if !names[name] {
			t.Fatalf("missing IF-MIB signal %s", name)
		}
	}
}
