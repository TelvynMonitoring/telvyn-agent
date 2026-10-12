package snmp

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestMikrotikCPUTemperatureGaugeFallback(t *testing.T) {
	const oid = "1.3.6.1.4.1.14988.1.1.3.6"
	const entry = ".1.3.6.1.4.1.14988.1.1.3.100.1."
	for _, tc := range []struct {
		name string
		unit int
		want bool
	}{
		{"cpu-temperature", 1, true},
		{"temperature", 1, false},
		{"cpu-temperature", 2, false},
	} {
		t.Run(tc.name+string(rune('0'+tc.unit)), func(t *testing.T) {
			driver := &fakeDriver{
				getReturn: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.NoSuchObject}},
				bulkPDUs: []gosnmp.SnmpPDU{
					{Name: entry + "2.987", Type: gosnmp.OctetString, Value: []byte(tc.name)},
					{Name: entry + "3.987", Type: gosnmp.Gauge32, Value: uint32(49)},
					{Name: entry + "4.987", Type: gosnmp.Integer, Value: tc.unit},
				},
			}
			v, ok := getScalar(nil, newClientWithDriver(driver, "x:161"), oid)
			if ok != tc.want || (ok && v != 490) {
				t.Fatalf("value=%v ok=%v; want 490/true only for CPU Celsius", v, ok)
			}
		})
	}
	legacy := &fakeDriver{getReturn: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Integer, Value: 480}}}
	if v, ok := getScalar(nil, newClientWithDriver(legacy, "x:161"), oid); !ok || v != 480 || len(legacy.bulkCalls) != 0 {
		t.Fatalf("legacy scalar must win without walking sensors: %v %v", v, ok)
	}
}
