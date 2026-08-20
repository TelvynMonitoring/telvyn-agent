package snmp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

type metadataDriver struct {
	gets  map[string]gosnmp.SnmpPDU
	walks map[string][]gosnmp.SnmpPDU
}

func (d *metadataDriver) Connect() error              { return nil }
func (d *metadataDriver) ConnReady() bool             { return true }
func (d *metadataDriver) Close() error                { return nil }
func (d *metadataDriver) SetDeadline(time.Time) error { return nil }

func (d *metadataDriver) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	var variables []gosnmp.SnmpPDU
	for _, oid := range oids {
		if pdu, ok := d.gets[oid]; ok {
			variables = append(variables, pdu)
		}
	}
	return &gosnmp.SnmpPacket{Variables: variables}, nil
}

func (d *metadataDriver) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	for _, pdu := range d.walks[root] {
		if err := fn(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (d *metadataDriver) Walk(root string, fn gosnmp.WalkFunc) error {
	return d.BulkWalk(root, fn)
}

func textPDU(name, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.OctetString, Value: []byte(value)}
}

func oidPDU(name, value string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.ObjectIdentifier, Value: value}
}

func TestCollectDeviceMetadata_MikroTikUsesIdentityOIDs(t *testing.T) {
	d := &metadataDriver{
		gets: map[string]gosnmp.SnmpPDU{
			oidSysDescr:                   textPDU(oidSysDescr, "RouterOS 7.15"),
			oidSysObjectID:                oidPDU(oidSysObjectID, "1.3.6.1.4.1.14988.1"),
			oidSysName:                    textPDU(oidSysName, "router-01"),
			"1.3.6.1.4.1.14988.1.1.7.9.0": textPDU(".1.3.6.1.4.1.14988.1.1.7.9.0", "CCR2004-1G-12S+"),
			"1.3.6.1.4.1.14988.1.1.7.3.0": textPDU(".1.3.6.1.4.1.14988.1.1.7.3.0", "ABC123"),
			"1.3.6.1.4.1.14988.1.1.7.4.0": textPDU(".1.3.6.1.4.1.14988.1.1.7.4.0", "7.15"),
		},
		walks: map[string][]gosnmp.SnmpPDU{},
	}
	meta := LoadProfileForTest(t, "mikrotik-router").CollectDeviceMetadata(context.Background(), newClientWithDriver(d, "router:161"))

	if !strings.EqualFold(meta["vendor"], "MikroTik") || meta["model"] != "CCR2004-1G-12S+" || meta["serial_number"] != "ABC123" || meta["version"] != "7.15" {
		t.Fatalf("metadata MikroTik incompleta: %#v", meta)
	}
}

func TestCollectDeviceMetadata_FiberHomeUsesProfileAndSysDescrFallback(t *testing.T) {
	d := &metadataDriver{
		gets: map[string]gosnmp.SnmpPDU{
			oidSysDescr:    textPDU(oidSysDescr, "FiberHome AN5516-04B Firmware V1.2.3"),
			oidSysObjectID: oidPDU(oidSysObjectID, "1.3.6.1.4.1.5875.800.1001.11"),
		},
		walks: map[string][]gosnmp.SnmpPDU{},
	}
	meta := LoadProfileForTest(t, "fiberhome-an5516").CollectDeviceMetadata(context.Background(), newClientWithDriver(d, "olt:161"))

	if meta["vendor"] != "fiberhome" || meta["model"] != "FiberHome AN5516-04B Firmware V1.2.3" || meta["version"] != "1.2.3" {
		t.Fatalf("metadata FiberHome incompleta: %#v", meta)
	}
	if meta["os_name"] != "SNMP" {
		t.Fatalf("os_name FiberHome=%q want SNMP fallback", meta["os_name"])
	}
}

func TestCollectDeviceMetadata_UnknownVendorStillReportsStandardIdentity(t *testing.T) {
	d := &metadataDriver{
		gets: map[string]gosnmp.SnmpPDU{
			oidSysDescr:    textPDU(oidSysDescr, "Acme Edge 9000 firmware 3.2"),
			oidSysObjectID: oidPDU(oidSysObjectID, "1.3.6.1.4.1.99999.7"),
		},
		walks: map[string][]gosnmp.SnmpPDU{},
	}
	meta := (&Profile{}).CollectDeviceMetadata(context.Background(), newClientWithDriver(d, "edge:161"))

	if meta["vendor"] != "enterprise-99999" || meta["sys_object_id"] != "1.3.6.1.4.1.99999.7" || meta["model"] != "Acme Edge 9000 firmware 3.2" || meta["version"] != "3.2" {
		t.Fatalf("metadata vendor desconhecido incompleta: %#v", meta)
	}
}

func LoadProfileForTest(t *testing.T, name string) *Profile {
	t.Helper()
	p, err := LoadProfile(name)
	if err != nil {
		t.Fatalf("LoadProfile(%q): %v", name, err)
	}
	return p
}
