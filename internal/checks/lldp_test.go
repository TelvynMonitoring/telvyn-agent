package checks

import (
	"context"
	"testing"

	"github.com/gosnmp/gosnmp"
)

type fakeLLDPRunner struct {
	rows map[string][]gosnmp.SnmpPDU
}

func (f *fakeLLDPRunner) Walk(_ context.Context, oid string, visit func(gosnmp.SnmpPDU) error) error {
	for _, pdu := range f.rows[oid] {
		if err := visit(pdu); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeLLDPRunner) Close() error { return nil }

func TestCollectLLDPEdgesMapsLocalPortAndRemoteIdentity(t *testing.T) {
	row := func(oid, index string, value any) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid + "." + index, Value: value}
	}
	runner := &fakeLLDPRunner{rows: map[string][]gosnmp.SnmpPDU{
		ifNameOID:               {row(ifNameOID, "7", []byte("port7"))},
		ifDescrOID:              {row(ifDescrOID, "7", []byte("uplink interface"))},
		ifSpeedOID:              {row(ifSpeedOID, "7", uint32(1_000_000_000))},
		ifHighSpeedOID:          {row(ifHighSpeedOID, "7", uint32(10_000))},
		ifAliasOID:              {row(ifAliasOID, "7", []byte("datacenter uplink"))},
		lldpLocPortSubtypeOID:   {row(lldpLocPortSubtypeOID, "7", int(5))},
		lldpLocPortIDOID:        {row(lldpLocPortIDOID, "7", []byte("port7"))},
		lldpLocPortDescOID:      {row(lldpLocPortDescOID, "7", []byte("local uplink"))},
		lldpRemLocalOID:         {row(lldpRemLocalOID, "0.7.1", int(7))},
		lldpRemChassisSub:       {row(lldpRemChassisSub, "0.7.1", int(4))},
		lldpRemChassisID:        {row(lldpRemChassisID, "0.7.1", []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})},
		lldpRemPortSub:          {row(lldpRemPortSub, "0.7.1", int(5))},
		lldpRemPortID:           {row(lldpRemPortID, "0.7.1", []byte("ether1"))},
		lldpRemPortDesc:         {row(lldpRemPortDesc, "0.7.1", []byte("uplink"))},
		lldpRemSystemName:       {row(lldpRemSystemName, "0.7.1", []byte("core-01"))},
		lldpRemSystemDescr:      {row(lldpRemSystemDescr, "0.7.1", []byte("RouterOS"))},
		lldpRemSysCapSupported:  {row(lldpRemSysCapSupported, "0.7.1", []byte{0x28})},
		lldpRemSysCapEnabled:    {row(lldpRemSysCapEnabled, "0.7.1", []byte{0x08})},
		lldpRemManAddrIfSubtype: {row(lldpRemManAddrIfSubtype, "0.7.1.1.4.192.0.2.10", int(2))},
		lldpRemManAddrIfID:      {row(lldpRemManAddrIfID, "0.7.1.1.4.192.0.2.10", int(12))},
		lldpRemManAddrOID:       {row(lldpRemManAddrOID, "0.7.1.1.4.192.0.2.10", ".1.3.6.1.2.1.1")},
		lldpRemUnknownTLVInfo:   {row(lldpRemUnknownTLVInfo, "0.7.1.127", []byte{0xde, 0xad})},
		lldpRemOrgDefInfo:       {row(lldpRemOrgDefInfo, "0.7.1.0.18.15.1.1", []byte{0xbe, 0xef})},
	}}

	edges, err := collectLLDPEdges(context.Background(), runner, "99")
	if err != nil {
		t.Fatalf("collectLLDPEdges returned error: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("expected one LLDP edge, got %d", len(edges))
	}
	edge := edges[0]
	if edge.GetLocalHostId() != "99" || edge.GetLocalIface() != "port7" || edge.GetLocalIfaceSpeedMbps() != 10_000 {
		t.Fatalf("unexpected local edge: %#v", edge)
	}
	if edge.GetRemoteChassisId() != "aa:bb:cc:dd:ee:ff" || edge.GetRemoteSysName() != "core-01" || edge.GetRemotePortId() != "ether1" {
		t.Fatalf("unexpected remote edge: %#v", edge)
	}
	raw := edge.GetRaw().AsMap()
	lldp := raw["lldp"].(map[string]any)
	local := lldp["local"].(map[string]any)
	remote := lldp["remote"].(map[string]any)
	if local["interface_alias"] != "datacenter uplink" || local["port_description"] != "local uplink" {
		t.Fatalf("local LLDP details were not preserved: %#v", local)
	}
	addresses := remote["management_addresses"].([]any)
	if len(addresses) != 1 || addresses[0].(map[string]any)["address"] != "192.0.2.10" {
		t.Fatalf("management addresses were not decoded: %#v", addresses)
	}
	supported := remote["capabilities_supported"].(map[string]any)["names"].([]any)
	if len(supported) != 2 || supported[0] != "bridge" || supported[1] != "router" {
		t.Fatalf("capabilities were not decoded: %#v", supported)
	}
	if len(remote["unknown_tlvs"].([]any)) != 1 || len(remote["organizational_tlvs"].([]any)) != 1 {
		t.Fatalf("raw extension TLVs were not preserved: %#v", remote)
	}
}

func TestIdentifierValueDecodesNetworkAddress(t *testing.T) {
	pdu := gosnmp.SnmpPDU{Value: []byte{1, 192, 0, 2, 25}}
	if got := identifierValue(pdu, 5, true); got != "192.0.2.25" {
		t.Fatalf("expected network chassis ID to be decoded, got %q", got)
	}
}
