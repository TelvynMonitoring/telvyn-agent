package checks

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/ispwatch/collector/internal/snmp"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ifNameOID               = "1.3.6.1.2.1.31.1.1.1.1"
	ifDescrOID              = "1.3.6.1.2.1.2.2.1.2"
	ifSpeedOID              = "1.3.6.1.2.1.2.2.1.5"
	ifHighSpeedOID          = "1.3.6.1.2.1.31.1.1.1.15"
	ifAliasOID              = "1.3.6.1.2.1.31.1.1.1.18"
	lldpLocPortSubtypeOID   = "1.0.8802.1.1.2.1.3.7.1.2"
	lldpLocPortIDOID        = "1.0.8802.1.1.2.1.3.7.1.3"
	lldpLocPortDescOID      = "1.0.8802.1.1.2.1.3.7.1.4"
	lldpRemLocalOID         = "1.0.8802.1.1.2.1.4.1.1.2"
	lldpRemChassisSub       = "1.0.8802.1.1.2.1.4.1.1.4"
	lldpRemChassisID        = "1.0.8802.1.1.2.1.4.1.1.5"
	lldpRemPortSub          = "1.0.8802.1.1.2.1.4.1.1.6"
	lldpRemPortID           = "1.0.8802.1.1.2.1.4.1.1.7"
	lldpRemPortDesc         = "1.0.8802.1.1.2.1.4.1.1.8"
	lldpRemSystemName       = "1.0.8802.1.1.2.1.4.1.1.9"
	lldpRemSystemDescr      = "1.0.8802.1.1.2.1.4.1.1.10"
	lldpRemSysCapSupported  = "1.0.8802.1.1.2.1.4.1.1.11"
	lldpRemSysCapEnabled    = "1.0.8802.1.1.2.1.4.1.1.12"
	lldpRemManAddrIfSubtype = "1.0.8802.1.1.2.1.4.2.1.3"
	lldpRemManAddrIfID      = "1.0.8802.1.1.2.1.4.2.1.4"
	lldpRemManAddrOID       = "1.0.8802.1.1.2.1.4.2.1.5"
	lldpRemUnknownTLVInfo   = "1.0.8802.1.1.2.1.4.3.1.2"
	lldpRemOrgDefInfo       = "1.0.8802.1.1.2.1.4.4.1.4"
)

// TopologyPusher é implementado pelo exporter HTTP. A coleta continua sendo
// um Check normal: o scheduler publica o status e limita SNMP como os demais.
type TopologyPusher interface {
	PostTopology(context.Context, *collectorv1.TopologyReport) error
}

var topologyPusher TopologyPusher

func SetTopologyPusher(pusher TopologyPusher) { topologyPusher = pusher }

type lldpRunner interface {
	Walk(context.Context, string, func(gosnmp.SnmpPDU) error) error
	Close() error
}

type lldpClientFactory func(snmp.Params) (lldpRunner, error)

var defaultLLDPClientFactory lldpClientFactory = func(params snmp.Params) (lldpRunner, error) {
	return snmp.NewClient(params)
}

type lldpCheck struct {
	id       string
	interval time.Duration
	hostID   string
	tags     map[string]string
	params   snmp.Params
	clientFn lldpClientFactory
	batchSeq atomic.Int64
}

func newLLDPCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params, err := snmp.ParamsFromMap(cfg.GetParams())
	if err != nil {
		return nil, err
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for key, value := range cfg.GetStaticTags() {
		tags[key] = value
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "lldp.discover-" + cfg.GetHostId()
	}
	return &lldpCheck{id: id, interval: interval, hostID: cfg.GetHostId(), tags: tags, params: params, clientFn: defaultLLDPClientFactory}, nil
}

func (c *lldpCheck) ID() string              { return c.id }
func (c *lldpCheck) Interval() time.Duration { return c.interval }
func (c *lldpCheck) Tags() map[string]string { return c.tags }
func (c *lldpCheck) Kind() string            { return "snmp" }

func (c *lldpCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	runner, err := c.clientFn(c.params)
	if err != nil {
		return nil, err
	}
	defer runner.Close()

	edges, err := collectLLDPEdges(ctx, runner, c.hostID)
	if err != nil {
		return nil, err
	}
	if len(edges) == 0 || topologyPusher == nil {
		return nil, nil
	}
	report := &collectorv1.TopologyReport{
		BatchSeq:  c.batchSeq.Add(1),
		ScannedAt: timestamppb.Now(),
		Edges:     edges,
	}
	if err := topologyPusher.PostTopology(ctx, report); err != nil {
		return nil, fmt.Errorf("lldp topology ingest: %w", err)
	}
	return nil, nil
}

func collectLLDPEdges(ctx context.Context, runner lldpRunner, hostID string) ([]*collectorv1.TopologyEdgeReport, error) {
	localPortSubtypes, err := walkInts(ctx, runner, lldpLocPortSubtypeOID)
	if err != nil {
		return nil, err
	}
	localPortIDs, err := walkStrings(ctx, runner, lldpLocPortIDOID)
	if err != nil {
		return nil, err
	}
	localPortDescriptions, err := walkStrings(ctx, runner, lldpLocPortDescOID)
	if err != nil {
		return nil, err
	}
	ifNames, err := walkStrings(ctx, runner, ifNameOID)
	if err != nil {
		return nil, err
	}
	ifDescrs, err := walkStrings(ctx, runner, ifDescrOID)
	if err != nil {
		return nil, err
	}
	ifSpeeds, err := walkInts(ctx, runner, ifSpeedOID)
	if err != nil {
		return nil, err
	}
	ifHighSpeeds, err := walkInts(ctx, runner, ifHighSpeedOID)
	if err != nil {
		return nil, err
	}
	ifAliases, err := walkStrings(ctx, runner, ifAliasOID)
	if err != nil {
		return nil, err
	}
	columns := []string{
		lldpRemLocalOID, lldpRemChassisSub, lldpRemChassisID, lldpRemPortSub,
		lldpRemPortID, lldpRemPortDesc, lldpRemSystemName, lldpRemSystemDescr,
		lldpRemSysCapSupported, lldpRemSysCapEnabled,
	}
	data := make(map[string]map[string]gosnmp.SnmpPDU)
	for _, oid := range columns {
		values, walkErr := walkPDUs(ctx, runner, oid)
		if walkErr != nil {
			return nil, walkErr
		}
		for index, pdu := range values {
			if data[index] == nil {
				data[index] = make(map[string]gosnmp.SnmpPDU)
			}
			data[index][oid] = pdu
		}
	}
	managementAddresses, err := collectManagementAddresses(ctx, runner)
	if err != nil {
		return nil, err
	}
	unknownTLVs, err := collectRawTLVs(ctx, runner, lldpRemUnknownTLVInfo)
	if err != nil {
		return nil, err
	}
	organizationalTLVs, err := collectRawTLVs(ctx, runner, lldpRemOrgDefInfo)
	if err != nil {
		return nil, err
	}

	edges := make([]*collectorv1.TopologyEdgeReport, 0, len(data))
	for index, row := range data {
		localPort := intValue(row[lldpRemLocalOID])
		if localPort == 0 {
			localPort = lldpLocalPortFromIndex(index)
		}
		localIface, speed, ifIndex := resolveLocalInterface(localPort, localPortIDs, ifNames, ifDescrs, ifSpeeds, ifHighSpeeds)
		chassisSubtype := intValue(row[lldpRemChassisSub])
		chassisID := identifierValue(row[lldpRemChassisID], chassisSubtype, true)
		remoteName := stringValue(row[lldpRemSystemName])
		remotePortSubtype := intValue(row[lldpRemPortSub])
		remotePort := identifierValue(row[lldpRemPortID], remotePortSubtype, false)
		if chassisID == "" && remoteName == "" && remotePort == "" {
			continue
		}
		remoteDetails := map[string]any{
			"table_index":            index,
			"chassis_id_subtype":     chassisSubtype,
			"chassis_id":             chassisID,
			"port_id_subtype":        remotePortSubtype,
			"port_id":                remotePort,
			"port_description":       stringValue(row[lldpRemPortDesc]),
			"system_name":            remoteName,
			"system_description":     stringValue(row[lldpRemSystemDescr]),
			"capabilities_supported": capabilityDetails(row[lldpRemSysCapSupported]),
			"capabilities_enabled":   capabilityDetails(row[lldpRemSysCapEnabled]),
			"management_addresses":   managementAddresses[index],
			"unknown_tlvs":           unknownTLVs[index],
			"organizational_tlvs":    organizationalTLVs[index],
		}
		localDetails := map[string]any{
			"host_id":               hostID,
			"port_number":           localPort,
			"port_id_subtype":       localPortSubtypes[localPort],
			"port_id":               localPortIDs[localPort],
			"port_description":      localPortDescriptions[localPort],
			"interface_index":       ifIndex,
			"interface_name":        localIface,
			"interface_description": ifDescrs[ifIndex],
			"interface_alias":       ifAliases[ifIndex],
			"interface_speed_mbps":  speed,
		}
		raw, rawErr := structpb.NewStruct(map[string]any{
			"lldp": map[string]any{
				"local":  localDetails,
				"remote": remoteDetails,
			},
		})
		if rawErr != nil {
			return nil, fmt.Errorf("encode LLDP details: %w", rawErr)
		}
		edges = append(edges, &collectorv1.TopologyEdgeReport{
			LocalHostId:            hostID,
			LocalIface:             localIface,
			LocalIfaceSpeedMbps:    speed,
			RemoteChassisIdSubtype: int32(chassisSubtype),
			RemoteChassisId:        chassisID,
			RemotePortIdSubtype:    int32(remotePortSubtype),
			RemotePortId:           remotePort,
			RemotePortDesc:         stringValue(row[lldpRemPortDesc]),
			RemoteSysName:          remoteName,
			RemoteSysDescr:         stringValue(row[lldpRemSystemDescr]),
			Layer:                  "L2",
			SourceProtocol:         "lldp",
			LinkType:               "ethernet",
			Raw:                    raw,
		})
	}
	return edges, nil
}

func walkPDUs(ctx context.Context, runner lldpRunner, oid string) (map[string]gosnmp.SnmpPDU, error) {
	values := make(map[string]gosnmp.SnmpPDU)
	err := runner.Walk(ctx, oid, func(pdu gosnmp.SnmpPDU) error {
		if index := oidSuffix(pdu.Name, oid); index != "" {
			values[index] = pdu
		}
		return nil
	})
	return values, err
}

func walkStrings(ctx context.Context, runner lldpRunner, oid string) (map[int]string, error) {
	pdus, err := walkPDUs(ctx, runner, oid)
	if err != nil {
		return nil, err
	}
	values := make(map[int]string, len(pdus))
	for index, pdu := range pdus {
		if id := lastOIDPart(index); id > 0 {
			values[id] = stringValue(pdu)
		}
	}
	return values, nil
}

func walkInts(ctx context.Context, runner lldpRunner, oid string) (map[int]int64, error) {
	pdus, err := walkPDUs(ctx, runner, oid)
	if err != nil {
		return nil, err
	}
	values := make(map[int]int64, len(pdus))
	for index, pdu := range pdus {
		if id := lastOIDPart(index); id > 0 {
			values[id] = int64(intValue(pdu))
		}
	}
	return values, nil
}

func collectManagementAddresses(ctx context.Context, runner lldpRunner) (map[string][]any, error) {
	columns := []string{lldpRemManAddrIfSubtype, lldpRemManAddrIfID, lldpRemManAddrOID}
	rows := make(map[string]map[string]gosnmp.SnmpPDU)
	for _, oid := range columns {
		values, err := walkPDUs(ctx, runner, oid)
		if err != nil {
			return nil, err
		}
		for index, pdu := range values {
			if rows[index] == nil {
				rows[index] = make(map[string]gosnmp.SnmpPDU)
			}
			rows[index][oid] = pdu
		}
	}
	indexes := make([]string, 0, len(rows))
	for index := range rows {
		indexes = append(indexes, index)
	}
	sort.Strings(indexes)
	result := make(map[string][]any)
	for _, index := range indexes {
		rowKey, family, address, ok := managementAddressFromIndex(index)
		if !ok {
			continue
		}
		row := rows[index]
		result[rowKey] = append(result[rowKey], map[string]any{
			"address_family":    addressFamilyName(family),
			"address_family_id": family,
			"address":           address,
			"interface_subtype": intValue(row[lldpRemManAddrIfSubtype]),
			"interface_id":      intValue(row[lldpRemManAddrIfID]),
			"object_oid":        stringValue(row[lldpRemManAddrOID]),
		})
	}
	return result, nil
}

func collectRawTLVs(ctx context.Context, runner lldpRunner, oid string) (map[string][]any, error) {
	values, err := walkPDUs(ctx, runner, oid)
	if err != nil {
		return nil, err
	}
	indexes := make([]string, 0, len(values))
	for index := range values {
		indexes = append(indexes, index)
	}
	sort.Strings(indexes)
	result := make(map[string][]any)
	for _, index := range indexes {
		parts, ok := oidNumbers(index)
		if !ok || len(parts) < 4 {
			continue
		}
		details := map[string]any{
			"oid":       values[index].Name,
			"index":     index,
			"value_hex": hex.EncodeToString(bytesValue(values[index])),
		}
		if text := printableValue(values[index]); text != "" {
			details["value_text"] = text
		}
		if oid == lldpRemUnknownTLVInfo {
			details["tlv_type"] = parts[3]
		} else if len(parts) >= 8 {
			offset := 3
			if parts[offset] == 3 && len(parts) >= 9 {
				offset++
			}
			if len(parts) >= offset+5 {
				details["oui"] = fmt.Sprintf("%02x:%02x:%02x", parts[offset], parts[offset+1], parts[offset+2])
				details["subtype"] = parts[offset+3]
				details["info_index"] = parts[offset+4]
			}
		}
		result[remoteRowKey(parts)] = append(result[remoteRowKey(parts)], details)
	}
	return result, nil
}

func managementAddressFromIndex(index string) (string, int, string, bool) {
	parts, ok := oidNumbers(index)
	if !ok || len(parts) < 5 {
		return "", 0, "", false
	}
	family := parts[3]
	addressBytes := parts[4:]
	if len(addressBytes) > 1 && addressBytes[0] == len(addressBytes)-1 {
		addressBytes = addressBytes[1:]
	}
	bytes := make([]byte, len(addressBytes))
	for index, value := range addressBytes {
		if value < 0 || value > 255 {
			return "", 0, "", false
		}
		bytes[index] = byte(value)
	}
	return remoteRowKey(parts), family, formatNetworkAddress(family, bytes), true
}

func oidNumbers(index string) ([]int, bool) {
	parts := strings.Split(strings.Trim(index, "."), ".")
	values := make([]int, len(parts))
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func remoteRowKey(parts []int) string {
	if len(parts) < 3 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", parts[0], parts[1], parts[2])
}

func resolveLocalInterface(port int, localPortIDs, ifNames, ifDescrs map[int]string,
	ifSpeeds, ifHighSpeeds map[int]int64) (string, int32, int) {
	portID := strings.TrimSpace(localPortIDs[port])
	for ifIndex, ifName := range ifNames {
		if portID != "" && (strings.EqualFold(portID, ifName) || strings.EqualFold(portID, ifDescrs[ifIndex])) {
			return ifName, interfaceSpeed(ifIndex, ifSpeeds, ifHighSpeeds), ifIndex
		}
	}
	if ifName := ifNames[port]; ifName != "" {
		return ifName, interfaceSpeed(port, ifSpeeds, ifHighSpeeds), port
	}
	if portID != "" {
		return portID, 0, 0
	}
	return fmt.Sprintf("port-%d", port), 0, 0
}

func interfaceSpeed(ifIndex int, ifSpeeds, ifHighSpeeds map[int]int64) int32 {
	if highSpeed := ifHighSpeeds[ifIndex]; highSpeed > 0 {
		if highSpeed > int64(^uint32(0)>>1) {
			return int32(^uint32(0) >> 1)
		}
		return int32(highSpeed)
	}
	return mbps(ifSpeeds[ifIndex])
}

func oidSuffix(name, root string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), ".")
	root = strings.TrimPrefix(strings.TrimSpace(root), ".")
	return strings.TrimPrefix(strings.TrimPrefix(name, root), ".")
}

func lastOIDPart(index string) int {
	part := index[strings.LastIndex(index, ".")+1:]
	var value int
	_, _ = fmt.Sscanf(part, "%d", &value)
	return value
}

func lldpLocalPortFromIndex(index string) int {
	parts := strings.Split(index, ".")
	if len(parts) < 3 {
		return 0
	}
	var value int
	_, _ = fmt.Sscanf(parts[len(parts)-2], "%d", &value)
	return value
}

func stringValue(pdu gosnmp.SnmpPDU) string {
	if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView || pdu.Type == gosnmp.Null {
		return ""
	}
	switch value := pdu.Value.(type) {
	case nil:
		return ""
	case []byte:
		return strings.TrimSpace(string(value))
	case string:
		return strings.TrimSpace(value)
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func identifierValue(pdu gosnmp.SnmpPDU, subtype int, chassis bool) string {
	bytes := bytesValue(pdu)
	if len(bytes) == 0 {
		return stringValue(pdu)
	}
	macSubtype := 3
	networkSubtype := 4
	if chassis {
		macSubtype = 4
		networkSubtype = 5
	}
	if subtype == macSubtype {
		return formatMAC(bytes)
	}
	if subtype == networkSubtype && len(bytes) > 1 {
		return formatNetworkAddress(int(bytes[0]), bytes[1:])
	}
	if text := printableBytes(bytes); text != "" {
		return text
	}
	return hex.EncodeToString(bytes)
}

func formatNetworkAddress(family int, address []byte) string {
	if (family == 1 && len(address) == net.IPv4len) || (family == 2 && len(address) == net.IPv6len) {
		return net.IP(address).String()
	}
	if family == 6 && len(address) == 6 {
		return formatMAC(address)
	}
	if text := printableBytes(address); text != "" {
		return text
	}
	return hex.EncodeToString(address)
}

func addressFamilyName(family int) string {
	switch family {
	case 1:
		return "ipv4"
	case 2:
		return "ipv6"
	case 6:
		return "ieee802"
	case 16:
		return "dns"
	default:
		return fmt.Sprintf("iana-%d", family)
	}
}

func formatMAC(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = fmt.Sprintf("%02x", item)
	}
	return strings.Join(parts, ":")
}

func capabilityDetails(pdu gosnmp.SnmpPDU) map[string]any {
	value := bytesValue(pdu)
	capabilities := []string{
		"other", "repeater", "bridge", "wlanAccessPoint", "router", "telephone",
		"docsisCableDevice", "stationOnly", "cVlanComponent", "sVlanComponent", "twoPortMacRelay",
	}
	names := make([]any, 0)
	for bit, name := range capabilities {
		byteIndex := bit / 8
		if byteIndex < len(value) && value[byteIndex]&(1<<uint(7-bit%8)) != 0 {
			names = append(names, name)
		}
	}
	return map[string]any{
		"hex":   hex.EncodeToString(value),
		"names": names,
	}
}

func bytesValue(pdu gosnmp.SnmpPDU) []byte {
	switch value := pdu.Value.(type) {
	case []byte:
		return value
	case string:
		return []byte(value)
	default:
		return nil
	}
}

func printableValue(pdu gosnmp.SnmpPDU) string {
	return printableBytes(bytesValue(pdu))
}

func printableBytes(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	for _, item := range value {
		if item < 32 || item > 126 {
			return ""
		}
	}
	return strings.TrimSpace(string(value))
}

func intValue(pdu gosnmp.SnmpPDU) int {
	value, ok := snmp.PduFloat(pdu)
	if !ok {
		return 0
	}
	return int(value)
}

func mbps(bitsPerSecond int64) int32 {
	if bitsPerSecond <= 0 {
		return 0
	}
	value := bitsPerSecond / 1_000_000
	if value > int64(^uint32(0)>>1) {
		return int32(^uint32(0) >> 1)
	}
	return int32(value)
}

func init() {
	Default.Register("lldp.discover", newLLDPCheck)
}
