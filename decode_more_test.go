// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package snmptrapreceiver

import (
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
)

func TestDecodeVarTypes(t *testing.T) {
	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		PDUType: gosnmp.InformRequest,
		Variables: []gosnmp.SnmpPDU{
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
			{Name: "1.1.1", Type: gosnmp.Integer, Value: int(7)},
			{Name: "1.1.2", Type: gosnmp.IPAddress, Value: []byte{10, 1, 2, 3}},
			{Name: "1.1.3", Type: gosnmp.Counter32, Value: uint32(9)},
			{Name: "1.1.4", Type: gosnmp.Counter64, Value: uint64(11)},
			{Name: "1.1.5", Type: gosnmp.Gauge32, Value: uint32(4)},
			{Name: "1.1.6", Type: gosnmp.Null, Value: nil},
			{Name: "1.1.7", Type: gosnmp.Opaque, Value: []byte{0xff, 0xfe}},
			{Name: "1.1.8", Type: gosnmp.BitString, Value: []byte{0x80}},
			{Name: "1.1.9", Type: gosnmp.Uinteger32, Value: uint32(3)},
			{Name: "1.1.10", Type: gosnmp.Boolean, Value: true},
			{Name: "1.1.11", Type: gosnmp.NoSuchObject, Value: nil},
			{Name: "1.1.12", Type: gosnmp.NoSuchInstance, Value: nil},
			{Name: "1.1.13", Type: gosnmp.EndOfMibView, Value: nil},
			{Name: "1.1.14", Type: gosnmp.NsapAddress, Value: []byte{1, 2}},
			{Name: "1.1.15", Type: gosnmp.Asn1BER(99), Value: "x"},
			{Name: sysUpTime, Type: gosnmp.TimeTicks, Value: int(-1)},
			{Name: "1.1.16", Type: gosnmp.OctetString, Value: net.IP{192, 0, 2, 10}},
		},
	}
	rec := Decode(packet, nil, time.Now(), DecodeOptions{})
	require.Equal(t, "inform", rec.PDUType)
	require.Equal(t, uint(0), rec.SysUpTime)

	got := map[string]string{}
	for _, vb := range rec.Varbinds {
		got[vb.OID] = vb.Type
	}
	require.Equal(t, "Integer", got["1.1.1"])
	require.Equal(t, "IPAddress", got["1.1.2"])
	require.Equal(t, "10.1.2.3", varbindValue(t, rec, "1.1.2"))
	require.Equal(t, "Counter32", got["1.1.3"])
	require.Equal(t, "Counter64", got["1.1.4"])
	require.Equal(t, "Gauge32", got["1.1.5"])
	require.Equal(t, "Null", got["1.1.6"])
	require.Equal(t, "Opaque", got["1.1.7"])
	require.Equal(t, "fffe", varbindValue(t, rec, "1.1.7"))
	require.Equal(t, "BitString", got["1.1.8"])
	require.Equal(t, "Uinteger32", got["1.1.9"])
	require.Equal(t, "Boolean", got["1.1.10"])
	require.Equal(t, "NoSuchObject", got["1.1.11"])
	require.Equal(t, "NoSuchInstance", got["1.1.12"])
	require.Equal(t, "EndOfMibView", got["1.1.13"])
	require.Equal(t, "NsapAddress", got["1.1.14"])
	require.Equal(t, "type_99", got["1.1.15"])
	require.Equal(t, "192.0.2.10", varbindValue(t, rec, "1.1.16"))
}

func TestDecodeEdges(t *testing.T) {
	unknown := &gosnmp.SnmpPacket{Version: gosnmp.SnmpVersion(9), PDUType: gosnmp.GetRequest}
	rec := Decode(unknown, nil, time.Now(), DecodeOptions{})
	require.Equal(t, "9", rec.Version)
	require.NotEqual(t, "trap", rec.PDUType)
	require.False(t, rec.Resolved())

	emptyEnt := &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: 6}}
	require.Empty(t, Decode(emptyEnt, nil, time.Now(), DecodeOptions{}).TrapOID)

	outOfRange := &gosnmp.SnmpPacket{Version: gosnmp.Version1, SnmpTrap: gosnmp.SnmpTrap{GenericTrap: 7, Enterprise: "1.2.3"}}
	require.Empty(t, Decode(outOfRange, nil, time.Now(), DecodeOptions{}).TrapOID)

	require.Equal(t, Lookup{Name: "1.2.3"}, lookup(nil, "1.2.3"))
	require.Equal(t, Lookup{Name: ""}, lookup(NoopTranslator{}, ""))
	require.Equal(t, Lookup{Name: "1.2.3"}, lookup(emptyNameTranslator{}, "1.2.3"))

	_, ok := asUint(int32(-2))
	require.False(t, ok)
	n, ok := asUint(uint(4))
	require.True(t, ok)
	require.Equal(t, uint(4), n)
	n, ok = asUint(int32(6))
	require.True(t, ok)
	require.Equal(t, uint(6), n)
	n, ok = asUint(uint64(8))
	require.True(t, ok)
	require.Equal(t, uint(8), n)
	_, ok = asUint("nope")
	require.False(t, ok)

	require.Equal(t, "1.2.3", formatValue(gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.2.3"}))
	require.Equal(t, "plain", formatValue(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: "plain"}))
	require.Equal(t, "fffe", formatValue(gosnmp.SnmpPDU{Type: gosnmp.IPAddress, Value: []byte{0xff, 0xfe}}))
	require.Equal(t, "ab", stringify([]byte{'a', 'b'}))
	require.Equal(t, "z", stringify("z"))
	require.Equal(t, "7", stringify(7))

	require.Equal(t, "trap", pduKind(0))
	require.Equal(t, "inform", pduKind(gosnmp.InformRequest))
}

type emptyNameTranslator struct{}

func (emptyNameTranslator) Lookup(string) (Lookup, error) {
	return Lookup{}, nil
}

func varbindValue(t *testing.T, rec Record, oid string) any {
	t.Helper()
	for _, vb := range rec.Varbinds {
		if vb.OID == oid {
			return vb.Value
		}
	}
	t.Fatalf("missing varbind %s", oid)
	return nil
}
