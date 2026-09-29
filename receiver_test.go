// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package snmptrapreceiver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/Mesverrum/otelcol-snmptrapreceiver/internal/metadata"
)

func TestHandleTrapForwardsLog(t *testing.T) {
	sink := &consumertest.LogsSink{}
	recv, err := newReceiver(&Config{ListenAddress: "127.0.0.1:0", Attributes: map[string]string{"job": "snmptrap"}}, receivertest.NewNopSettings(metadata.Type), sink)
	require.NoError(t, err)

	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		PDUType:   gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
		},
	}
	recv.handleTrap(packet, &net.UDPAddr{IP: net.ParseIP("172.20.20.2"), Port: 161})
	require.Len(t, recv.queue, 1)
	ld := <-recv.queue
	require.Equal(t, 1, ld.LogRecordCount())
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	v, ok := lr.Attributes().Get("trap_oid")
	require.True(t, ok)
	require.Equal(t, "1.3.6.1.6.3.1.1.5.3", v.AsString())
}

func TestHandleTrapDrops(t *testing.T) {
	recv := testReceiver(t, &Config{
		ListenAddress:    "127.0.0.1:0",
		Communities:      []string{"public"},
		IncludeCommunity: true,
		DropUndefined:    true,
	})

	recv.handleTrap(nil, nil)
	require.Empty(t, recv.queue)

	rejected := linkDownPacket()
	rejected.Community = "private"
	recv.handleTrap(rejected, nil)
	require.Empty(t, recv.queue)

	recv.handleTrap(linkDownPacket(), nil)
	require.Empty(t, recv.queue)

	recv.cfg.DropUndefined = false
	recv.handleTrap(linkDownPacket(), &net.UDPAddr{IP: net.ParseIP("10.0.0.8"), Port: 161})
	require.Len(t, recv.queue, 1)
	ld := <-recv.queue
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	community, ok := lr.Attributes().Get("community")
	require.True(t, ok)
	require.Equal(t, "public", community.AsString())
}

func TestHandleTrapQueueFull(t *testing.T) {
	recv := testReceiver(t, &Config{ListenAddress: "127.0.0.1:0"})
	recv.queue = make(chan plog.Logs, 1)
	recv.queue <- plog.NewLogs()
	recv.handleTrap(linkDownPacket(), nil)
	require.Len(t, recv.queue, 1)
}

func TestStartErrors(t *testing.T) {
	recv := testReceiver(t, &Config{
		ListenAddress: "127.0.0.1:0",
		V3:            &V3Config{User: "trapuser", SecurityLevel: "nope"},
	})
	require.Error(t, recv.Start(t.Context(), nil))

	recv = testReceiver(t, &Config{ListenAddress: "127.0.0.1:99999"})
	require.Error(t, recv.Start(t.Context(), nil))
}

func TestDrainConsumeError(t *testing.T) {
	done := make(chan struct{})
	recv := testReceiver(t, &Config{ListenAddress: "127.0.0.1:0"})
	recv.next = signalConsumer{done: done}
	ctx, cancel := context.WithCancel(t.Context())
	recv.wg.Add(1)
	go recv.drain(ctx)
	recv.queue <- plog.NewLogs()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not consume the trap log")
	}
	cancel()
	recv.wg.Wait()
}

func TestDrainNilNext(t *testing.T) {
	recv := testReceiver(t, &Config{ListenAddress: "127.0.0.1:0"})
	recv.next = nil
	ctx, cancel := context.WithCancel(t.Context())
	recv.wg.Add(1)
	go recv.drain(ctx)
	recv.queue <- plog.NewLogs()
	require.Eventually(t, func() bool {
		return len(recv.queue) == 0
	}, time.Second, 5*time.Millisecond)
	cancel()
	recv.wg.Wait()
}

func testReceiver(t *testing.T, cfg *Config) *snmpTrapReceiver {
	t.Helper()
	recv, err := newReceiver(cfg, receivertest.NewNopSettings(metadata.Type), consumertest.NewNop())
	require.NoError(t, err)
	return recv
}

func linkDownPacket() *gosnmp.SnmpPacket {
	return &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		PDUType:   gosnmp.SNMPv2Trap,
		Variables: []gosnmp.SnmpPDU{
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: "1.3.6.1.6.3.1.1.5.3"},
		},
	}
}

type signalConsumer struct {
	done chan struct{}
}

func (signalConsumer) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func (s signalConsumer) ConsumeLogs(context.Context, plog.Logs) error {
	close(s.done)
	return errors.New("consume failed")
}

func TestStartShutdown(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.ListenAddress = "127.0.0.1:0"
	set := receivertest.NewNopSettings(metadata.Type)
	recv, err := factory.CreateLogs(t.Context(), set, cfg, consumertest.NewNop())
	require.NoError(t, err)
	require.NoError(t, recv.Start(t.Context(), nil))
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, recv.Shutdown(t.Context()))
}
