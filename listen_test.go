// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package snmptrapreceiver

import (
	"io"
	"log/slog"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/require"
)

func TestListenChanged(t *testing.T) {
	base := ListenConfig{ListenAddress: "127.0.0.1:1620", Communities: []string{"public"}, MIBPaths: []string{"/mibs"}}
	require.False(t, ListenChanged(base, base))

	changedAddr := base
	changedAddr.ListenAddress = "127.0.0.1:1162"
	require.True(t, ListenChanged(base, changedAddr))

	changedCommunity := base
	changedCommunity.Communities = []string{"private"}
	require.True(t, ListenChanged(base, changedCommunity))

	changedMIB := base
	changedMIB.MIBPaths = []string{"/other"}
	require.True(t, ListenChanged(base, changedMIB))

	withV3 := base
	withV3.V3 = &V3Config{User: "u"}
	require.True(t, ListenChanged(base, withV3))

	otherV3 := withV3
	otherV3.V3 = &V3Config{User: "u", AuthPassword: "x"}
	require.True(t, ListenChanged(withV3, otherV3))
	require.False(t, v3Changed(nil, nil))
	require.False(t, v3Changed(&V3Config{User: "u"}, &V3Config{User: "u"}))
}

func TestGoSNMPParamsV3(t *testing.T) {
	params, err := GoSNMPParams(ListenConfig{}, slog.Default())
	require.NoError(t, err)
	require.Equal(t, gosnmp.Version2c, params.Version)

	params, err = GoSNMPParams(ListenConfig{V3: &V3Config{
		User:          "trapuser",
		SecurityLevel: "authPriv",
		AuthProtocol:  "SHA256",
		AuthPassword:  "authauthauth",
		PrivProtocol:  "AES",
		PrivPassword:  "privprivpriv",
	}}, slog.Default())
	require.NoError(t, err)
	require.Equal(t, gosnmp.Version3, params.Version)
	require.Equal(t, gosnmp.AuthPriv, params.MsgFlags)
	usm, ok := params.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	require.True(t, ok)
	require.Equal(t, "trapuser", usm.UserName)
	require.Equal(t, gosnmp.SHA256, usm.AuthenticationProtocol)
	require.Equal(t, gosnmp.AES, usm.PrivacyProtocol)

	_, err = GoSNMPParams(ListenConfig{V3: &V3Config{User: "u", SecurityLevel: "nope"}}, nil)
	require.Error(t, err)
	_, err = GoSNMPParams(ListenConfig{V3: &V3Config{User: "u", SecurityLevel: "authNoPriv", AuthProtocol: "nope"}}, nil)
	require.Error(t, err)
	_, err = GoSNMPParams(ListenConfig{V3: &V3Config{User: "u", SecurityLevel: "authPriv", AuthProtocol: "MD5", PrivProtocol: "nope"}}, nil)
	require.Error(t, err)
}

func TestV3ProtocolMaps(t *testing.T) {
	flags := []struct {
		in   string
		want gosnmp.SnmpV3MsgFlags
		ok   bool
	}{
		{"", gosnmp.NoAuthNoPriv, true},
		{"noAuthNoPriv", gosnmp.NoAuthNoPriv, true},
		{"authNoPriv", gosnmp.AuthNoPriv, true},
		{"authPriv", gosnmp.AuthPriv, true},
		{"bogus", 0, false},
	}
	for _, tc := range flags {
		got, err := mapMsgFlags(tc.in)
		if tc.ok {
			require.NoError(t, err, tc.in)
			require.Equal(t, tc.want, got, tc.in)
		} else {
			require.Error(t, err, tc.in)
		}
	}

	auths := []struct {
		in   string
		want gosnmp.SnmpV3AuthProtocol
	}{
		{"", gosnmp.NoAuth},
		{"none", gosnmp.NoAuth},
		{"noauth", gosnmp.NoAuth},
		{"MD5", gosnmp.MD5},
		{"SHA", gosnmp.SHA},
		{"SHA224", gosnmp.SHA224},
		{"SHA256", gosnmp.SHA256},
		{"SHA384", gosnmp.SHA384},
		{"SHA512", gosnmp.SHA512},
	}
	for _, tc := range auths {
		got, err := mapAuthProtocol(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
	_, err := mapAuthProtocol("nope")
	require.Error(t, err)

	privs := []struct {
		in   string
		want gosnmp.SnmpV3PrivProtocol
	}{
		{"", gosnmp.NoPriv},
		{"none", gosnmp.NoPriv},
		{"nopriv", gosnmp.NoPriv},
		{"DES", gosnmp.DES},
		{"AES", gosnmp.AES},
		{"AES192", gosnmp.AES192},
		{"AES192C", gosnmp.AES192C},
		{"AES256", gosnmp.AES256},
		{"AES256C", gosnmp.AES256C},
	}
	for _, tc := range privs {
		got, err := mapPrivProtocol(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
	_, err = mapPrivProtocol("nope")
	require.Error(t, err)
}

func TestPDUKindAndLogger(t *testing.T) {
	require.Equal(t, "inform", PDUKind(gosnmp.InformRequest))
	require.Equal(t, "trap", PDUKind(gosnmp.SNMPv2Trap))

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	snmpLogger{log: discard}.Print("hello")
	snmpLogger{log: discard}.Printf("hello %s", "there")
	snmpLogger{}.Print("dropped")
	snmpLogger{}.Printf("dropped %s", "too")
}
