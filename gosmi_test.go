// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package snmptrapreceiver

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCleanPaths(t *testing.T) {
	got := cleanPaths([]string{" /mibs ", "", "/mibs", "  ", "/other"})
	require.Equal(t, []string{"/mibs", "/other"}, got)
	require.Empty(t, cleanPaths(nil))
}

func TestGosmiMissingAndJunk(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	tr, err := NewGosmiTranslator([]string{missing, missing, " "}, nil)
	require.NoError(t, err)
	_, ok := tr.(*GosmiTranslator)
	require.True(t, ok)

	_, err = loadDir(missing)
	require.Error(t, err)

	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".hidden"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.png"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a mib"), 0o644))
	n, err := loadDir(dir)
	require.NoError(t, err)
	require.Equal(t, 0, n)
}

func TestGosmiLookup(t *testing.T) {
	dir := t.TempDir()
	mib := filepath.Join(dir, "TRAPTEST-MIB.mib")
	require.NoError(t, os.WriteFile(mib, []byte(trapTestMIB), 0o644))

	tr, err := NewGosmiTranslator([]string{dir}, nil)
	require.NoError(t, err)
	g, ok := tr.(*GosmiTranslator)
	require.True(t, ok)

	_, err = g.Lookup("")
	require.Error(t, err)
	_, err = g.Lookup("not-an-oid")
	require.Error(t, err)
	_, err = g.Lookup("1.3.6.1.9.9.9.9")
	require.Error(t, err)

	got, err := g.Lookup("1.3.6.1.4.1.99999.1")
	require.NoError(t, err)
	require.Equal(t, "TRAPTEST-MIB::testTrap", got.Name)
	require.Equal(t, "TRAPTEST-MIB", got.MIB)
}

const trapTestMIB = `TRAPTEST-MIB DEFINITIONS ::= BEGIN
testRoot OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 99999 }
testTrap OBJECT IDENTIFIER ::= { testRoot 1 }
END
`
