// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutils

import (
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

//go:embed testdata/tcp_ao_uapi/*.hex
var tcpAOGoldenFiles embed.FS

func tcpAOTestKey(sendID, receiveID uint8) TCPAOKey {
	return TCPAOKey{
		SendID:    sendID,
		ReceiveID: receiveID,
		Algorithm: TCPAOAlgorithmHMACSHA1_96,
		MasterKey: []byte("secret"),
	}
}

func decodeTCPAOWire[T any](t *testing.T, value []byte) T {
	t.Helper()
	var wire T
	wireSize := binary.Size(&wire)
	if wireSize != len(value) {
		t.Fatalf("wire record size = %d, input size = %d", wireSize, len(value))
	}
	n, err := binary.Decode(value, binary.LittleEndian, &wire)
	if err != nil {
		t.Fatalf("decode wire record: %v", err)
	}
	if n != wireSize {
		t.Fatalf("decoded %d wire bytes, want %d", n, wireSize)
	}
	return wire
}

func assertTCPAOZeroBytes(t *testing.T, name string, value []byte) {
	t.Helper()
	for i, b := range value {
		if b != 0 {
			t.Fatalf("%s byte %d = %#x, want zero", name, i, b)
		}
	}
}

func assertTCPAOGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := "testdata/tcp_ao_uapi/" + name + ".hex"
	data, err := tcpAOGoldenFiles.ReadFile(path)
	if err != nil {
		t.Fatalf("read TCP-AO golden %s: %v", path, err)
	}
	want, err := hex.DecodeString(strings.Join(strings.Fields(string(data)), ""))
	if err != nil {
		t.Fatalf("decode TCP-AO golden %s: %v", path, err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("TCP-AO command differs from Linux UAPI golden %s\n got: %x\nwant: %x", path, got, want)
	}
}

func TestTCPAOWireSizes(t *testing.T) {
	tests := []struct {
		name string
		wire any
		want int
	}{
		{name: "sockaddr storage", wire: tcpAOSockaddrStorage{}, want: tcpAOSockaddrStorageSize},
		{name: "IPv4 sockaddr", wire: tcpAOSockaddrInet4Wire{}, want: tcpAOSockaddrInet4Size},
		{name: "IPv6 sockaddr", wire: tcpAOSockaddrInet6Wire{}, want: tcpAOSockaddrInet6Size},
		{name: "ADD_KEY", wire: tcpAOAddWire{}, want: tcpAOAddSize},
		{name: "DEL_KEY", wire: tcpAODelWire{}, want: tcpAODelSize},
		{name: "INFO", wire: tcpAOInfoWire{}, want: tcpAOInfoSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := binary.Size(tt.wire); got != tt.want {
				t.Fatalf("encoded size = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestTCPAOAddMarshalIPv4(t *testing.T) {
	const interfaceIndex = int32(0x01020304)
	key := tcpAOTestKey(7, 9)
	key.ExcludeTCPOptions = true
	command, err := marshalTCPAOAdd(netip.MustParsePrefix("192.0.2.1/32"), interfaceIndex, key, true)
	if err != nil {
		t.Fatal(err)
	}
	assertTCPAOGolden(t, "add_ipv4", command[:])
}

func TestTCPAOAddMarshalIPv6(t *testing.T) {
	key := TCPAOKey{
		SendID:    1,
		ReceiveID: 2,
		Algorithm: TCPAOAlgorithmAES128CMAC96,
		MasterKey: []byte("0123456789abcdef"),
	}
	command, err := marshalTCPAOAdd(netip.MustParsePrefix("2001:db8:1::/64"), 0, key, false)
	if err != nil {
		t.Fatal(err)
	}
	assertTCPAOGolden(t, "add_ipv6", command[:])
}

func TestTCPAODelMarshalUsesIdentityOnly(t *testing.T) {
	key := tcpAOTestKey(7, 9)
	key.ExcludeTCPOptions = true
	command, err := marshalTCPAODel(netip.MustParsePrefix("198.51.100.0/24"), 42, key)
	if err != nil {
		t.Fatal(err)
	}
	assertTCPAOGolden(t, "del_ipv4", command[:])
}

func TestTCPAOInfoDerivesRNextFromSelectedKey(t *testing.T) {
	preferred := uint8(7)
	config := TCPAOConfig{
		Keys: []TCPAOKey{
			tcpAOTestKey(7, 23),
			tcpAOTestKey(1, 42),
		},
		PreferredSendID: &preferred,
	}
	command, err := marshalTCPAOInfo(config)
	if err != nil {
		t.Fatal(err)
	}
	assertTCPAOGolden(t, "info", command[:])
}

func TestTCPAOInfoAllowsZeroCurrentKey(t *testing.T) {
	preferred := uint8(0)
	command, err := marshalTCPAOInfo(TCPAOConfig{
		Keys:            []TCPAOKey{tcpAOTestKey(0, 23)},
		PreferredSendID: &preferred,
	})
	if err != nil {
		t.Fatal(err)
	}
	info := decodeTCPAOWire[tcpAOInfoWire](t, command[:])
	if info.CurrentKey != 0 || info.RNextKey != 23 {
		t.Errorf("CurrentKey/RNextKey = %d/%d, want 0/23", info.CurrentKey, info.RNextKey)
	}
}

func TestTCPAOValidation(t *testing.T) {
	validKey := tcpAOTestKey(1, 2)
	preferred := uint8(9)
	tests := []struct {
		name    string
		scope   netip.Prefix
		ifindex int32
		config  TCPAOConfig
	}{
		{name: "invalid scope", scope: netip.Prefix{}, config: TCPAOConfig{Keys: []TCPAOKey{validKey}}},
		{name: "unmasked scope", scope: netip.MustParsePrefix("192.0.2.1/24"), config: TCPAOConfig{Keys: []TCPAOKey{validKey}}},
		{name: "mapped IPv4", scope: netip.MustParsePrefix("::ffff:192.0.2.1/128"), config: TCPAOConfig{Keys: []TCPAOKey{validKey}}},
		{name: "negative ifindex", scope: netip.MustParsePrefix("192.0.2.1/32"), ifindex: -1, config: TCPAOConfig{Keys: []TCPAOKey{validKey}}},
		{name: "empty secret", scope: netip.MustParsePrefix("192.0.2.1/32"), config: TCPAOConfig{Keys: []TCPAOKey{{SendID: 1, ReceiveID: 2, Algorithm: TCPAOAlgorithmHMACSHA1_96}}}},
		{name: "unknown algorithm", scope: netip.MustParsePrefix("192.0.2.1/32"), config: TCPAOConfig{Keys: []TCPAOKey{{SendID: 1, ReceiveID: 2, Algorithm: TCPAOAlgorithm(99), MasterKey: []byte("secret")}}}},
		{name: "duplicate send ID", scope: netip.MustParsePrefix("192.0.2.1/32"), config: TCPAOConfig{Keys: []TCPAOKey{validKey, tcpAOTestKey(1, 3)}}},
		{name: "duplicate receive ID", scope: netip.MustParsePrefix("192.0.2.1/32"), config: TCPAOConfig{Keys: []TCPAOKey{validKey, tcpAOTestKey(3, 2)}}},
		{name: "missing preferred ID", scope: netip.MustParsePrefix("192.0.2.1/32"), config: TCPAOConfig{Keys: []TCPAOKey{validKey}, PreferredSendID: &preferred}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateTCPAOAddKeys(tt.config.Keys); err == nil {
				if _, err = selectedTCPAOKey(tt.config); err == nil {
					_, err = marshalTCPAOAdd(tt.scope, tt.ifindex, tt.config.Keys[0], false)
				}
				if err == nil {
					t.Fatal("validation succeeded, want an error")
				}
			}
		})
	}
}

func TestTCPAOWildcardScope(t *testing.T) {
	key := tcpAOTestKey(1, 2)
	for _, scope := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	} {
		if _, err := marshalTCPAOAdd(scope, 0, key, false); err != nil {
			t.Errorf("scope %s: %v", scope, err)
		}
	}
}

func TestTCPAOAddRollsBackPartialInstallation(t *testing.T) {
	setErr := errors.New("injected add failure")
	type call struct {
		option int
		value  []byte
	}
	var calls []call
	addCalls := 0
	setSockopt := func(option int, value []byte) error {
		calls = append(calls, call{option: option, value: slices.Clone(value)})
		if option == tcpAOAddKey {
			addCalls++
			if addCalls == 2 {
				return setErr
			}
		}
		return nil
	}

	config := TCPAOConfig{Keys: []TCPAOKey{
		tcpAOTestKey(1, 11),
		tcpAOTestKey(2, 12),
		tcpAOTestKey(3, 13),
	}}
	err := addTCPAOKeys(setSockopt, netip.MustParsePrefix("192.0.2.1/32"), 0, config)
	if !errors.Is(err, setErr) {
		t.Fatalf("error = %v, want injected failure", err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want two adds and one rollback delete", len(calls))
	}
	if calls[0].option != tcpAOAddKey || calls[1].option != tcpAOAddKey || calls[2].option != tcpAODelKey {
		t.Fatalf("option sequence = %v, want ADD, ADD, DEL", []int{calls[0].option, calls[1].option, calls[2].option})
	}
	rollback := decodeTCPAOWire[tcpAODelWire](t, calls[2].value)
	if rollback.SendID != 1 || rollback.ReceiveID != 11 {
		t.Errorf("rollback IDs = %d/%d, want 1/11", rollback.SendID, rollback.ReceiveID)
	}
}

func TestTCPAOAddClearsCommandBuffer(t *testing.T) {
	var retained []byte
	err := addTCPAOKeys(func(option int, value []byte) error {
		if option != tcpAOAddKey {
			t.Fatalf("option = %d, want ADD", option)
		}
		retained = value
		wire := decodeTCPAOWire[tcpAOAddWire](t, value)
		if string(wire.Key[:wire.KeyLength]) != "secret" {
			t.Fatal("master key is not present during setsockopt")
		}
		return nil
	}, netip.MustParsePrefix("192.0.2.1/32"), 0, TCPAOConfig{Keys: []TCPAOKey{tcpAOTestKey(1, 11)}})
	if err != nil {
		t.Fatal(err)
	}
	if retained == nil {
		t.Fatal("setsockopt did not retain a command buffer")
	}
	assertTCPAOZeroBytes(t, "ADD command after setsockopt", retained)
}

func TestTCPAOAddReportsRollbackFailure(t *testing.T) {
	addErr := errors.New("injected add failure")
	deleteErr := errors.New("injected rollback failure")
	addCalls := 0
	setSockopt := func(option int, _ []byte) error {
		switch option {
		case tcpAOAddKey:
			addCalls++
			if addCalls == 2 {
				return addErr
			}
		case tcpAODelKey:
			return deleteErr
		}
		return nil
	}

	config := TCPAOConfig{Keys: []TCPAOKey{
		tcpAOTestKey(1, 11),
		tcpAOTestKey(2, 12),
	}}
	err := addTCPAOKeys(setSockopt, netip.MustParsePrefix("192.0.2.1/32"), 0, config)
	if !errors.Is(err, addErr) || !errors.Is(err, deleteErr) {
		t.Fatalf("error = %v, want both add and rollback failures", err)
	}
}

func TestTCPAODeleteRemovesAllKeys(t *testing.T) {
	type call struct {
		option int
		value  []byte
	}
	var calls []call
	setSockopt := func(option int, value []byte) error {
		calls = append(calls, call{option: option, value: slices.Clone(value)})
		return nil
	}

	config := TCPAOConfig{Keys: []TCPAOKey{
		tcpAOTestKey(1, 11),
		tcpAOTestKey(2, 12),
	}}
	if err := deleteTCPAOKeys(setSockopt, netip.MustParsePrefix("192.0.2.1/32"), 0, config); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want two deletes", len(calls))
	}
	if calls[0].option != tcpAODelKey || calls[1].option != tcpAODelKey {
		t.Fatalf("option sequence = %v, want DEL, DEL", []int{calls[0].option, calls[1].option})
	}
	first := decodeTCPAOWire[tcpAODelWire](t, calls[0].value)
	second := decodeTCPAOWire[tcpAODelWire](t, calls[1].value)
	if first.SendID != 1 || second.SendID != 2 {
		t.Errorf("deleted SendIDs = %d/%d, want 1/2", first.SendID, second.SendID)
	}
}

func TestTCPAODeleteRollsBackPartialDeletion(t *testing.T) {
	deleteErr := errors.New("injected delete failure")
	type call struct {
		option int
		value  []byte
	}
	var calls []call
	var rollbackBuffer []byte
	deleteCalls := 0
	setSockopt := func(option int, value []byte) error {
		calls = append(calls, call{option: option, value: slices.Clone(value)})
		if option == tcpAOAddKey {
			rollbackBuffer = value
		}
		if option == tcpAODelKey {
			deleteCalls++
			if deleteCalls == 2 {
				return deleteErr
			}
		}
		return nil
	}

	config := TCPAOConfig{Keys: []TCPAOKey{
		tcpAOTestKey(1, 11),
		tcpAOTestKey(2, 12),
		tcpAOTestKey(3, 13),
	}}
	err := deleteTCPAOKeys(setSockopt, netip.MustParsePrefix("192.0.2.1/32"), 0, config)
	if !errors.Is(err, deleteErr) {
		t.Fatalf("error = %v, want injected delete failure", err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %d, want two deletes and one rollback add", len(calls))
	}
	if calls[0].option != tcpAODelKey || calls[1].option != tcpAODelKey || calls[2].option != tcpAOAddKey {
		t.Fatalf("option sequence = %v, want DEL, DEL, ADD", []int{calls[0].option, calls[1].option, calls[2].option})
	}
	rollback := decodeTCPAOWire[tcpAOAddWire](t, calls[2].value)
	if rollback.SendID != 1 || rollback.ReceiveID != 11 {
		t.Errorf("rollback IDs = %d/%d, want 1/11", rollback.SendID, rollback.ReceiveID)
	}
	if got := string(rollback.Key[:rollback.KeyLength]); got != "secret" {
		t.Errorf("rollback master key = %q, want restored key material", got)
	}
	if rollback.Flags != 0 {
		t.Errorf("rollback selection flags = %#x, want zero", rollback.Flags)
	}
	assertTCPAOZeroBytes(t, "rollback ADD command after setsockopt", rollbackBuffer)
}

func TestTCPAODeleteReportsRollbackFailure(t *testing.T) {
	deleteErr := errors.New("injected delete failure")
	addErr := errors.New("injected rollback failure")
	deleteCalls := 0
	setSockopt := func(option int, _ []byte) error {
		switch option {
		case tcpAODelKey:
			deleteCalls++
			if deleteCalls == 2 {
				return deleteErr
			}
		case tcpAOAddKey:
			return addErr
		}
		return nil
	}

	config := TCPAOConfig{Keys: []TCPAOKey{
		tcpAOTestKey(1, 11),
		tcpAOTestKey(2, 12),
	}}
	err := deleteTCPAOKeys(setSockopt, netip.MustParsePrefix("192.0.2.1/32"), 0, config)
	if !errors.Is(err, deleteErr) || !errors.Is(err, addErr) {
		t.Fatalf("error = %v, want both delete and rollback failures", err)
	}
}

func TestTCPAOAddInstallsSelectedKeyLast(t *testing.T) {
	preferred := uint8(1)
	config := TCPAOConfig{
		Keys: []TCPAOKey{
			tcpAOTestKey(1, 11),
			tcpAOTestKey(2, 12),
		},
		PreferredSendID: &preferred,
	}
	var sendIDs []uint8
	var flags []uint32
	err := addTCPAOKeys(func(option int, value []byte) error {
		if option != tcpAOAddKey {
			t.Fatalf("option = %d, want ADD", option)
		}
		wire := decodeTCPAOWire[tcpAOAddWire](t, value)
		sendIDs = append(sendIDs, wire.SendID)
		flags = append(flags, wire.Flags)
		return nil
	}, netip.MustParsePrefix("192.0.2.1/32"), 0, config)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sendIDs, []uint8{2, 1}) {
		t.Fatalf("SendID order = %v, want [2 1]", sendIDs)
	}
	if !slices.Equal(flags, []uint32{0, tcpAOFlagSetCurrent | tcpAOFlagSetRNext}) {
		t.Fatalf("flags = %v", flags)
	}
}
