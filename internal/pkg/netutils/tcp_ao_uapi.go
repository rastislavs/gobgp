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
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// TCP-AO was added to the Linux UAPI in Linux 6.7. The supported Linux
// architectures are little-endian, so the host-endian UAPI fields are encoded
// using binary.LittleEndian. Keep the wire records below free of implicit
// padding: encoding/binary writes their fields contiguously.
const (
	tcpAOAddKey = 38
	tcpAODelKey = 39
	tcpAOInfo   = 40

	tcpAOSockaddrStorageSize = 128
	tcpAOSockaddrInet4Size   = 16
	tcpAOSockaddrInet6Size   = 28
	tcpAOAlgorithmNameSize   = 64
	tcpAOAddSize             = 288
	tcpAODelSize             = 144
	tcpAOInfoSize            = 48

	tcpAOAFInet  = 2
	tcpAOAFInet6 = 10

	tcpAOFlagSetCurrent = 1 << 0
	tcpAOFlagSetRNext   = 1 << 1

	tcpAOKeyFlagIfindex    = 1 << 0
	tcpAOKeyFlagExcludeOpt = 1 << 1

	tcpAOMACLength = 12
)

type tcpAOAddCommand [tcpAOAddSize]byte
type tcpAODelCommand [tcpAODelSize]byte
type tcpAOInfoCommand [tcpAOInfoSize]byte

// tcpAOSockaddrStorage mirrors Linux struct __kernel_sockaddr_storage:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/socket.h#L16-L27
type tcpAOSockaddrStorage [tcpAOSockaddrStorageSize]byte

// tcpAOAddWire mirrors Linux struct tcp_ao_add:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L378-L393
//
// Flags replaces the C bitfield group with its complete uint32 storage word;
// Reserved2 represents explicit UAPI padding. The encoded size is checked
// before every encode and in tests.
type tcpAOAddWire struct {
	Address        tcpAOSockaddrStorage
	Algorithm      [tcpAOAlgorithmNameSize]byte
	InterfaceIndex int32
	Flags          uint32
	Reserved2      uint16
	PrefixLength   uint8
	SendID         uint8
	ReceiveID      uint8
	MACLength      uint8
	KeyFlags       uint8
	KeyLength      uint8
	Key            [tcpAOMaxKeyLen]byte
}

// tcpAODelWire mirrors Linux struct tcp_ao_del:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L395-L409
//
// Flags replaces the C bitfield group with its complete uint32 storage word;
// Reserved2 represents explicit UAPI padding.
type tcpAODelWire struct {
	Address        tcpAOSockaddrStorage
	InterfaceIndex int32
	Flags          uint32
	Reserved2      uint16
	PrefixLength   uint8
	SendID         uint8
	ReceiveID      uint8
	CurrentKey     uint8
	RNextKey       uint8
	KeyFlags       uint8
}

// tcpAOInfoWire mirrors Linux struct tcp_ao_info_opt:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/tcp.h#L411-L427
//
// Flags replaces the C bitfield group with its complete uint32 storage word;
// Reserved2 represents explicit UAPI padding.
type tcpAOInfoWire struct {
	Flags             uint32
	Reserved2         uint16
	CurrentKey        uint8
	RNextKey          uint8
	PacketGood        uint64
	PacketBad         uint64
	PacketKeyNotFound uint64
	PacketAORequired  uint64
	PacketDroppedICMP uint64
}

// tcpAOSockaddrInet4Wire mirrors Linux struct sockaddr_in:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/in.h#L256-L265
type tcpAOSockaddrInet4Wire struct {
	Family  uint16
	Port    [2]byte
	Address [4]byte
	Zero    [8]byte
}

// tcpAOSockaddrInet6Wire mirrors Linux struct sockaddr_in6:
// https://github.com/torvalds/linux/blob/v6.7/include/uapi/linux/in6.h#L50-L56
type tcpAOSockaddrInet6Wire struct {
	Family   uint16
	Port     [2]byte
	FlowInfo [4]byte
	Address  [16]byte
	ScopeID  uint32
}

type tcpAOSetSockoptFunc func(option int, value []byte) error

func encodeTCPAOWire(dst []byte, wire any) error {
	wireSize := binary.Size(wire)
	if wireSize < 0 {
		return fmt.Errorf("TCP-AO wire record has a variable-size field")
	}
	if wireSize != len(dst) {
		return fmt.Errorf("TCP-AO wire record size is %d, want %d", wireSize, len(dst))
	}
	n, err := binary.Encode(dst, binary.LittleEndian, wire)
	if err != nil {
		return fmt.Errorf("failed to encode TCP-AO wire record: %w", err)
	}
	if n != wireSize {
		return fmt.Errorf("encoded %d TCP-AO wire bytes, want %d", n, wireSize)
	}
	return nil
}

func encodeTCPAOSockaddr(storage *tcpAOSockaddrStorage, wire any) error {
	wireSize := binary.Size(wire)
	if wireSize < 0 || wireSize > len(storage) {
		return fmt.Errorf("TCP-AO sockaddr wire record size is %d, maximum %d", wireSize, len(storage))
	}
	return encodeTCPAOWire(storage[:wireSize], wire)
}

func validateTCPAOScope(scope netip.Prefix, ifindex int32) error {
	if !scope.IsValid() {
		return fmt.Errorf("invalid TCP-AO peer scope")
	}
	if ifindex < 0 {
		return fmt.Errorf("invalid TCP-AO interface index %d", ifindex)
	}
	addr := scope.Addr()
	if addr.Zone() != "" {
		return fmt.Errorf("TCP-AO peer scope must not contain an IPv6 zone")
	}
	if addr.Is4In6() {
		return fmt.Errorf("TCP-AO peer scope must use an unmapped IPv4 address")
	}
	if scope != scope.Masked() {
		return fmt.Errorf("TCP-AO peer scope %s has host bits set", scope)
	}
	if scope.Bits() != 0 && addr.IsUnspecified() {
		return fmt.Errorf("TCP-AO wildcard address requires a zero-length prefix")
	}
	return nil
}

func validateTCPAOKeyIDs(keys []TCPAOKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("TCP-AO requires at least one key")
	}
	if len(keys) > 256 {
		return fmt.Errorf("TCP-AO supports at most 256 keys")
	}
	var sendIDs, receiveIDs [256]bool
	for _, key := range keys {
		if sendIDs[key.SendID] {
			return fmt.Errorf("duplicate TCP-AO SendID %d", key.SendID)
		}
		if receiveIDs[key.ReceiveID] {
			return fmt.Errorf("duplicate TCP-AO ReceiveID %d", key.ReceiveID)
		}
		sendIDs[key.SendID] = true
		receiveIDs[key.ReceiveID] = true
	}
	return nil
}

func validateTCPAOAddKeys(keys []TCPAOKey) error {
	if err := validateTCPAOKeyIDs(keys); err != nil {
		return err
	}
	for _, key := range keys {
		if len(key.MasterKey) == 0 || len(key.MasterKey) > tcpAOMaxKeyLen {
			return fmt.Errorf("TCP-AO key with SendID %d must contain 1 through %d master-key bytes", key.SendID, tcpAOMaxKeyLen)
		}
		switch key.Algorithm {
		case TCPAOAlgorithmHMACSHA1_96, TCPAOAlgorithmAES128CMAC96:
		default:
			return fmt.Errorf("unsupported TCP-AO algorithm for SendID %d", key.SendID)
		}
	}
	return nil
}

func selectedTCPAOKey(config TCPAOConfig) (*TCPAOKey, error) {
	if config.PreferredSendID == nil {
		return nil, nil
	}
	for i := range config.Keys {
		if config.Keys[i].SendID == *config.PreferredSendID {
			return &config.Keys[i], nil
		}
	}
	return nil, fmt.Errorf("TCP-AO preferred SendID %d does not exist", *config.PreferredSendID)
}

func marshalTCPAOSockaddr(scope netip.Prefix) (tcpAOSockaddrStorage, error) {
	var storage tcpAOSockaddrStorage
	addr := scope.Addr()
	if addr.Is4() {
		wire := tcpAOSockaddrInet4Wire{
			Family:  tcpAOAFInet,
			Address: addr.As4(),
		}
		if err := encodeTCPAOSockaddr(&storage, &wire); err != nil {
			return storage, fmt.Errorf("failed to encode TCP-AO IPv4 address: %w", err)
		}
		return storage, nil
	}
	wire := tcpAOSockaddrInet6Wire{
		Family:  tcpAOAFInet6,
		Address: addr.As16(),
	}
	if err := encodeTCPAOSockaddr(&storage, &wire); err != nil {
		return storage, fmt.Errorf("failed to encode TCP-AO IPv6 address: %w", err)
	}
	return storage, nil
}

func tcpAOAlgorithmName(algorithm TCPAOAlgorithm) string {
	switch algorithm {
	case TCPAOAlgorithmHMACSHA1_96:
		return "hmac(sha1)"
	case TCPAOAlgorithmAES128CMAC96:
		return "cmac(aes128)"
	default:
		return ""
	}
}

func marshalTCPAOAdd(scope netip.Prefix, ifindex int32, key TCPAOKey, selected bool) (tcpAOAddCommand, error) {
	var command tcpAOAddCommand
	if err := validateTCPAOScope(scope, ifindex); err != nil {
		return command, err
	}
	if err := validateTCPAOAddKeys([]TCPAOKey{key}); err != nil {
		return command, err
	}

	address, err := marshalTCPAOSockaddr(scope)
	if err != nil {
		return command, err
	}
	wire := tcpAOAddWire{
		Address:        address,
		InterfaceIndex: ifindex,
		PrefixLength:   uint8(scope.Bits()),
		SendID:         key.SendID,
		ReceiveID:      key.ReceiveID,
		MACLength:      tcpAOMACLength,
		KeyLength:      uint8(len(key.MasterKey)),
	}
	copy(wire.Algorithm[:], tcpAOAlgorithmName(key.Algorithm))
	if selected {
		wire.Flags = tcpAOFlagSetCurrent | tcpAOFlagSetRNext
	}
	if ifindex != 0 {
		wire.KeyFlags |= tcpAOKeyFlagIfindex
	}
	if key.ExcludeTCPOptions {
		wire.KeyFlags |= tcpAOKeyFlagExcludeOpt
	}
	copy(wire.Key[:], key.MasterKey)
	defer clear(wire.Key[:])
	if err := encodeTCPAOWire(command[:], &wire); err != nil {
		clear(command[:])
		return command, err
	}
	return command, nil
}

func marshalTCPAODel(scope netip.Prefix, ifindex int32, key TCPAOKey) (tcpAODelCommand, error) {
	var command tcpAODelCommand
	if err := validateTCPAOScope(scope, ifindex); err != nil {
		return command, err
	}

	address, err := marshalTCPAOSockaddr(scope)
	if err != nil {
		return command, err
	}
	wire := tcpAODelWire{
		Address:        address,
		InterfaceIndex: ifindex,
		PrefixLength:   uint8(scope.Bits()),
		SendID:         key.SendID,
		ReceiveID:      key.ReceiveID,
	}
	// TCP_AO_DEL_KEY accepts TCP_AO_KEYF_IFINDEX, but not
	// TCP_AO_KEYF_EXCLUDE_OPT.
	if ifindex != 0 {
		wire.KeyFlags = tcpAOKeyFlagIfindex
	}
	if err := encodeTCPAOWire(command[:], &wire); err != nil {
		return command, err
	}
	return command, nil
}

func marshalTCPAOInfo(config TCPAOConfig) (tcpAOInfoCommand, error) {
	var command tcpAOInfoCommand
	if err := validateTCPAOKeyIDs(config.Keys); err != nil {
		return command, err
	}
	selected, err := selectedTCPAOKey(config)
	if err != nil {
		return command, err
	}
	if selected == nil {
		return command, fmt.Errorf("TCP-AO key selection requires a preferred SendID")
	}

	wire := tcpAOInfoWire{
		Flags:      tcpAOFlagSetCurrent | tcpAOFlagSetRNext,
		CurrentKey: selected.SendID,
		RNextKey:   selected.ReceiveID,
	}
	if err := encodeTCPAOWire(command[:], &wire); err != nil {
		return command, err
	}
	return command, nil
}

func addTCPAOKeys(setSockopt tcpAOSetSockoptFunc, peer netip.Prefix, ifindex int32, config TCPAOConfig) error {
	if err := validateTCPAOScope(peer, ifindex); err != nil {
		return err
	}
	if err := validateTCPAOAddKeys(config.Keys); err != nil {
		return err
	}
	selected, err := selectedTCPAOKey(config)
	if err != nil {
		return err
	}

	// Install the selected key last. If an earlier add fails, rollback never
	// has to delete a key already referenced by CurrentKey or RNextKey.
	installOrder := config.Keys
	if selected != nil {
		installOrder = make([]TCPAOKey, 0, len(config.Keys))
		for _, key := range config.Keys {
			if key.SendID != selected.SendID {
				installOrder = append(installOrder, key)
			}
		}
		installOrder = append(installOrder, *selected)
	}

	installed := make([]TCPAOKey, 0, len(installOrder))
	for _, key := range installOrder {
		command, err := marshalTCPAOAdd(peer, ifindex, key, selected != nil && selected.SendID == key.SendID)
		if err != nil {
			return err
		}
		err = setSockopt(tcpAOAddKey, command[:])
		clear(command[:])
		if err == nil {
			installed = append(installed, key)
			continue
		}

		addErr := fmt.Errorf("failed to add TCP-AO key SendID %d ReceiveID %d: %w", key.SendID, key.ReceiveID, err)
		var rollbackErr error
		for i := len(installed) - 1; i >= 0; i-- {
			installedKey := installed[i]
			deleteCommand, marshalErr := marshalTCPAODel(peer, ifindex, installedKey)
			if marshalErr != nil {
				rollbackErr = errors.Join(rollbackErr, marshalErr)
				continue
			}
			if deleteErr := setSockopt(tcpAODelKey, deleteCommand[:]); deleteErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("SendID %d ReceiveID %d: %w", installedKey.SendID, installedKey.ReceiveID, deleteErr))
			}
		}
		if rollbackErr != nil {
			return errors.Join(addErr, fmt.Errorf("failed to roll back TCP-AO keys: %w", rollbackErr))
		}
		return addErr
	}
	return nil
}

func deleteTCPAOKeys(setSockopt tcpAOSetSockoptFunc, peer netip.Prefix, ifindex int32, config TCPAOConfig) error {
	if err := validateTCPAOScope(peer, ifindex); err != nil {
		return err
	}
	// Deletion itself only needs the key identities, but keeping the operation
	// transactional requires the complete key definitions in case an earlier
	// deletion has to be rolled back.
	if err := validateTCPAOAddKeys(config.Keys); err != nil {
		return err
	}
	deleted := make([]TCPAOKey, 0, len(config.Keys))
	for _, key := range config.Keys {
		command, err := marshalTCPAODel(peer, ifindex, key)
		if err != nil {
			return err
		}
		err = setSockopt(tcpAODelKey, command[:])
		if err == nil {
			deleted = append(deleted, key)
			continue
		}

		deleteErr := fmt.Errorf("failed to delete TCP-AO key SendID %d ReceiveID %d: %w", key.SendID, key.ReceiveID, err)
		var rollbackErr error
		for i := len(deleted) - 1; i >= 0; i-- {
			deletedKey := deleted[i]
			addCommand, marshalErr := marshalTCPAOAdd(peer, ifindex, deletedKey, false)
			if marshalErr != nil {
				rollbackErr = errors.Join(rollbackErr, marshalErr)
				continue
			}
			addErr := setSockopt(tcpAOAddKey, addCommand[:])
			clear(addCommand[:])
			if addErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("SendID %d ReceiveID %d: %w", deletedKey.SendID, deletedKey.ReceiveID, addErr))
			}
		}
		if rollbackErr != nil {
			return errors.Join(deleteErr, fmt.Errorf("failed to roll back deleted TCP-AO keys: %w", rollbackErr))
		}
		return deleteErr
	}
	return nil
}

func setTCPAOKeySelection(setSockopt tcpAOSetSockoptFunc, config TCPAOConfig) error {
	command, err := marshalTCPAOInfo(config)
	if err != nil {
		return err
	}
	if err := setSockopt(tcpAOInfo, command[:]); err != nil {
		return fmt.Errorf("failed to select TCP-AO key SendID %d: %w", *config.PreferredSendID, err)
	}
	return nil
}
