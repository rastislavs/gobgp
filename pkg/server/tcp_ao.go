// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tcpAoMaxMasterKeyBytes matches TCP_AO_MAXKEYLEN from Linux's include/uapi/linux/tcp.h.
const tcpAoMaxMasterKeyBytes = 80

type tcpAoKeychain struct {
	mu       sync.RWMutex // used to protect concurrent access of management operations and socket operations
	name     string
	keys     map[uint8]netutils.TCPAOKey
	revision uint64
}

type tcpAoKeychainStore struct {
	keychains map[string]*tcpAoKeychain
}

func newTcpAoKeychainStore() *tcpAoKeychainStore {
	return &tcpAoKeychainStore{keychains: make(map[string]*tcpAoKeychain)}
}

func (s *tcpAoKeychainStore) addKeychain(chain *tcpAoKeychain) {
	s.keychains[chain.name] = chain
}

func (s *tcpAoKeychainStore) getKeychain(name string) (*tcpAoKeychain, bool) {
	chain, ok := s.keychains[name]
	return chain, ok
}

func (s *tcpAoKeychainStore) getAllKeychains() []*tcpAoKeychain {
	return slices.Collect(maps.Values(s.keychains))
}

func (s *tcpAoKeychainStore) deleteKeychain(name string) bool {
	chain, ok := s.keychains[name]
	if !ok {
		return false
	}
	chain.clearKeys()
	delete(s.keychains, name)
	return true
}

func (s *tcpAoKeychainStore) clearAllKeychains() {
	for _, chain := range s.keychains {
		chain.clearKeys()
	}
	clear(s.keychains)
}

func newTcpAoKeychain(a *api.TcpAoKeychain) (*tcpAoKeychain, error) {
	keys, err := newTcpAoKeychainKeys(a.Name, a.Keys)
	if err != nil {
		return nil, err
	}
	keyMap := make(map[uint8]netutils.TCPAOKey, len(keys))
	for _, key := range keys {
		keyMap[key.SendID] = key
	}
	return &tcpAoKeychain{name: a.Name, keys: keyMap}, nil
}

func newTcpAoKeychainKeys(chainName string, keys []*api.TcpAoKey) ([]netutils.TCPAOKey, error) {
	if len(keys) == 0 || len(keys) > 256 {
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q must contain between 1 and 256 keys", chainName)
	}
	sendIDs := make(map[uint32]struct{}, len(keys))
	receiveIDs := make(map[uint32]struct{}, len(keys))
	for i, key := range keys {
		if key == nil {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q contains a nil key at index %d", chainName, i)
		}
		if key.SendId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has send ID %d outside 0..255", chainName, i, key.SendId)
		}
		if key.ReceiveId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has receive ID %d outside 0..255", chainName, i, key.ReceiveId)
		}
		if _, ok := sendIDs[key.SendId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate send ID %d", chainName, key.SendId)
		}
		if _, ok := receiveIDs[key.ReceiveId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate receive ID %d", chainName, key.ReceiveId)
		}
		switch key.Algorithm {
		case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96,
			api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96,
			api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128:
		default:
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has unsupported algorithm %s", chainName, i, key.Algorithm)
		}
		if len(key.MasterKey) == 0 || len(key.MasterKey) > tcpAoMaxMasterKeyBytes {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d master key must contain between 1 and %d bytes", chainName, i, tcpAoMaxMasterKeyBytes)
		}
		sendIDs[key.SendId] = struct{}{}
		receiveIDs[key.ReceiveId] = struct{}{}
	}

	result := make([]netutils.TCPAOKey, 0, len(keys))
	for _, apiKey := range keys {
		key := netutils.TCPAOKey{
			SendID:            uint8(apiKey.SendId),
			ReceiveID:         uint8(apiKey.ReceiveId),
			Algorithm:         netutils.TCPAOAlgorithm(apiKey.Algorithm),
			ExcludeTCPOptions: apiKey.ExcludeTcpOptions,
			MasterKey:         append([]byte{}, apiKey.MasterKey...),
		}
		result = append(result, key)
	}
	return result, nil
}

func (c *tcpAoKeychain) toAPIKeychain() *api.TcpAoKeychain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := &api.TcpAoKeychain{
		Name: c.name,
		Keys: make([]*api.TcpAoKey, 0, len(c.keys)),
	}
	sendIDs := make([]uint8, 0, len(c.keys))
	for sendID := range c.keys {
		sendIDs = append(sendIDs, sendID)
	}
	slices.Sort(sendIDs)
	for _, sendID := range sendIDs {
		key := c.keys[sendID]
		result.Keys = append(result.Keys, &api.TcpAoKey{
			SendId:            uint32(key.SendID),
			ReceiveId:         uint32(key.ReceiveID),
			Algorithm:         api.TcpAoAlgorithm(key.Algorithm),
			ExcludeTcpOptions: key.ExcludeTCPOptions,
			// MasterKey is intentionally omitted
		})
	}
	return result
}

func (c *tcpAoKeychain) hasSendID(sendID uint8) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.keys[sendID]
	return ok
}

func (c *tcpAoKeychain) getKey(sendID, receiveID uint8) (netutils.TCPAOKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, ok := c.keys[sendID]
	if !ok || key.ReceiveID != receiveID {
		return netutils.TCPAOKey{}, false
	}
	return key, true
}

func (c *tcpAoKeychain) updateKeys(added, deleted []netutils.TCPAOKey) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, deletedKey := range deleted {
		key, ok := c.keys[deletedKey.SendID]
		if !ok || key.ReceiveID != deletedKey.ReceiveID {
			continue
		}
		clear(key.MasterKey)
		delete(c.keys, deletedKey.SendID)
	}
	for _, key := range added {
		c.keys[key.SendID] = key
	}
	if len(added) != 0 || len(deleted) != 0 {
		c.revision++
	}
}

func (c *tcpAoKeychain) clearKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, key := range c.keys {
		clear(key.MasterKey)
	}
	clear(c.keys)
}

func (c *tcpAoKeychain) socketKeys(preferredSendID uint8) (*tcpAoSocketKeys, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.keys) == 0 {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not contain any key", c.name)
	}
	if _, ok := c.keys[preferredSendID]; !ok {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q has no key with send ID %d", c.name, preferredSendID)
	}
	keys := slices.Collect(maps.Values(c.keys))
	socketKeys := newTcpAoSocketKeys(keys, &preferredSendID)
	socketKeys.keychainRevision = c.revision
	return socketKeys, nil
}

func (c *tcpAoKeychain) getRevision() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.revision
}

// tcpAoSocketKeys is a short-lived TCP-AO key snapshot used for socket operations.
// Its master keys are deep-copied while the keychain is locked, allowing the
// potentially blocking socket calls to run without holding keychain lock.
// Callers should clear() this snapshot after use.
// The preferred send ID is optional: listeners and key deletion only need the keys;
// active and accepted connections also select a send ID.
type tcpAoSocketKeys struct {
	keys             []netutils.TCPAOKey
	preferredSendID  *uint8
	keychainRevision uint64
}

func newTcpAoSocketKeys(keys []netutils.TCPAOKey, preferredSendID *uint8) *tcpAoSocketKeys {
	socketKeys := &tcpAoSocketKeys{keys: make([]netutils.TCPAOKey, 0, len(keys))}
	for _, key := range keys {
		key.MasterKey = append([]byte{}, key.MasterKey...)
		socketKeys.keys = append(socketKeys.keys, key)
	}
	if preferredSendID != nil {
		preferred := *preferredSendID
		socketKeys.preferredSendID = &preferred
	}
	return socketKeys
}

func (k *tcpAoSocketKeys) clear() {
	if k == nil {
		return
	}
	for i := range k.keys {
		clear(k.keys[i].MasterKey)
		k.keys[i].MasterKey = nil
	}
	k.keys = nil
	k.preferredSendID = nil
}

type tcpAoConnection struct {
	net.Conn
	keyBinding       *tcpAoKeyBinding
	keychainRevision uint64
}

func (c *tcpAoConnection) SyscallConn() (syscall.RawConn, error) {
	syscallConn, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("TCP connection does not expose a syscall connection")
	}
	return syscallConn.SyscallConn()
}

func tcpAoConnectionCurrent(conn net.Conn, current *tcpAoKeyBinding) bool {
	tcpAoConn, ok := conn.(*tcpAoConnection)
	if !ok {
		return true
	}
	if tcpAoConn.keyBinding != current {
		return false
	}
	return current == nil || tcpAoConn.keychainRevision == current.keychain.getRevision()
}

func tcpAoConnectionKeysMatch(conn net.Conn, socketKeys *tcpAoSocketKeys) (bool, error) {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return false, err
	}
	states, err := netutils.GetTCPAOKeyStateSockopt(raw)
	if err != nil {
		return false, err
	}
	if len(states) != len(socketKeys.keys) {
		return false, nil
	}
	keys := make(map[[2]uint8]struct{}, len(socketKeys.keys))
	for _, key := range socketKeys.keys {
		keys[[2]uint8{key.SendID, key.ReceiveID}] = struct{}{}
	}
	for _, state := range states {
		if _, ok := keys[[2]uint8{state.SendID, state.ReceiveID}]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (k *tcpAoSocketKeys) netutilsConfig(selectPreferred bool) (netutils.TCPAOConfig, error) {
	if k == nil {
		return netutils.TCPAOConfig{}, fmt.Errorf("missing TCP-AO socket keys")
	}
	result := netutils.TCPAOConfig{Keys: k.keys}
	if selectPreferred {
		if k.preferredSendID == nil {
			return netutils.TCPAOConfig{}, fmt.Errorf("missing TCP-AO preferred send ID")
		}
		preferred := *k.preferredSendID
		result.PreferredSendID = &preferred
	}
	return result, nil
}

func addTcpAoKeys(raw syscall.RawConn, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys, selectPreferred bool) error {
	peerPrefix, interfaceName, err := tcpAoPeerScope(peerAddr, interfaceName)
	if err != nil {
		return err
	}
	config, err := socketKeys.netutilsConfig(selectPreferred)
	if err != nil {
		return err
	}
	return netutils.AddTCPAOKeysSockopt(raw, peerPrefix, interfaceName, config)
}

func deleteTcpAoKeys(raw syscall.RawConn, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys) error {
	peerPrefix, interfaceName, err := tcpAoPeerScope(peerAddr, interfaceName)
	if err != nil {
		return err
	}
	config, err := socketKeys.netutilsConfig(false)
	if err != nil {
		return err
	}
	return netutils.DeleteTCPAOKeysSockopt(raw, peerPrefix, interfaceName, config)
}

func addTcpAoKeysToListeners(listeners []*net.TCPListener, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys) error {
	if _, _, err := tcpAoPeerScope(peerAddr, interfaceName); err != nil {
		return err
	}
	configured := make([]*net.TCPListener, 0, len(listeners))
	rollback := func(cause error) error {
		errs := []error{cause}
		for _, err := range deleteTcpAoKeysFromListeners(configured, peerAddr, interfaceName, socketKeys) {
			errs = append(errs, fmt.Errorf("failed to roll back TCP-AO listener configuration: %w", err))
		}
		return errors.Join(errs...)
	}
	for _, listener := range listeners {
		raw, err := listener.SyscallConn()
		if err != nil {
			return rollback(err)
		}
		// AddTCPAOKeysSockopt installs keys one at a time and can fail
		// after partially configuring the listener.
		configured = append(configured, listener)
		if err := addTcpAoKeys(raw, peerAddr, interfaceName, socketKeys, false); err != nil {
			return rollback(err)
		}
	}
	return nil
}

func deleteTcpAoKeysFromListeners(listeners []*net.TCPListener, peerAddr netip.Addr, interfaceName string, socketKeys *tcpAoSocketKeys) []error {
	var result []error
	for _, listener := range listeners {
		raw, err := listener.SyscallConn()
		if err == nil {
			err = deleteTcpAoKeys(raw, peerAddr, interfaceName, socketKeys)
		}
		if err != nil {
			result = append(result, err)
		}
	}
	return result
}

func setTcpAoConnectionPreferredKey(conn net.Conn, socketKeys *tcpAoSocketKeys) error {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return err
	}
	config, err := socketKeys.netutilsConfig(true)
	if err != nil {
		return err
	}
	return netutils.SetTCPAOKeySockopt(raw, config, true, true)
}

func setTcpAoConnectionRNext(conn net.Conn, socketKeys *tcpAoSocketKeys) error {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return err
	}
	config, err := socketKeys.netutilsConfig(true)
	if err != nil {
		return err
	}
	return netutils.SetTCPAOKeySockopt(raw, config, true, false)
}

func getTcpAoConnectionState(conn net.Conn) (*api.TcpAoPeerState, error) {
	raw, err := tcpAoRawConn(conn)
	if err != nil {
		return nil, err
	}
	keyStates, err := netutils.GetTCPAOKeyStateSockopt(raw)
	if err != nil {
		return nil, err
	}
	counters, err := netutils.GetTCPAOSocketCountersSockopt(raw)
	if err != nil {
		return nil, err
	}
	state := &api.TcpAoPeerState{
		Keys:               make([]*api.TcpAoKeyState, 0, len(keyStates)),
		PacketsKeyNotFound: counters.PacketsKeyNotFound,
		PacketsAoRequired:  counters.PacketsAORequired,
		PacketsDroppedIcmp: counters.PacketsDroppedICMP,
	}
	for _, key := range keyStates {
		state.Keys = append(state.Keys, &api.TcpAoKeyState{
			SendId:      uint32(key.SendID),
			ReceiveId:   uint32(key.ReceiveID),
			Current:     key.Current,
			ReceiveNext: key.ReceiveNext,
			PacketsGood: key.PacketsGood,
			PacketsBad:  key.PacketsBad,
		})
	}
	return state, nil
}

func tcpAoPeerScope(addr netip.Addr, interfaceName string) (netip.Prefix, string, error) {
	if !addr.IsValid() {
		return netip.Prefix{}, "", fmt.Errorf("invalid TCP-AO peer address")
	}
	zone := addr.Zone()
	if addr.IsLinkLocalUnicast() && zone == "" {
		return netip.Prefix{}, "", status.Error(codes.InvalidArgument, "TCP-AO link-local peer address requires an IPv6 zone")
	}
	if zone != "" && !addr.IsLinkLocalUnicast() {
		return netip.Prefix{}, "", status.Error(codes.InvalidArgument, "TCP-AO peer address may only contain an IPv6 zone when it is link-local")
	}
	addr = addr.WithZone("").Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	if interfaceName == "" {
		interfaceName = zone
	}
	return netip.PrefixFrom(addr, bits), interfaceName, nil
}

func tcpAoRawConn(conn net.Conn) (syscall.RawConn, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("TCP connection does not expose a syscall connection")
	}
	return syscallConn.SyscallConn()
}
