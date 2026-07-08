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
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
)

func (c *tcpAoSocketConfig) netutilsConfig(withSelection bool) (netutils.TCPAOConfig, error) {
	if c == nil || c.keychain == nil {
		return netutils.TCPAOConfig{}, fmt.Errorf("missing TCP-AO socket configuration")
	}
	result := netutils.TCPAOConfig{Keys: make([]netutils.TCPAOKey, 0, len(c.keychain.keys))}
	for _, key := range c.keychain.keys {
		var algorithm netutils.TCPAOAlgorithm
		switch key.algorithm {
		case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96:
			algorithm = netutils.TCPAOAlgorithmHMACSHA1_96
		case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
			algorithm = netutils.TCPAOAlgorithmAES128CMAC96
		default:
			return netutils.TCPAOConfig{}, fmt.Errorf("unsupported TCP-AO algorithm %s", key.algorithm)
		}
		result.Keys = append(result.Keys, netutils.TCPAOKey{
			SendID:            key.sendID,
			ReceiveID:         key.receiveID,
			Algorithm:         algorithm,
			MasterKey:         key.masterKey,
			ExcludeTCPOptions: key.excludeTCPOptions,
		})
	}
	if withSelection {
		preferred := c.preferredSendID
		result.PreferredSendID = &preferred
	}
	return result, nil
}

func tcpAoExactPeerPrefix(addr netip.Addr) (netip.Prefix, error) {
	if !addr.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid TCP-AO peer address")
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("TCP-AO link-local peers are not supported by the MVP")
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

func tcpAoSyscallConn(conn net.Conn) (syscall.RawConn, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("TCP connection does not expose a syscall connection")
	}
	return syscallConn.SyscallConn()
}

func addTcpAoListenerKeys(listener *net.TCPListener, peer netip.Prefix, config *tcpAoSocketConfig) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return err
	}
	keys, err := config.netutilsConfig(false)
	if err != nil {
		return err
	}
	return netutils.AddTCPAOKeysSockopt(raw, peer, 0, keys)
}

func deleteTcpAoListenerKeys(listener *net.TCPListener, peer netip.Prefix, config *tcpAoSocketConfig) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return err
	}
	keys, err := config.netutilsConfig(false)
	if err != nil {
		return err
	}
	return netutils.DeleteTCPAOKeysSockopt(raw, peer, 0, keys)
}

func setTcpAoConnectionSelection(conn net.Conn, config *tcpAoSocketConfig) error {
	raw, err := tcpAoSyscallConn(conn)
	if err != nil {
		return err
	}
	keys, err := config.netutilsConfig(true)
	if err != nil {
		return err
	}
	return netutils.SetTCPAOKeySelectionSockopt(raw, keys)
}

func addTcpAoDialerKeys(raw syscall.RawConn, peer netip.Prefix, config *tcpAoSocketConfig) error {
	keys, err := config.netutilsConfig(true)
	if err != nil {
		return err
	}
	return netutils.AddTCPAOKeysSockopt(raw, peer, 0, keys)
}
