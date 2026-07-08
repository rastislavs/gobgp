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

//go:build linux && (amd64 || arm64)

package netutils

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// TestTCPAOLiveLoopback is opt-in because it requires Linux 6.7 or later with
// CONFIG_TCP_AO enabled. It is exercised by the Lima validation workflow.
func TestTCPAOLiveLoopback(t *testing.T) {
	if os.Getenv("GOBGP_TCP_AO_LIVE_TEST") != "1" {
		t.Skip("set GOBGP_TCP_AO_LIVE_TEST=1 on a TCP-AO-enabled Linux kernel")
	}
	for _, test := range []struct {
		name      string
		algorithm TCPAOAlgorithm
		network   string
		address   string
		prefix    string
	}{
		{name: "HMAC-SHA-1-96/IPv4", algorithm: TCPAOAlgorithmHMACSHA1_96, network: "tcp4", address: "127.0.0.1", prefix: "127.0.0.1/32"},
		{name: "AES-128-CMAC-96/IPv4", algorithm: TCPAOAlgorithmAES128CMAC96, network: "tcp4", address: "127.0.0.1", prefix: "127.0.0.1/32"},
		{name: "HMAC-SHA-1-96/IPv6", algorithm: TCPAOAlgorithmHMACSHA1_96, network: "tcp6", address: "::1", prefix: "::1/128"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runTCPAOLiveLoopback(t, test.algorithm, test.network, test.address, test.prefix)
		})
	}
}

func runTCPAOLiveLoopback(t *testing.T, algorithm TCPAOAlgorithm, network, address, prefix string) {
	peer := netip.MustParsePrefix(prefix)
	oldSecret := []byte("gobgp-tcp-ao-old-key")
	secret := []byte("gobgp-tcp-ao-preferred-key")
	clientPreferred := uint8(10)
	serverPreferred := uint8(20)
	clientConfig := TCPAOConfig{
		Keys: []TCPAOKey{
			{
				SendID:    9,
				ReceiveID: 19,
				Algorithm: algorithm,
				MasterKey: oldSecret,
			},
			{
				SendID:    clientPreferred,
				ReceiveID: serverPreferred,
				Algorithm: algorithm,
				MasterKey: secret,
			},
		},
		PreferredSendID: &clientPreferred,
	}
	serverConfig := TCPAOConfig{
		Keys: []TCPAOKey{
			{
				SendID:    19,
				ReceiveID: 9,
				Algorithm: algorithm,
				MasterKey: oldSecret,
			},
			{
				SendID:    serverPreferred,
				ReceiveID: clientPreferred,
				Algorithm: algorithm,
				MasterKey: secret,
			},
		},
		PreferredSendID: &serverPreferred,
	}

	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		listenerConfig := serverConfig
		listenerConfig.PreferredSendID = nil
		return AddTCPAOKeysSockopt(raw, peer, 0, listenerConfig)
	}}
	listenConfig.SetMultipathTCP(false)
	listener, err := listenConfig.Listen(context.Background(), network, net.JoinHostPort(address, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	dialer := net.Dialer{
		Timeout: time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			return AddTCPAOKeysSockopt(raw, peer, 0, clientConfig)
		},
	}
	dialer.SetMultipathTCP(false)
	client, err := dialer.DialContext(context.Background(), network, listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the TCP-AO connection")
	}
	t.Cleanup(func() { _ = server.Close() })

	raw, err := server.(syscall.Conn).SyscallConn()
	require.NoError(t, err)
	require.NoError(t, SetTCPAOKeySelectionSockopt(raw, serverConfig))
	clientCurrent, clientRNext := getTCPAOSelection(t, client)
	require.Equal(t, clientPreferred, clientCurrent)
	require.Equal(t, serverPreferred, clientRNext)
	serverCurrent, serverRNext := getTCPAOSelection(t, server)
	require.Equal(t, serverPreferred, serverCurrent)
	require.Equal(t, clientPreferred, serverRNext)

	payload := []byte("tcp-ao-ok")
	require.NoError(t, client.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, server.SetDeadline(time.Now().Add(time.Second)))
	_, err = client.Write(payload)
	require.NoError(t, err)
	received := make([]byte, len(payload))
	_, err = io.ReadFull(server, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)

	_, err = server.Write(payload)
	require.NoError(t, err)
	_, err = io.ReadFull(client, received)
	require.NoError(t, err)
	require.Equal(t, payload, received)
}

func getTCPAOSelection(t *testing.T, conn net.Conn) (uint8, uint8) {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	require.NoError(t, err)

	var command tcpAOInfoCommand
	length := uint32(len(command))
	var syscallErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(tcpAOInfo),
			uintptr(unsafe.Pointer(&command[0])),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
		if errno != 0 {
			syscallErr = errno
		}
	}))
	require.NoError(t, syscallErr)
	require.Equal(t, uint32(tcpAOInfoSize), length)
	info := decodeTCPAOWire[tcpAOInfoWire](t, command[:])
	return info.CurrentKey, info.RNextKey
}

func TestTCPAOLiveWrongKeyRejected(t *testing.T) {
	if os.Getenv("GOBGP_TCP_AO_LIVE_TEST") != "1" {
		t.Skip("set GOBGP_TCP_AO_LIVE_TEST=1 on a TCP-AO-enabled Linux kernel")
	}

	peer := netip.MustParsePrefix("127.0.0.1/32")
	serverKey := TCPAOKey{
		SendID:    20,
		ReceiveID: 10,
		Algorithm: TCPAOAlgorithmHMACSHA1_96,
		MasterKey: []byte("correct-key"),
	}
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return AddTCPAOKeysSockopt(raw, peer, 0, TCPAOConfig{Keys: []TCPAOKey{serverKey}})
	}}
	listenConfig.SetMultipathTCP(false)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	preferred := uint8(10)
	clientKey := TCPAOKey{
		SendID:    preferred,
		ReceiveID: 20,
		Algorithm: TCPAOAlgorithmHMACSHA1_96,
		MasterKey: []byte("wrong-key"),
	}
	controlResult := make(chan error, 1)
	dialer := net.Dialer{
		Timeout: 500 * time.Millisecond,
		Control: func(_, _ string, raw syscall.RawConn) error {
			err := AddTCPAOKeysSockopt(raw, peer, 0, TCPAOConfig{
				Keys:            []TCPAOKey{clientKey},
				PreferredSendID: &preferred,
			})
			controlResult <- err
			return err
		},
	}
	dialer.SetMultipathTCP(false)
	conn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	select {
	case err := <-controlResult:
		require.NoError(t, err, "client TCP-AO socket setup must succeed before testing peer rejection")
	default:
		t.Fatal("dial did not invoke TCP-AO socket setup")
	}
	require.Error(t, err, "a peer with the wrong TCP-AO master key must not connect")
	netErr, ok := err.(net.Error)
	require.True(t, ok && netErr.Timeout(), "wrong-key handshake must time out, got %v", err)
}

func TestTCPAOLiveUnsignedPeerRejected(t *testing.T) {
	if os.Getenv("GOBGP_TCP_AO_LIVE_TEST") != "1" {
		t.Skip("set GOBGP_TCP_AO_LIVE_TEST=1 on a TCP-AO-enabled Linux kernel")
	}

	peer := netip.MustParsePrefix("127.0.0.1/32")
	serverKey := TCPAOKey{
		SendID:    20,
		ReceiveID: 10,
		Algorithm: TCPAOAlgorithmHMACSHA1_96,
		MasterKey: []byte("unsigned-rejection-key"),
	}
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		return AddTCPAOKeysSockopt(raw, peer, 0, TCPAOConfig{Keys: []TCPAOKey{serverKey}})
	}}
	listenConfig.SetMultipathTCP(false)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	dialer.SetMultipathTCP(false)
	conn, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	require.Error(t, err, "an unsigned peer must not connect to a TCP-AO-protected scope")
	netErr, ok := err.(net.Error)
	require.True(t, ok && netErr.Timeout(), "unsigned handshake must time out, got %v", err)
}
