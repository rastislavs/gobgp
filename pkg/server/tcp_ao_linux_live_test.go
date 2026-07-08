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

package server

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/stretchr/testify/require"
)

// TestTCPAOGoBGPLiveSession is opt-in because it requires a TCP-AO-enabled
// Linux kernel. It validates listener installation, active dial setup,
// accepted-child selection, and the BGP FSM as one path.
func TestTCPAOGoBGPLiveSession(t *testing.T) {
	if os.Getenv("GOBGP_TCP_AO_LIVE_TEST") != "1" {
		t.Skip("set GOBGP_TCP_AO_LIVE_TEST=1 on a TCP-AO-enabled Linux kernel")
	}
	for _, test := range []struct {
		name      string
		port      int
		algorithm api.TcpAoAlgorithm
	}{
		{name: "HMAC-SHA-1-96", port: 21179, algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96},
		{name: "AES-128-CMAC-96", port: 21180, algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96},
	} {
		t.Run(test.name, func(t *testing.T) {
			runTCPAOGoBGPLiveSession(t, test.port, test.algorithm)
		})
	}
}

func runTCPAOGoBGPLiveSession(t *testing.T, bgpPort int, algorithm api.TcpAoAlgorithm) {
	t.Helper()
	ctx := context.Background()
	passive := NewBgpServer()
	active := NewBgpServer()
	go passive.Serve()
	go active.Serve()
	t.Cleanup(func() {
		if active.isServing.Load() {
			require.NoError(t, active.StopBgp(ctx, &api.StopBgpRequest{}))
		}
		if passive.isServing.Load() {
			require.NoError(t, passive.StopBgp(ctx, &api.StopBgpRequest{}))
		}
	})

	require.NoError(t, passive.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:             65000,
		RouterId:        "192.0.2.1",
		ListenPort:      int32(bgpPort),
		ListenAddresses: []string{"127.0.0.1"},
	}}))
	require.NoError(t, active.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:        65001,
		RouterId:   "192.0.2.2",
		ListenPort: -1,
	}}))
	require.Len(t, passive.listeners, 1)
	listener := passive.listeners[0]
	acceptCh := passive.acceptCh

	secret := []byte("gobgp-live-session-secret")
	addChain := func(server *BgpServer, name string, sendID, receiveID uint32, masterKey []byte) {
		_, err := server.AddTcpAoKeychain(ctx, &api.AddTcpAoKeychainRequest{Keychain: &api.TcpAoKeychain{
			Name: name,
			Keys: []*api.TcpAoKey{{
				SendId:    sendID,
				ReceiveId: receiveID,
				Algorithm: algorithm,
				MasterKey: masterKey,
			}},
		}})
		require.NoError(t, err)
	}
	addChain(passive, "passive-chain", 20, 10, secret)
	addChain(active, "active-chain", 10, 20, secret)

	passivePeer := func(chain string) *api.Peer {
		return &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: "127.0.0.2",
				PeerAsn:         65001,
				TcpAo:           &api.TcpAoKeyAttachment{Keychain: chain},
			},
			Transport: &api.Transport{
				PassiveMode:  true,
				LocalAddress: "127.0.0.1",
			},
		}
	}
	activePeer := func(chain string) *api.Peer {
		return &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: "127.0.0.1",
				PeerAsn:         65000,
				TcpAo:           &api.TcpAoKeyAttachment{Keychain: chain},
			},
			Transport: &api.Transport{
				RemotePort:   uint32(bgpPort),
				LocalAddress: "127.0.0.2",
			},
		}
	}

	require.NoError(t, passive.AddPeer(ctx, &api.AddPeerRequest{Peer: passivePeer("passive-chain")}))
	require.NoError(t, active.AddPeer(ctx, &api.AddPeerRequest{Peer: activePeer("active-chain")}))
	require.Same(t, listener, passive.listeners[0])
	require.Equal(t, acceptCh, passive.acceptCh)

	requireEstablished := func() {
		t.Helper()
		require.Eventually(t, func() bool {
			passivePeer := passive.neighborMap[netip.MustParseAddr("127.0.0.2")]
			activePeer := active.neighborMap[netip.MustParseAddr("127.0.0.1")]
			return passivePeer != nil && activePeer != nil &&
				passivePeer.State() == bgp.BGP_FSM_ESTABLISHED &&
				activePeer.State() == bgp.BGP_FSM_ESTABLISHED
		}, 10*time.Second, 50*time.Millisecond)
	}
	requireEstablished()

	// Replace both immutable chains through the supported disruptive flow.
	// Listener keys are updated in place, matching the TCP-MD5 lifecycle.
	replacementSecret := []byte("gobgp-live-replacement-secret")
	addChain(passive, "passive-replacement", 20, 10, replacementSecret)
	addChain(active, "active-replacement", 10, 20, replacementSecret)
	require.NoError(t, passive.DeletePeer(ctx, &api.DeletePeerRequest{Address: "127.0.0.2"}))
	require.NoError(t, active.DeletePeer(ctx, &api.DeletePeerRequest{Address: "127.0.0.1"}))
	require.NoError(t, passive.AddPeer(ctx, &api.AddPeerRequest{Peer: passivePeer("passive-replacement")}))
	require.NoError(t, active.AddPeer(ctx, &api.AddPeerRequest{Peer: activePeer("active-replacement")}))
	require.Same(t, listener, passive.listeners[0])
	require.Equal(t, acceptCh, passive.acceptCh)
	requireEstablished()

	require.NoError(t, passive.DeleteTcpAoKeychain(ctx, &api.DeleteTcpAoKeychainRequest{Name: "passive-chain"}))
	require.NoError(t, active.DeleteTcpAoKeychain(ctx, &api.DeleteTcpAoKeychainRequest{Name: "active-chain"}))
}
