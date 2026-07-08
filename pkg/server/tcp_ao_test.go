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
	"context"
	"net/netip"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func validTcpAoKeychain(name string) *api.TcpAoKeychain {
	return &api.TcpAoKeychain{
		Name: name,
		Keys: []*api.TcpAoKey{{
			SendId:            1,
			ReceiveId:         2,
			Algorithm:         api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			MasterKey:         []byte("secret"),
			ExcludeTcpOptions: true,
		}},
	}
}

func tcpAoUint32(value uint32) *uint32 {
	return &value
}

func TestNewTcpAoKeychainValidation(t *testing.T) {
	tooManyKeys := make([]*api.TcpAoKey, 257)
	for i := range tooManyKeys {
		tooManyKeys[i] = &api.TcpAoKey{
			SendId:    uint32(i),
			ReceiveId: uint32(i),
			Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			MasterKey: []byte{1},
		}
	}

	tests := []struct {
		name  string
		chain *api.TcpAoKeychain
	}{
		{name: "nil keychain"},
		{name: "empty name", chain: validTcpAoKeychain("")},
		{name: "no keys", chain: &api.TcpAoKeychain{Name: "chain"}},
		{name: "too many keys", chain: &api.TcpAoKeychain{Name: "chain", Keys: tooManyKeys}},
		{name: "nil key", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{nil}}},
		{name: "send ID overflow", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{SendId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}}},
		{name: "receive ID overflow", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{ReceiveId: 256, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}}}}},
		{name: "duplicate send ID", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
			{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
			{SendId: 1, ReceiveId: 2, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
		}}},
		{name: "duplicate receive ID", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{
			{SendId: 1, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{1}},
			{SendId: 2, ReceiveId: 1, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte{2}},
		}}},
		{name: "unspecified algorithm", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{MasterKey: []byte{1}}}}},
		{name: "unknown algorithm", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm(99), MasterKey: []byte{1}}}}},
		{name: "empty master key", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96}}}},
		{name: "long master key", chain: &api.TcpAoKeychain{Name: "chain", Keys: []*api.TcpAoKey{{Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: make([]byte, tcpAoMaxMasterKeyBytes+1)}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTcpAoKeychain(tt.chain)
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestNewTcpAoKeychainAcceptsDirectionalIDsAndLimits(t *testing.T) {
	keys := make([]*api.TcpAoKey, 256)
	for i := range keys {
		keys[i] = &api.TcpAoKey{
			// Reverse the RecvID space. Cross-namespace equality and crossed
			// pairs are valid; uniqueness applies independently per field.
			SendId:    uint32(255 - i),
			ReceiveId: uint32(i),
			Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96,
			MasterKey: make([]byte, tcpAoMaxMasterKeyBytes),
		}
	}
	chain, err := newTcpAoKeychain(&api.TcpAoKeychain{Name: "all-ids", Keys: keys})
	require.NoError(t, err)
	require.Len(t, chain.keys, 256)
	for i, key := range chain.keys {
		assert.Equal(t, uint8(i), key.sendID)
		assert.Equal(t, uint8(255-i), key.receiveID)
	}
}

func TestTcpAoKeychainCRUDAndRedaction(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})

	requestChain := &api.TcpAoKeychain{
		Name: "z-chain",
		Keys: []*api.TcpAoKey{
			{SendId: 9, ReceiveId: 19, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, MasterKey: []byte("second")},
			{SendId: 1, ReceiveId: 11, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("first"), ExcludeTcpOptions: true},
		},
	}
	response, err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: requestChain})
	require.NoError(t, err)
	require.NotNil(t, response.Keychain)
	require.Len(t, response.Keychain.Keys, 2)
	assert.Equal(t, uint32(1), response.Keychain.Keys[0].SendId)
	assert.Equal(t, uint32(9), response.Keychain.Keys[1].SendId)
	assert.Empty(t, response.Keychain.Keys[0].MasterKey)
	assert.Empty(t, response.Keychain.Keys[1].MasterKey)

	// Neither the request nor a retained lookup may alias the registry.
	requestChain.Keys[0].MasterKey[0] = 'X'
	stored, ok := s.lookupTcpAoKeychain("z-chain")
	require.True(t, ok)
	assert.Equal(t, []byte("first"), stored.keys[0].masterKey)
	assert.Equal(t, []byte("second"), stored.keys[1].masterKey)
	stored.keys[0].masterKey[0] = 'X'
	storedAgain, ok := s.lookupTcpAoKeychain("z-chain")
	require.True(t, ok)
	assert.Equal(t, []byte("first"), storedAgain.keys[0].masterKey)

	_, err = s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: validTcpAoKeychain("a-chain")})
	require.NoError(t, err)
	_, err = s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: validTcpAoKeychain("z-chain")})
	require.Error(t, err)
	assert.Equal(t, codes.AlreadyExists, status.Code(err))

	var listed []*api.TcpAoKeychain
	err = s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, func(chain *api.TcpAoKeychain) {
		listed = append(listed, chain)
	})
	require.NoError(t, err)
	require.Len(t, listed, 2)
	assert.Equal(t, []string{"a-chain", "z-chain"}, []string{listed[0].Name, listed[1].Name})
	for _, chain := range listed {
		for _, key := range chain.Keys {
			assert.Empty(t, key.MasterKey)
		}
	}

	listed = nil
	err = s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "z-chain"}, func(chain *api.TcpAoKeychain) {
		listed = append(listed, chain)
	})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "z-chain", listed[0].Name)

	err = s.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "missing"}, func(*api.TcpAoKeychain) {})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "a-chain"}))
	_, ok = s.lookupTcpAoKeychain("a-chain")
	assert.False(t, ok)
	err = s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "a-chain"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteTcpAoKeychainRejectsReference(t *testing.T) {
	chain, err := newTcpAoKeychain(validTcpAoKeychain("referenced"))
	require.NoError(t, err)
	registry := map[string]*tcpAoKeychain{"referenced": chain}

	err = deleteTcpAoKeychain(registry, "referenced", true)
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	stored, ok := registry["referenced"]
	require.True(t, ok)
	assert.Equal(t, []byte("secret"), stored.keys[0].masterKey)

	require.NoError(t, deleteTcpAoKeychain(registry, "referenced", false))
	assert.Empty(t, registry)
	assert.Nil(t, stored.keys[0].masterKey)
}

func TestTcpAoKeychainsClearedOnStop(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	_, err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: validTcpAoKeychain("chain")})
	require.NoError(t, err)
	stored := s.tcpAoChains["chain"]
	require.NotNil(t, stored)

	require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	assert.Empty(t, s.tcpAoChains)
	assert.Nil(t, stored.keys[0].masterKey)
}

func TestTcpAoKeyAttachmentValidation(t *testing.T) {
	s := NewBgpServer()
	one, err := newTcpAoKeychain(validTcpAoKeychain("one"))
	require.NoError(t, err)
	s.tcpAoChains[one.name] = one

	multiple, err := newTcpAoKeychain(&api.TcpAoKeychain{
		Name: "multiple",
		Keys: []*api.TcpAoKey{
			{SendId: 0, ReceiveId: 10, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("zero")},
			{SendId: 1, ReceiveId: 11, Algorithm: api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, MasterKey: []byte("one")},
		},
	})
	require.NoError(t, err)
	s.tcpAoChains[multiple.name] = multiple

	implicit, err := s.newTcpAoAttachment(&api.TcpAoKeyAttachment{Keychain: "one"})
	require.NoError(t, err)
	assert.Equal(t, uint8(1), implicit.preferredSendID)
	assert.False(t, implicit.preferredSendIDExplicit)
	assert.Nil(t, implicit.api().PreferredSendId)

	explicitZero, err := s.newTcpAoAttachment(&api.TcpAoKeyAttachment{
		Keychain:        "multiple",
		PreferredSendId: tcpAoUint32(0),
	})
	require.NoError(t, err)
	assert.Equal(t, uint8(0), explicitZero.preferredSendID)
	assert.True(t, explicitZero.preferredSendIDExplicit)
	require.NotNil(t, explicitZero.api().PreferredSendId)
	assert.Equal(t, uint32(0), *explicitZero.api().PreferredSendId)

	_, err = s.newTcpAoAttachment(&api.TcpAoKeyAttachment{Keychain: "multiple"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.newTcpAoAttachment(&api.TcpAoKeyAttachment{Keychain: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.newTcpAoAttachment(&api.TcpAoKeyAttachment{Keychain: "one", PreferredSendId: tcpAoUint32(256)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.newTcpAoAttachment(&api.TcpAoKeyAttachment{Keychain: "one", PreferredSendId: tcpAoUint32(9)})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.newTcpAoAttachment(&api.TcpAoKeyAttachment{PreferredSendId: tcpAoUint32(0)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	reset, err := s.newTcpAoAttachment(&api.TcpAoKeyAttachment{})
	require.NoError(t, err)
	assert.Nil(t, reset)
}

func TestUpdatePeerGroupRejectsMD5ConflictWithExplicitTcpAoMember(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		if s.isServing.Load() {
			require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		}
	})
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn:        65000,
		RouterId:   "192.0.2.254",
		ListenPort: -1,
	}}))
	_, err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{
		Keychain: validTcpAoKeychain("peer-chain"),
	})
	require.NoError(t, err)
	require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{PeerGroupName: "plain-group", PeerAsn: 65001},
	}}))
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: "192.0.2.10",
			PeerGroup:       "plain-group",
			TcpAo:           &api.TcpAoKeyAttachment{Keychain: "peer-chain"},
		},
		Transport: &api.Transport{PassiveMode: true},
	}}))

	_, err = s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "plain-group",
			PeerAsn:       65001,
			AuthPassword:  "md5-secret",
		},
	}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, s.peerGroupMap["plain-group"].Conf.Config.AuthPassword)
	peer := s.neighborMap[netip.MustParseAddr("192.0.2.10")]
	require.NotNil(t, peer)
	require.NotNil(t, peer.fsm.tcpAoConfig)
	assert.Equal(t, "peer-chain", peer.fsm.tcpAoConfig.keychain.name)
}

func TestTcpAoPeerGroupInheritanceAndOverride(t *testing.T) {
	s := NewBgpServer()
	go s.Serve()
	t.Cleanup(func() {
		if s.isServing.Load() {
			require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
		}
	})
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{
		Asn:        65000,
		RouterId:   "192.0.2.254",
		ListenPort: -1,
	}}))

	for _, name := range []string{"group-chain", "peer-chain", "replacement-chain"} {
		_, err := s.AddTcpAoKeychain(context.Background(), &api.AddTcpAoKeychainRequest{Keychain: validTcpAoKeychain(name)})
		require.NoError(t, err)
	}
	addGroup := func(name, chain string) {
		t.Helper()
		require.NoError(t, s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
			Conf: &api.PeerGroupConf{
				PeerGroupName: name,
				PeerAsn:       65001,
				TcpAo:         &api.TcpAoKeyAttachment{Keychain: chain},
			},
		}}))
	}
	addGroup("ao-group", "group-chain")
	addGroup("same-ao-group", "group-chain")
	addGroup("different-ao-group", "peer-chain")
	err := s.AddPeerGroup(context.Background(), &api.AddPeerGroupRequest{PeerGroup: &api.PeerGroup{
		Conf: &api.PeerGroupConf{
			PeerGroupName: "invalid-md5-ao",
			PeerAsn:       65002,
			AuthPassword:  "md5-secret",
			TcpAo:         &api.TcpAoKeyAttachment{Keychain: "group-chain"},
		},
	}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	err = s.AddDynamicNeighbor(context.Background(), &api.AddDynamicNeighborRequest{DynamicNeighbor: &api.DynamicNeighbor{
		Prefix:    "198.51.100.0/24",
		PeerGroup: "ao-group",
	}})
	assert.Equal(t, codes.Unimplemented, status.Code(err))

	peerRequest := func(group string, tcpAo *api.TcpAoKeyAttachment) *api.Peer {
		return &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: "192.0.2.1",
				PeerGroup:       group,
				TcpAo:           tcpAo,
			},
			Transport: &api.Transport{PassiveMode: true},
		}
	}
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerRequest("ao-group", nil)}))

	peer := s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer)
	assert.Nil(t, peer.tcpAoAttachment)
	require.NotNil(t, peer.fsm.tcpAoConfig)
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)
	assert.True(t, s.tcpAoKeychainReferenced("group-chain"))
	err = s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "group-chain"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	var listed []*api.Peer
	require.NoError(t, s.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.1"}, func(peer *api.Peer) {
		listed = append(listed, peer)
	}))
	require.Len(t, listed, 1)
	assert.Nil(t, listed[0].Conf.TcpAo, "an inherited attachment must not be returned as an explicit peer override")

	// UpdatePeer cannot migrate a live peer to different effective key
	// material. Operators must delete and recreate the peer instead.
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("ao-group", &api.TcpAoKeyAttachment{Keychain: "peer-chain"})})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Nil(t, peer.tcpAoAttachment)
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)

	// A representational change to an explicit attachment with the same
	// effective keychain and selected SendID is a no-op and may proceed.
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("ao-group", &api.TcpAoKeyAttachment{
		Keychain:        "group-chain",
		PreferredSendId: tcpAoUint32(1),
	})})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer.tcpAoAttachment)
	assert.Equal(t, "group-chain", peer.tcpAoAttachment.keychain)
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)

	// Omitting tcp_ao preserves the explicit representation, while a
	// present-empty value may restore identical inherited configuration.
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("ao-group", nil)})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	require.NotNil(t, peer.tcpAoAttachment)
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("ao-group", &api.TcpAoKeyAttachment{})})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Nil(t, peer.tcpAoAttachment)
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)

	// Peer-group membership may change only when the resulting effective
	// attachment remains identical.
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("same-ao-group", nil)})
	require.NoError(t, err)
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, "same-ao-group", peer.fsm.pConf.ReadOnly().Config.PeerGroup)
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)
	_, err = s.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: peerRequest("different-ao-group", nil)})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, "same-ao-group", peer.fsm.pConf.ReadOnly().Config.PeerGroup)

	groupRequest := func(tcpAo *api.TcpAoKeyAttachment, authPassword string) *api.PeerGroup {
		return &api.PeerGroup{Conf: &api.PeerGroupConf{
			PeerGroupName: "same-ao-group",
			PeerAsn:       65001,
			AuthPassword:  authPassword,
			TcpAo:         tcpAo,
		}}
	}
	// An attachment change is rejected while static members exist.
	_, err = s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
		PeerGroup: groupRequest(&api.TcpAoKeyAttachment{Keychain: "replacement-chain"}, ""),
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, "group-chain", peer.fsm.tcpAoConfig.keychain.name)
	assert.Equal(t, "group-chain", s.peerGroupMap["same-ao-group"].tcpAoAttachment.keychain)

	// Semantically identical attachment representations and omission remain
	// valid while the group has members.
	_, err = s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
		PeerGroup: groupRequest(&api.TcpAoKeyAttachment{Keychain: "group-chain", PreferredSendId: tcpAoUint32(1)}, ""),
	})
	require.NoError(t, err)
	_, err = s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{PeerGroup: groupRequest(nil, "")})
	require.NoError(t, err)
	assert.Equal(t, "group-chain", s.peerGroupMap["same-ao-group"].tcpAoAttachment.keychain)

	// Once the group is memberless, changing its attachment is allowed. A
	// newly created peer then receives the new immutable socket configuration.
	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "192.0.2.1"}))
	require.Empty(t, s.peerGroupMap["same-ao-group"].members)
	_, err = s.UpdatePeerGroup(context.Background(), &api.UpdatePeerGroupRequest{
		PeerGroup: groupRequest(&api.TcpAoKeyAttachment{Keychain: "replacement-chain"}, ""),
	})
	require.NoError(t, err)
	assert.Equal(t, "replacement-chain", s.peerGroupMap["same-ao-group"].tcpAoAttachment.keychain)
	require.NoError(t, s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peerRequest("same-ao-group", nil)}))
	peer = s.neighborMap[netip.MustParseAddr("192.0.2.1")]
	assert.Equal(t, "replacement-chain", peer.fsm.tcpAoConfig.keychain.name)

	require.NoError(t, s.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: "192.0.2.1"}))
	for _, name := range []string{"ao-group", "same-ao-group", "different-ao-group"} {
		require.NoError(t, s.DeletePeerGroup(context.Background(), &api.DeletePeerGroupRequest{Name: name}))
	}
	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "group-chain"}))
	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "peer-chain"}))
	require.NoError(t, s.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "replacement-chain"}))
}
