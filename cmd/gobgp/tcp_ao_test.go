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

package main

import (
	"context"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type tcpAoCLIClient struct {
	api.GoBgpServiceClient
	addKeychain    *api.AddTcpAoKeychainRequest
	updateKeychain *api.UpdateTcpAoKeychainRequest
	deleteKeychain *api.DeleteTcpAoKeychainRequest
	addPeer        *api.AddPeerRequest
}

func (c *tcpAoCLIClient) AddTcpAoKeychain(_ context.Context, request *api.AddTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.AddTcpAoKeychainResponse, error) {
	c.addKeychain = request
	return &api.AddTcpAoKeychainResponse{}, nil
}

func (c *tcpAoCLIClient) UpdateTcpAoKeychain(_ context.Context, request *api.UpdateTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.UpdateTcpAoKeychainResponse, error) {
	c.updateKeychain = request
	return &api.UpdateTcpAoKeychainResponse{}, nil
}

func (c *tcpAoCLIClient) DeleteTcpAoKeychain(_ context.Context, request *api.DeleteTcpAoKeychainRequest, _ ...grpc.CallOption) (*api.DeleteTcpAoKeychainResponse, error) {
	c.deleteKeychain = request
	return &api.DeleteTcpAoKeychainResponse{}, nil
}

func (c *tcpAoCLIClient) AddPeer(_ context.Context, request *api.AddPeerRequest, _ ...grpc.CallOption) (*api.AddPeerResponse, error) {
	c.addPeer = request
	return &api.AddPeerResponse{}, nil
}

func useTcpAoCLIClient(t *testing.T) *tcpAoCLIClient {
	t.Helper()
	previousClient := client
	previousContext := ctx
	fake := &tcpAoCLIClient{}
	client = fake
	ctx = context.Background()
	t.Cleanup(func() {
		client = previousClient
		ctx = previousContext
	})
	return fake
}

func TestParseTcpAoKey(t *testing.T) {
	key, err := parseTcpAoKey("0,010,hmac-sha-1-96,c2VjcmV0,exclude-tcp-options")
	require.NoError(t, err)
	assert.Equal(t, uint32(0), key.SendId)
	assert.Equal(t, uint32(10), key.ReceiveId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96, key.Algorithm)
	assert.Equal(t, []byte("secret"), key.MasterKey)
	assert.True(t, key.ExcludeTcpOptions)

	for _, value := range []string{
		"0,10,hmac-sha1-96",
		"256,10,hmac-sha1-96,c2VjcmV0",
		"0,10,unknown,c2VjcmV0",
		"0,10,hmac-sha1-96,not-base64",
		"0,10,hmac-sha1-96,c2VjcmV0,unknown-option",
	} {
		_, err := parseTcpAoKey(value)
		assert.Error(t, err, value)
	}
}

func TestFormatTcpAoPeerState(t *testing.T) {
	state := &api.TcpAoPeerState{
		Keys: []*api.TcpAoKeyState{
			{SendId: 2, ReceiveId: 12, ReceiveNext: true, PacketsGood: 7, PacketsBad: 3},
			{SendId: 1, ReceiveId: 13, Current: true, PacketsGood: 42},
			{SendId: 1, ReceiveId: 11, PacketsGood: 5},
		},
		PacketsKeyNotFound: 2,
		PacketsAoRequired:  3,
		PacketsDroppedIcmp: 4,
	}
	assert.Equal(t, `  TCP-AO socket counters:
    Key not found: 2, AO required: 3, Dropped ICMP: 4
  TCP-AO socket key state:
    Send ID Receive ID Current Receive next Packets good Packets bad
          1         11   false        false            5           0
          1         13    true        false           42           0
          2         12   false         true            7           3
`, formatTcpAoPeerState(state))
	assert.Equal(t, uint32(2), state.Keys[0].SendId, "formatter must not mutate API state")
	assert.Empty(t, formatTcpAoPeerState(nil))
}

func TestTcpAoKeychainCommands(t *testing.T) {
	fake := useTcpAoCLIClient(t)

	command := newKeychainCmd()
	command.SetArgs([]string{"add", "fabric",
		"--key", "0,10,hmac-sha1-96,c2VjcmV0",
		"--key", "1,11,aes-128-cmac-96,b3RoZXI=,exclude-tcp-options",
		"--key", "2,12,hmac-sha-256-96,bmluZXR5LXNpeA==",
		"--key", "3,13,hmac-sha-256-128,b25lLXR3ZW50eS1laWdodA==",
	})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.addKeychain)
	assert.Equal(t, "fabric", fake.addKeychain.Keychain.Name)
	require.Len(t, fake.addKeychain.Keychain.Keys, 4)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96, fake.addKeychain.Keychain.Keys[1].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96, fake.addKeychain.Keychain.Keys[2].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, fake.addKeychain.Keychain.Keys[3].Algorithm)

	command = newKeychainCmd()
	command.SetArgs([]string{"update", "fabric",
		"--add-key", "2,12,hmac-sha1-96,bmV3",
		"--delete-key", "1,11",
	})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.updateKeychain)
	require.Len(t, fake.updateKeychain.AddKeys, 1)
	require.Len(t, fake.updateKeychain.DeleteKeys, 1)
	assert.Equal(t, uint32(1), fake.updateKeychain.DeleteKeys[0].SendId)

	command = newKeychainCmd()
	command.SetArgs([]string{"del", "fabric"})
	require.NoError(t, command.Execute())
	require.NotNil(t, fake.deleteKeychain)
	assert.Equal(t, "fabric", fake.deleteKeychain.Name)
}

func TestNeighborAddTcpAoPeerConfig(t *testing.T) {
	fake := useTcpAoCLIClient(t)
	require.NoError(t, modNeighbor(cmdAdd, []string{
		"192.0.2.1", "as", "65001", "tcp-ao-keychain", "fabric", "tcp-ao-preferred-send-id", "0",
	}))
	require.NotNil(t, fake.addPeer)
	require.NotNil(t, fake.addPeer.Peer.GetTcpAo())
	assert.Equal(t, "fabric", fake.addPeer.Peer.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(0), fake.addPeer.Peer.GetTcpAo().GetPreferredSendId())
}
