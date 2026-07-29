package config

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExampleUpdateConfig shows how InitialConfig can be used without UpdateConfig
func ExampleInitialConfig() {
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	initialConfig, err := ReadConfigFile("gobgp.conf", "toml")
	if err != nil {
		// Handle error
		return
	}

	isGracefulRestart := true
	_, err = InitialConfig(context.Background(), bgpServer, initialConfig, isGracefulRestart)
	if err != nil {
		// Handle error
		return
	}
}

// ExampleUpdateConfig shows how UpdateConfig is used in conjunction with
// InitialConfig.
func ExampleUpdateConfig() {
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()

	initialConfig, err := ReadConfigFile("gobgp.conf", "toml")
	if err != nil {
		// Handle error
		return
	}

	isGracefulRestart := true
	currentConfig, err := InitialConfig(context.Background(), bgpServer, initialConfig, isGracefulRestart)
	if err != nil {
		// Handle error
		return
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for range sigCh {
		newConfig, err := ReadConfigFile("gobgp.conf", "toml")
		if err != nil {
			// Handle error
			continue
		}

		currentConfig, err = UpdateConfig(context.Background(), bgpServer, currentConfig, newConfig)
		if err != nil {
			// Handle error
			continue
		}
	}
}

func TestTcpAoKeychainConfigLifecycle(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "gobgpd.toml")

	writeConfig := func(content string) *oc.BgpConfigSet {
		require.NoError(t, os.WriteFile(configFile, []byte(content), 0o600))
		config, err := ReadConfigFile(configFile, "toml")
		require.NoError(t, err)
		return config
	}
	global := `
[global.config]
  as = 65000
  router-id = "192.0.2.1"
  port = -1
`
	initial := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 1
      receive-id = 11
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "aW5pdGlhbA=="
`)
	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()
	t.Cleanup(func() {
		require.NoError(t, bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	current, err := InitialConfig(context.Background(), bgpServer, initial, false)
	require.NoError(t, err)

	listed := listTcpAoKeychains(t, bgpServer)
	require.Contains(t, listed, "fabric")
	require.Len(t, listed["fabric"].Keys, 1)
	assert.Equal(t, uint32(1), listed["fabric"].Keys[0].SendId)
	assert.Empty(t, listed["fabric"].Keys[0].MasterKey)

	replacement := *current
	replacement.Keychains = append([]oc.Keychain(nil), current.Keychains...)
	replacement.Keychains[0].Keys = append([]oc.Key(nil), current.Keychains[0].Keys...)
	replacement.Keychains[0].Keys[0].Config.SecretKey = "dXBkYXRlZA=="
	_, err = UpdateConfig(context.Background(), bgpServer, current, &replacement)
	require.ErrorContains(t, err, "key replacement requires separate delete + add configuration updates")

	updated := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 2
      receive-id = 12
      crypto-algorithm = "hmac_sha_256_96"
      secret-key = "dXBkYXRlZA=="

[[keychains]]
  [keychains.config]
    name = "edge"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 3
      receive-id = 13
      crypto-algorithm = "hmac_sha_256_128"
      exclude-tcp-options = true
      secret-key = "ZWRnZS1rZXk="
`)
	current, err = UpdateConfig(context.Background(), bgpServer, current, updated)
	require.NoError(t, err)

	listed = listTcpAoKeychains(t, bgpServer)
	require.Len(t, listed, 2)
	require.Len(t, listed["fabric"].Keys, 1)
	assert.Equal(t, uint32(2), listed["fabric"].Keys[0].SendId)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_96, listed["fabric"].Keys[0].Algorithm)
	assert.Equal(t, api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA256_128, listed["edge"].Keys[0].Algorithm)
	assert.True(t, listed["edge"].Keys[0].ExcludeTcpOptions)
	removed := writeConfig(global + `
[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 2
      receive-id = 12
      crypto-algorithm = "hmac_sha_256_96"
      secret-key = "dXBkYXRlZA=="
`)
	_, err = UpdateConfig(context.Background(), bgpServer, current, removed)
	require.NoError(t, err)

	err = bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "edge"}, func(*api.TcpAoKeychain) {})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestTcpAoPeerConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "gobgpd.toml")
	require.NoError(t, os.WriteFile(configFile, []byte(`
[global.config]
  as = 65000
  router-id = "192.0.2.1"
  port = -1

[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 0
      receive-id = 10
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "emVybw=="
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 1
      receive-id = 11
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "b25l"

[[vrfs]]
  [vrfs.config]
    name = "blue"
    rd = "65000:100"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65001
    vrf = "blue"
  [neighbors.transport.config]
    passive-mode = true
  [neighbors.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0
`), 0o600))

	config, err := ReadConfigFile(configFile, "toml")
	require.NoError(t, err)
	require.Len(t, config.Neighbors, 1)
	assert.Equal(t, oc.KeychainRef("fabric"), config.Neighbors[0].TcpAo.Config.Keychain)
	assert.Equal(t, uint8(0), config.Neighbors[0].TcpAo.Config.PreferredSendId)
	assert.Equal(t, "blue", config.Neighbors[0].Config.Vrf)

	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()
	t.Cleanup(func() {
		require.NoError(t, bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	current, err := InitialConfig(context.Background(), bgpServer, config, false)
	require.NoError(t, err)

	var peer *api.Peer
	require.NoError(t, bgpServer.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.2"}, func(listed *api.Peer) {
		peer = listed
	}))
	require.NotNil(t, peer)
	require.NotNil(t, peer.GetTcpAo())
	assert.Equal(t, "blue", peer.GetConf().GetVrf())
	assert.Equal(t, "fabric", peer.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(0), peer.GetTcpAo().GetPreferredSendId())

	updated := *current
	updated.Keychains = append([]oc.Keychain(nil), current.Keychains...)
	updated.Keychains[0].Keys = append(append([]oc.Key(nil), current.Keychains[0].Keys[1:]...), oc.Key{
		Config: oc.KeyConfig{
			KeyId:           "2",
			ReceiveId:       12,
			CryptoAlgorithm: oc.CRYPTO_TYPE_HMAC_SHA_1_96,
			SecretKey:       "dHdv",
		},
	})
	updated.Neighbors = append([]oc.Neighbor(nil), current.Neighbors...)
	updated.Neighbors[0].TcpAo.Config.PreferredSendId = 2
	next, err := UpdateConfig(context.Background(), bgpServer, current, &updated)
	require.NoError(t, err)
	require.Len(t, listTcpAoKeychains(t, bgpServer)["fabric"].Keys, 2)
	peer = nil
	require.NoError(t, bgpServer.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.2"}, func(listed *api.Peer) {
		peer = listed
	}))
	require.NotNil(t, peer)
	assert.Equal(t, uint32(2), peer.GetTcpAo().GetPreferredSendId())

	restored, err := UpdateConfig(context.Background(), bgpServer, next, current)
	require.NoError(t, err)
	require.Len(t, listTcpAoKeychains(t, bgpServer)["fabric"].Keys, 2)

	removed := *restored
	removed.Keychains = nil
	removed.Neighbors = nil
	_, err = UpdateConfig(context.Background(), bgpServer, restored, &removed)
	require.NoError(t, err)
	err = bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "fabric"}, func(*api.TcpAoKeychain) {})
	assert.Equal(t, codes.NotFound, status.Code(err))
	peer = nil
	require.NoError(t, bgpServer.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.2"}, func(listed *api.Peer) {
		peer = listed
	}))
	assert.Nil(t, peer)
}

func TestTcpAoPeerGroupConfig(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "gobgpd.toml")
	require.NoError(t, os.WriteFile(configFile, []byte(`
[global.config]
  as = 65000
  router-id = "192.0.2.1"
  port = -1

[[keychains]]
  [keychains.config]
    name = "fabric"
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 0
      receive-id = 10
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "emVybw=="
  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 1
      receive-id = 11
      crypto-algorithm = "hmac_sha_1_96"
      secret-key = "b25l"

[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "ao-group"
    peer-as = 65001
  [peer-groups.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-group = "ao-group"
  [neighbors.transport.config]
    passive-mode = true
`), 0o600))

	config, err := ReadConfigFile(configFile, "toml")
	require.NoError(t, err)
	require.Len(t, config.PeerGroups, 1)
	assert.Equal(t, oc.KeychainRef("fabric"), config.PeerGroups[0].TcpAo.Config.Keychain)
	assert.Equal(t, uint8(0), config.PeerGroups[0].TcpAo.Config.PreferredSendId)

	bgpServer := server.NewBgpServer()
	go bgpServer.Serve()
	t.Cleanup(func() {
		require.NoError(t, bgpServer.StopBgp(context.Background(), &api.StopBgpRequest{}))
	})
	current, err := InitialConfig(context.Background(), bgpServer, config, false)
	require.NoError(t, err)

	var group *api.PeerGroup
	require.NoError(t, bgpServer.ListPeerGroup(context.Background(), &api.ListPeerGroupRequest{PeerGroupName: "ao-group"}, func(listed *api.PeerGroup) {
		group = listed
	}))
	require.NotNil(t, group)
	require.NotNil(t, group.GetTcpAo())
	assert.Equal(t, "fabric", group.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(0), group.GetTcpAo().GetPreferredSendId())

	var peer *api.Peer
	require.NoError(t, bgpServer.ListPeer(context.Background(), &api.ListPeerRequest{Address: "192.0.2.2"}, func(listed *api.Peer) {
		peer = listed
	}))
	require.NotNil(t, peer)
	require.NotNil(t, peer.GetTcpAo())
	assert.Equal(t, "fabric", peer.GetTcpAo().GetKeychain())
	assert.Equal(t, uint32(0), peer.GetTcpAo().GetPreferredSendId())
	assert.Equal(t, codes.FailedPrecondition, status.Code(bgpServer.DeleteTcpAoKeychain(context.Background(), &api.DeleteTcpAoKeychainRequest{Name: "fabric"})))

	removed := *current
	removed.Keychains = nil
	removed.Neighbors = nil
	removed.PeerGroups = nil
	_, err = UpdateConfig(context.Background(), bgpServer, current, &removed)
	require.NoError(t, err)
	err = bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{Name: "fabric"}, func(*api.TcpAoKeychain) {})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func listTcpAoKeychains(t *testing.T, bgpServer *server.BgpServer) map[string]*api.TcpAoKeychain {
	t.Helper()
	result := make(map[string]*api.TcpAoKeychain)
	err := bgpServer.ListTcpAoKeychain(context.Background(), &api.ListTcpAoKeychainRequest{}, func(chain *api.TcpAoKeychain) {
		result[chain.Name] = chain
	})
	require.NoError(t, err)
	return result
}
