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
	"fmt"
	"sort"

	"github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const tcpAoMaxMasterKeyBytes = 80

// tcpAoKey and tcpAoKeychain are deliberately separate from their protobuf
// representations. In particular, no API response can accidentally alias or
// serialize the master-key bytes held by the server.
type tcpAoKey struct {
	sendID            uint8
	receiveID         uint8
	algorithm         api.TcpAoAlgorithm
	masterKey         []byte
	excludeTCPOptions bool
}

type tcpAoKeychain struct {
	name string
	keys []tcpAoKey
}

func newTcpAoKeychain(a *api.TcpAoKeychain) (*tcpAoKeychain, error) {
	if a == nil {
		return nil, status.Error(codes.InvalidArgument, "TCP-AO keychain is required")
	}
	if a.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "TCP-AO keychain name is required")
	}
	if len(a.Keys) == 0 || len(a.Keys) > 256 {
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q must contain between 1 and 256 keys", a.Name)
	}

	sendIDs := make(map[uint32]struct{}, len(a.Keys))
	receiveIDs := make(map[uint32]struct{}, len(a.Keys))
	for i, key := range a.Keys {
		if key == nil {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q contains a nil key at index %d", a.Name, i)
		}
		if key.SendId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has send ID %d outside 0..255", a.Name, i, key.SendId)
		}
		if key.ReceiveId > 255 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has receive ID %d outside 0..255", a.Name, i, key.ReceiveId)
		}
		if _, ok := sendIDs[key.SendId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate send ID %d", a.Name, key.SendId)
		}
		if _, ok := receiveIDs[key.ReceiveId]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has duplicate receive ID %d", a.Name, key.ReceiveId)
		}
		switch key.Algorithm {
		case api.TcpAoAlgorithm_TCP_AO_ALGORITHM_HMAC_SHA1_96,
			api.TcpAoAlgorithm_TCP_AO_ALGORITHM_AES_128_CMAC_96:
		default:
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d has unsupported algorithm %s", a.Name, i, key.Algorithm)
		}
		if len(key.MasterKey) == 0 || len(key.MasterKey) > tcpAoMaxMasterKeyBytes {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q key %d master key must contain between 1 and %d bytes", a.Name, i, tcpAoMaxMasterKeyBytes)
		}

		sendIDs[key.SendId] = struct{}{}
		receiveIDs[key.ReceiveId] = struct{}{}
	}

	// Validate the complete request before copying any secret bytes. An error on
	// a later key therefore cannot abandon an earlier copied master key for the
	// garbage collector to reclaim without first zeroing it.
	chain := &tcpAoKeychain{
		name: a.Name,
		keys: make([]tcpAoKey, 0, len(a.Keys)),
	}
	for _, key := range a.Keys {
		chain.keys = append(chain.keys, tcpAoKey{
			sendID:            uint8(key.SendId),
			receiveID:         uint8(key.ReceiveId),
			algorithm:         key.Algorithm,
			masterKey:         append([]byte(nil), key.MasterKey...),
			excludeTCPOptions: key.ExcludeTcpOptions,
		})
	}

	// A canonical order makes API results and socket programming deterministic.
	sort.Slice(chain.keys, func(i, j int) bool {
		return chain.keys[i].sendID < chain.keys[j].sendID
	})
	return chain, nil
}

func (c *tcpAoKeychain) clone() *tcpAoKeychain {
	if c == nil {
		return nil
	}
	clone := &tcpAoKeychain{
		name: c.name,
		keys: make([]tcpAoKey, len(c.keys)),
	}
	copy(clone.keys, c.keys)
	for i := range clone.keys {
		clone.keys[i].masterKey = append([]byte(nil), c.keys[i].masterKey...)
	}
	return clone
}

func (c *tcpAoKeychain) redactedAPI() *api.TcpAoKeychain {
	if c == nil {
		return nil
	}
	a := &api.TcpAoKeychain{
		Name: c.name,
		Keys: make([]*api.TcpAoKey, 0, len(c.keys)),
	}
	for _, key := range c.keys {
		a.Keys = append(a.Keys, &api.TcpAoKey{
			SendId:            uint32(key.sendID),
			ReceiveId:         uint32(key.receiveID),
			Algorithm:         key.algorithm,
			ExcludeTcpOptions: key.excludeTCPOptions,
		})
	}
	return a
}

func clearTcpAoKeychain(c *tcpAoKeychain) {
	if c == nil {
		return
	}
	for i := range c.keys {
		clear(c.keys[i].masterKey)
		c.keys[i].masterKey = nil
	}
}

func (s *BgpServer) clearTcpAoKeychains() {
	for name, chain := range s.tcpAoChains {
		clearTcpAoKeychain(chain)
		delete(s.tcpAoChains, name)
	}
}

// lookupTcpAoKeychain returns a deep copy suitable for retaining in a peer or
// socket configuration. Callers cannot mutate the registry or another
// consumer's copy of the secret.
func (s *BgpServer) lookupTcpAoKeychain(name string) (*tcpAoKeychain, bool) {
	chain, ok := s.tcpAoChains[name]
	if !ok {
		return nil, false
	}
	return chain.clone(), true
}

func (s *BgpServer) tcpAoKeychainReferenced(name string) bool {
	for _, group := range s.peerGroupMap {
		if group.tcpAoAttachment != nil && group.tcpAoAttachment.keychain == name {
			return true
		}
	}
	for _, peer := range s.neighborMap {
		if peer.tcpAoAttachment != nil && peer.tcpAoAttachment.keychain == name {
			return true
		}
		if peer.fsm.tcpAoConfig != nil && peer.fsm.tcpAoConfig.keychain.name == name {
			return true
		}
	}
	return false
}

func deleteTcpAoKeychain(registry map[string]*tcpAoKeychain, name string, referenced bool) error {
	if name == "" {
		return status.Error(codes.InvalidArgument, "TCP-AO keychain name is required")
	}
	chain, ok := registry[name]
	if !ok {
		return status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", name)
	}
	if referenced {
		return status.Errorf(codes.FailedPrecondition, "TCP-AO keychain %q is referenced", name)
	}
	clearTcpAoKeychain(chain)
	delete(registry, name)
	return nil
}

func (s *BgpServer) AddTcpAoKeychain(ctx context.Context, r *api.AddTcpAoKeychainRequest) (*api.AddTcpAoKeychainResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "nil request")
	}
	var response *api.AddTcpAoKeychainResponse
	err := s.mgmtOperation(func() error {
		chain, err := newTcpAoKeychain(r.Keychain)
		if err != nil {
			return err
		}
		if _, exists := s.tcpAoChains[chain.name]; exists {
			clearTcpAoKeychain(chain)
			return status.Errorf(codes.AlreadyExists, "TCP-AO keychain %q already exists", chain.name)
		}
		s.tcpAoChains[chain.name] = chain
		response = &api.AddTcpAoKeychainResponse{Keychain: chain.redactedAPI()}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (s *BgpServer) DeleteTcpAoKeychain(ctx context.Context, r *api.DeleteTcpAoKeychainRequest) error {
	if r == nil {
		return status.Error(codes.InvalidArgument, "nil request")
	}
	return s.mgmtOperation(func() error {
		return deleteTcpAoKeychain(s.tcpAoChains, r.Name, s.tcpAoKeychainReferenced(r.Name))
	}, false)
}

func (s *BgpServer) ListTcpAoKeychain(ctx context.Context, r *api.ListTcpAoKeychainRequest, fn func(*api.TcpAoKeychain)) error {
	if r == nil {
		return status.Error(codes.InvalidArgument, "nil request")
	}
	if fn == nil {
		return status.Error(codes.InvalidArgument, "nil callback")
	}

	var chains []*api.TcpAoKeychain
	err := s.mgmtOperation(func() error {
		if r.Name != "" {
			chain, ok := s.tcpAoChains[r.Name]
			if !ok {
				return status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", r.Name)
			}
			chains = []*api.TcpAoKeychain{chain.redactedAPI()}
			return nil
		}

		names := make([]string, 0, len(s.tcpAoChains))
		for name := range s.tcpAoChains {
			names = append(names, name)
		}
		sort.Strings(names)
		chains = make([]*api.TcpAoKeychain, 0, len(names))
		for _, name := range names {
			chains = append(chains, s.tcpAoChains[name].redactedAPI())
		}
		return nil
	}, false)
	if err != nil {
		return err
	}

	for _, chain := range chains {
		if err := ctx.Err(); err != nil {
			return err
		}
		fn(chain)
	}
	return nil
}

func (c *tcpAoKeychain) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf("TCP-AO keychain %q (%d keys)", c.name, len(c.keys))
}
