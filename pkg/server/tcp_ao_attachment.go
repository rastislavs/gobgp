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
	"github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tcpAoAttachment is the explicit configuration stored on a peer or peer
// group. preferredSendID is always resolved, while preferredSendIDExplicit
// preserves whether a one-key attachment omitted the optional API field.
type tcpAoAttachment struct {
	keychain                string
	preferredSendID         uint8
	preferredSendIDExplicit bool
}

func (a *tcpAoAttachment) clone() *tcpAoAttachment {
	if a == nil {
		return nil
	}
	clone := *a
	return &clone
}

func (a *tcpAoAttachment) equal(other *tcpAoAttachment) bool {
	if a == nil || other == nil {
		return a == other
	}
	return a.keychain == other.keychain && a.preferredSendID == other.preferredSendID
}

func (a *tcpAoAttachment) api() *api.TcpAoKeyAttachment {
	if a == nil {
		return nil
	}
	result := &api.TcpAoKeyAttachment{Keychain: a.keychain}
	if a.preferredSendIDExplicit {
		preferred := uint32(a.preferredSendID)
		result.PreferredSendId = &preferred
	}
	return result
}

// newTcpAoAttachment validates and normalizes a non-empty attachment. A nil
// attachment means that an API field was absent. A present attachment with an
// empty keychain is a reset command and is represented as nil by the caller.
func (s *BgpServer) newTcpAoAttachment(a *api.TcpAoKeyAttachment) (*tcpAoAttachment, error) {
	if a == nil {
		return nil, nil
	}
	if a.Keychain == "" {
		if a.PreferredSendId != nil {
			return nil, status.Error(codes.InvalidArgument, "a TCP-AO preference requires a keychain")
		}
		return nil, nil
	}

	chain, ok := s.tcpAoChains[a.Keychain]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", a.Keychain)
	}

	attachment := &tcpAoAttachment{keychain: a.Keychain}
	if a.PreferredSendId == nil {
		if len(chain.keys) != 1 {
			return nil, status.Errorf(codes.InvalidArgument, "TCP-AO keychain %q has multiple keys; preferred_send_id is required", a.Keychain)
		}
		attachment.preferredSendID = chain.keys[0].sendID
		return attachment, nil
	}
	if *a.PreferredSendId > 255 {
		return nil, status.Errorf(codes.InvalidArgument, "TCP-AO preferred send ID %d is outside 0..255", *a.PreferredSendId)
	}

	preferred := uint8(*a.PreferredSendId)
	for _, key := range chain.keys {
		if key.sendID == preferred {
			attachment.preferredSendID = preferred
			attachment.preferredSendIDExplicit = true
			return attachment, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q has no key with send ID %d", a.Keychain, preferred)
}

// tcpAoSocketConfig is an immutable, per-peer snapshot. The keychain is a deep
// copy so deleting the registry entry cannot change a socket being configured.
type tcpAoSocketConfig struct {
	keychain        *tcpAoKeychain
	preferredSendID uint8
}

func clearTcpAoSocketConfig(config *tcpAoSocketConfig) {
	if config == nil {
		return
	}
	clearTcpAoKeychain(config.keychain)
	config.keychain = nil
	config.preferredSendID = 0
}

func (c *tcpAoSocketConfig) matchesAttachment(a *tcpAoAttachment) bool {
	if c == nil || a == nil {
		return c == nil && a == nil
	}
	return c.keychain != nil && c.keychain.name == a.keychain && c.preferredSendID == a.preferredSendID
}

func (s *BgpServer) newTcpAoSocketConfig(a *tcpAoAttachment) (*tcpAoSocketConfig, error) {
	if a == nil {
		return nil, nil
	}
	chain, ok := s.lookupTcpAoKeychain(a.keychain)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q does not exist", a.keychain)
	}
	for _, key := range chain.keys {
		if key.sendID == a.preferredSendID {
			return &tcpAoSocketConfig{
				keychain:        chain,
				preferredSendID: a.preferredSendID,
			}, nil
		}
	}
	clearTcpAoKeychain(chain)
	return nil, status.Errorf(codes.NotFound, "TCP-AO keychain %q has no key with send ID %d", a.keychain, a.preferredSendID)
}

func effectiveTcpAoAttachment(explicit *tcpAoAttachment, group *peerGroup) *tcpAoAttachment {
	if explicit != nil {
		return explicit
	}
	if group != nil {
		return group.tcpAoAttachment
	}
	return nil
}
