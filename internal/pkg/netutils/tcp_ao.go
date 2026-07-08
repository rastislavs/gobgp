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

import "errors"

const tcpAOMaxKeyLen = 80

// ErrTCPAONotSupported is returned when TCP-AO is requested on a platform for
// which GoBGP does not provide the Linux TCP-AO userspace ABI.
var ErrTCPAONotSupported = errors.New("TCP-AO is not supported on this platform")

// TCPAOAlgorithm identifies an RFC 5926 TCP-AO algorithm profile. The MAC
// length is fixed at 96 bits for both profiles.
type TCPAOAlgorithm uint8

const (
	TCPAOAlgorithmUnspecified TCPAOAlgorithm = iota
	TCPAOAlgorithmHMACSHA1_96
	TCPAOAlgorithmAES128CMAC96
)

// TCPAOKey contains the platform-independent properties of one TCP-AO key.
// MasterKey is secret key material and must not be logged.
type TCPAOKey struct {
	SendID            uint8
	ReceiveID         uint8
	Algorithm         TCPAOAlgorithm
	MasterKey         []byte
	ExcludeTCPOptions bool
}

// TCPAOConfig is the set of keys installed on one socket. PreferredSendID is
// nil for a listening socket. When it is non-nil, the matching key becomes
// CurrentKey and its paired ReceiveID becomes RNextKey.
type TCPAOConfig struct {
	Keys            []TCPAOKey
	PreferredSendID *uint8
}
