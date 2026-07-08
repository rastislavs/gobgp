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

//go:build linux && (amd64 || arm64)

package netutils

import (
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setTCPAOSockopt(sc syscall.RawConn, option int, value []byte) error {
	var sockerr error
	controlErr := sc.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			uintptr(unix.IPPROTO_TCP),
			uintptr(option),
			uintptr(unsafe.Pointer(&value[0])),
			uintptr(len(value)),
			0,
		)
		if errno != 0 {
			sockerr = os.NewSyscallError("setsockopt(TCP_AO)", errno)
		}
	})
	runtime.KeepAlive(value)
	if sockerr != nil {
		return sockerr
	}
	return controlErr
}

// AddTCPAOKeysSockopt installs all configured keys on a TCP socket. A nil
// PreferredSendID leaves CurrentKey and RNextKey unset, as required for a
// listening socket. A non-nil value selects the matching key for both roles.
func AddTCPAOKeysSockopt(sc syscall.RawConn, peer netip.Prefix, ifindex int32, config TCPAOConfig) error {
	return addTCPAOKeys(func(option int, value []byte) error {
		return setTCPAOSockopt(sc, option, value)
	}, peer, ifindex, config)
}

// DeleteTCPAOKeysSockopt removes all configured keys from a TCP socket. The
// complete key definitions are required so a partial deletion can be rolled
// back if a later delete fails.
func DeleteTCPAOKeysSockopt(sc syscall.RawConn, peer netip.Prefix, ifindex int32, config TCPAOConfig) error {
	return deleteTCPAOKeys(func(option int, value []byte) error {
		return setTCPAOSockopt(sc, option, value)
	}, peer, ifindex, config)
}

// SetTCPAOKeySelectionSockopt selects CurrentKey by SendID and RNextKey by the
// paired ReceiveID on a connected TCP-AO socket.
func SetTCPAOKeySelectionSockopt(sc syscall.RawConn, config TCPAOConfig) error {
	return setTCPAOKeySelection(func(option int, value []byte) error {
		return setTCPAOSockopt(sc, option, value)
	}, config)
}
