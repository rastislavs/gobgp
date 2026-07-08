# TCP Authentication Option (TCP-AO) Design

> Status: MVP implementation in progress. The static gRPC-configured peer path
> is implemented and verified on Linux; declarative file configuration and the
> post-MVP features identified below remain. Last updated: 2026-07-08.

This document records the intended GoBGP design for the TCP Authentication
Option (TCP-AO). It is deliberately more detailed than normal user
documentation so that implementation work can be resumed without repeating the
protocol, Linux API, and GoBGP integration analysis.

The decisions in this document are the current baseline. If implementation
experience requires a change, update the decision summary, the affected API or
runtime section, and the change log at the end of this document.

This document uses three scope labels consistently:

- **Implemented first slice** is the static-peer gRPC path already present in
  the repository.
- **Remaining MVP** is declarative TOML/YAML configuration for that same
  immutable-keychain, creation-time-only model.
- **Post-MVP** covers live rollover and keychain membership changes,
  operational state, reconciliation, dynamic neighbors, VRFs, and
  link-local/unnumbered peers.

## Reading Guide

When resuming implementation:

1. Read [Decision Summary](#decision-summary) for the agreed invariants.
2. Read [Implementation Plan](#implementation-plan) for the completed first
   slice and the next MVP boundary.
3. Use [gRPC API](#grpc-api) as the public contract and
   [Runtime Socket Design](#runtime-socket-design) for lifecycle behavior.
4. Use [Linux UAPI Requirements](#linux-uapi-requirements) and
   [Testing Strategy](#testing-strategy) as implementation acceptance criteria.
5. Record any changed decision in both [Decision Summary](#decision-summary)
   and [Change Log](#change-log).

Major sections:

- [Long-term goals](#long-term-goals)
- [Initial non-goals](#non-goals-for-the-initial-implementation)
- [Standards and platform background](#standards-and-platform-background)
- [Terminology](#terminology)
- [Decision summary](#decision-summary)
- [Resource model](#resource-model)
- [gRPC API](#grpc-api)
- [API semantics](#api-semantics)
- [Declarative file configuration](#next-mvp-slice-declarative-file-configuration)
- [Runtime socket design](#runtime-socket-design)
- [Key rollover](#key-rollover)
- [Secret handling](#secret-handling)
- [Linux UAPI requirements](#linux-uapi-requirements)
- [Testing strategy](#testing-strategy)
- [Implementation plan](#implementation-plan)
- [Alternatives considered](#alternatives-considered)
- [Future work](#future-work)

## Summary

GoBGP supports an initial static TCP-AO path as a Linux transport
authentication mechanism for BGP sessions. The MVP:

- supports Linux 6.7 or later on supported 64-bit architectures when the kernel
  is built with `CONFIG_TCP_AO`;
- encounters unsupported kernels through the real socket operation, without a
  probe or capability API; listener failures are logged like TCP-MD5, while
  active and accepted connection setup fails;
- supports the RFC 5926 HMAC-SHA-1-96 and AES-128-CMAC-96 profiles, each with a
  fixed 12-byte MAC;
- manages multiple global named keychains;
- allows one keychain to be referenced by many peers and peer groups;
- allows exactly one effective keychain per peer connection;
- keeps desired key selection on the peer attachment without exposing public
  operational state;
- installs multiple immutable keys when a peer is created and rejects an
  `UpdatePeer` that would change the peer's effective TCP-AO configuration;
- requires an explicit `DeletePeer` followed by `AddPeer` for disruptive
  authentication replacement rather than hiding that replacement inside an
  update;
- fails closed when authentication cannot be configured; and
- never returns or logs master-key material.

The kernel performs TCP-AO signing and verification. GoBGP owns keychain
management, peer-to-keychain attachment, and static socket programming. The
later state, reconciliation, and live-rollover sections in this document are
explicitly post-MVP design, not current API.

## Long-Term Goals

- Provide standards-based TCP-AO protection for active and passive BGP sessions.
- Decouple reusable key material from peers.
- Support static peers, peer groups, dynamic neighbors, IPv4, IPv6, VRFs, and
  link-local/unnumbered peers.
- Support hitless rotation between keys in the same chain.
- Make desired configuration and actual per-socket state observable.
- Preserve compatibility with older gRPC clients that do not know about
  TCP-AO.
- Make authentication failures explicit and prevent silent downgrade.

## Non-Goals for the Initial Implementation

- HMAC-SHA-256 or any other non-RFC-5926 profile.
- Configurable MAC lengths.
- Time-based send/receive lifetimes or automatic scheduled rotation.
- Capability probes, public TCP-AO state, counters, or `TCP_AO_GET_KEYS`.
- Live key mutation, live selector changes, or hitless rollover.
- Dynamic neighbors, VRFs, and link-local/unnumbered peers.
- Declarative file configuration and dedicated CLI commands in the first code
  slice; the gRPC configuration path is implemented first.
- Multiple keychains attached to one peer.
- Disabling TCP-AO for one peer while its peer group enables TCP-AO; use a
  separate peer group for that exception.
- Forced CurrentKey changes or forced key deletion.
- Secret replacement in place.
- External KMS or secret-provider integration.
- Non-Linux socket implementations.
- TCP-AO repair/checkpoint support.

## Standards and Platform Background

[RFC 5925](https://www.rfc-editor.org/rfc/rfc5925.html) defines TCP-AO. It
replaces the single static secret used by TCP-MD5 with Master Key Tuples (MKTs),
connection-specific traffic keys, multiple keys per connection, SendID and
RecvID values, and coordinated rollover through CurrentKey and RNextKey.

[RFC 5926](https://www.rfc-editor.org/rfc/rfc5926.html) defines the initial
mandatory algorithm profiles:

- HMAC-SHA-1-96 with `KDF_HMAC_SHA1`; and
- AES-128-CMAC-96 with `KDF_AES_128_CMAC`.

Both profiles use a 96-bit (12-byte) MAC. The AES profile accepts a
variable-length administrative master key and applies the RFC-defined
AES-CMAC-PRF-128 extraction when it is not exactly 16 bytes.

Linux implements TCP-AO through per-socket `setsockopt` and `getsockopt`
operations. Userspace is responsible for adding, selecting, rotating, deleting,
and observing MKTs. The relevant operations are:

- `TCP_AO_ADD_KEY`;
- `TCP_AO_DEL_KEY`;
- `TCP_AO_INFO`; and
- `TCP_AO_GET_KEYS`.

The [Linux TCP-AO documentation](https://docs.kernel.org/networking/tcp_ao.html)
is authoritative for Linux behavior. Kernel version alone is insufficient:
the kernel may lack `CONFIG_TCP_AO`, an algorithm may be unavailable, or the
running architecture may not match the supported ABI.

## Terminology

| Term | Meaning in this design |
| --- | --- |
| Keychain | A globally named, reusable set of TCP-AO key entries. |
| SendID | Eight-bit key identifier sent as TCP-AO KeyID on outgoing segments. It is unique within a GoBGP keychain and is the canonical entry lookup. |
| RecvID | Eight-bit identifier used to match TCP-AO KeyID on incoming segments. When an MKT is the connection's RNextKey, its RecvID is advertised as RNextKeyID. |
| MKT | Master Key Tuple: key material plus algorithm, IDs, TCP-option authentication policy, and connection scope. |
| CurrentKey | The MKT currently used to authenticate outgoing segments on one TCP connection. |
| RNextKey | The MKT whose RecvID is advertised to request the peer's next outgoing key. |
| Preferred key | The attachment-selected MKT. Its SendID identifies the entry, and its paired RecvID supplies the desired RNextKey. |

GoBGP does not add a third administrative key-ID namespace. Key entries are
immutable. Preferred-send selection locates the entry by SendID, while the
selected entry's paired RecvID is derived automatically for RNextKey. TCP-AO
permits the two directional ID spaces to differ.

## Decision Summary

| ID | Decision | Rationale and consequence |
| --- | --- | --- |
| D1 | Support multiple global named keychains. | A deployment may use one chain, while larger deployments can isolate trust and rotation domains without an API change. |
| D2 | Attach exactly one effective chain to a peer. | This avoids ambiguous MKT selection and matches common router behavior. |
| D3 | Permit many peers to reuse a chain. | This is the requested management model, although documentation must warn about the larger compromise and rotation blast radius. |
| D4 | Keep address, prefix, VRF, interface, and socket data out of a keychain. | These are consumer-specific. An installed MKT is composed from a global key plus peer context. |
| D5 | Keep one preferred-key selector on the attachment, identified by SendID. | Peers sharing a chain may require different creation-time selections. The selected entry supplies both the initial outgoing MKT and the desired RNextKey; a chain has no single truthful selection for all consumers. |
| D6 | Do not expose CurrentKey, RNextKey, or counters in the MVP. | Public operational state requires `TCP_AO_GET_KEYS` and reconciliation and is deferred. |
| D7 | Do not add an administrative key ID. | SendID identifies the attachment-selected immutable entry, and RecvID remains its paired receive identity. |
| D8 | Make key entries immutable. | Changing secret, IDs, algorithm, or TCP-option exclusion in place is unsafe for installed MKTs. MVP rotation creates a replacement chain and recreates each affected peer; post-MVP rollover may add or remove whole immutable entries. |
| D9 | Support only HMAC-SHA-1-96 and AES-128-CMAC-96 initially. | Their KDF and MAC semantics are standardized and interoperable. |
| D10 | Do not expose MAC length initially. | Both initial profiles have a fixed 12-byte MAC. |
| D11 | Use `exclude_tcp_options`, defaulting to `false`. | The protobuf zero value follows RFC 5925 by authenticating TCP options and maps directly to Linux's exclusion flag. Operators explicitly enable exclusion when required for peer or middlebox interoperability. |
| D12 | Treat `TcpAoKey.master_key` as write-only. | Add uses the normal key resource, while every response clears the secret. |
| D13 | Do not expose keychain versions or optimistic-concurrency fields in the MVP. | MVP keychains are immutable, and management operations are serialized by the server. |
| D14 | Do not add a background reconciler in the MVP. | Listener key programming follows the existing synchronous, best-effort TCP-MD5 lifecycle. Active and accepted AO socket setup still fails closed. |
| D15 | Reject deletion of referenced chains. | The MVP has no unsafe force-delete behavior. |
| D16 | Do not modify established TCP-AO sockets in the MVP. | Effective TCP-AO changes through `UpdatePeer` are rejected; future normal rollover would need to coordinate CurrentKey through peer RNextKeyID. |
| D17 | Fail closed. | Socket setup failure closes or rejects the affected connection and never falls back to unsigned TCP or MD5. |
| D18 | Require explicit peer recreation for an effective TCP-AO change. | `UpdatePeer` does not perform an internal delete/add or session restart. Operators use `DeletePeer` and then `AddPeer`, making the disruption and failure boundary visible. |
| D19 | Reject peer-group TCP-AO attachment changes while static members exist. | Group fan-out would otherwise require a partially applied migration. Delete the static members, update the unused group, and add the peers again. |
| D20 | Defer dynamic-neighbor TCP-AO. | Prefix scopes and overlapping authentication policies require a later validated listener inventory. |
| D21 | Represent attachment state with message presence, a keychain name, and one optional scalar selector. | A present empty attachment resets to the contextual default: inherit for a grouped peer and disabled otherwise. This removes the mode enum and selector wrapper messages. |
| D22 | Return only an explicit peer override in `Peer.conf.tcp_ao`. | Canonical configured-state reads preserve inheritance across read-modify-write operations; there is no resolved peer state in the MVP. |
| D23 | Put `tcp_ao` beside `auth_password` in `PeerConf` and `PeerGroupConf`, not in `Transport`. | TCP-MD5 and TCP-AO are mutually exclusive peer-authentication policies. Socket programming remains a runtime concern and does not require the public configuration to live under transport. |
| D24 | Match the existing TCP-MD5 listener lifecycle for static peer add and delete. | `AddPeer` and `DeletePeer` program or remove exact-scope TCP-AO keys on live listeners. The MVP does not replace listeners, stop accept loops, or drain queued children; a connection already completed or queued at the update may reflect the previous listener policy. |

## Why Multiple Keychains

A singleton global keychain would make every peer part of one credential and
rotation domain. Supporting a collection costs little more in the public model,
allows operators to create only one chain when that is sufficient, and avoids a
future breaking API change.

The model follows the operational precedent of the
[Cisco Nexus TCP-AO keychain](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/chapter.html):
keys are configured globally and a connection references one chain.

RFC 5925 advises against broad MKT reuse across unrelated peering arrangements.
GoBGP will permit intentional reuse but should recommend separate chains for
separate trust domains.

## Resource Model

```text
TcpAoKeychain (global key material)
       ^
       | referenced by name
TcpAoKeyAttachment (Peer or PeerGroup desired selection)
       |
       | resolved with connection scope
       v
listener and connected-socket MKTs
       |
       v
TcpAoState (post-MVP actual per-peer/per-connection state)
```

A keychain contains only immutable key properties. It does not contain peer
addresses, prefixes, ports, interfaces, VRFs, CurrentKey, or RNextKey.

A peer or peer group attachment contains the chain reference and desired key
selection. The MVP connection scope is an exact static IPv4 or IPv6 peer.
Prefix scopes for dynamic neighbors, VRF/interface binding, and IPv6 zone
handling are post-MVP extensions; the MVP rejects those peer forms.

## gRPC API

The API is additive to
[`proto/api/gobgp.proto`](../../proto/api/gobgp.proto). The generated Go files
must be regenerated with the repository's Buf configuration.

### Service Methods

```protobuf
service GoBgpService {
  // Existing methods...

  rpc AddTcpAoKeychain(AddTcpAoKeychainRequest)
      returns (AddTcpAoKeychainResponse);

  rpc DeleteTcpAoKeychain(DeleteTcpAoKeychainRequest)
      returns (DeleteTcpAoKeychainResponse);

  rpc ListTcpAoKeychain(ListTcpAoKeychainRequest)
      returns (stream ListTcpAoKeychainResponse);
}
```

### Algorithms and Key Resource

```protobuf
enum TcpAoAlgorithm {
  TCP_AO_ALGORITHM_UNSPECIFIED = 0;
  TCP_AO_ALGORITHM_HMAC_SHA1_96 = 1;
  TCP_AO_ALGORITHM_AES_128_CMAC_96 = 2;
}

message TcpAoKey {
  // SendID uniquely identifies this immutable entry within the chain.
  // Validate both IDs as 0..255 before converting to Linux UAPI fields.
  uint32 send_id = 1;
  uint32 receive_id = 2;

  TcpAoAlgorithm algorithm = 3;

  // Write-only. Required when adding the key and cleared in every response.
  bytes master_key = 4 [debug_redact = true];

  // RFC 5925 authenticates non-AO TCP options by default. Setting this field
  // excludes them and maps to Linux TCP_AO_KEYF_EXCLUDE_OPT.
  bool exclude_tcp_options = 5;
}
```

An absent or false `exclude_tcp_options` follows the RFC 5925 default: TCP
options other than TCP-AO are included in the MAC. Setting it to true omits
those options from the MAC. TCP-AO itself is always authenticated. The setting
is not negotiated, so both endpoints must configure the corresponding MKT
consistently. Exclusion can accommodate a middlebox that rewrites TCP options,
at the cost of no longer detecting those changes.

Add requests populate `master_key` for every key. Add and List responses always
clear `master_key`. Clients must treat `master_key` as write-only.
`debug_redact` is defense in depth; the current Go protobuf string formatter
does not honor it, so code must never generically log secret-bearing requests.

### Keychain Resource and CRUD

```protobuf
message TcpAoKeychain {
  string name = 1;
  repeated TcpAoKey keys = 2;
}

message AddTcpAoKeychainRequest {
  TcpAoKeychain keychain = 1;
}

message AddTcpAoKeychainResponse {
  TcpAoKeychain keychain = 1;
}

message DeleteTcpAoKeychainRequest {
  string name = 1;
}

message DeleteTcpAoKeychainResponse {}

message ListTcpAoKeychainRequest {
  // Empty lists all chains; non-empty selects an exact name.
  string name = 1;
}

message ListTcpAoKeychainResponse {
  TcpAoKeychain keychain = 1;
}
```

MVP keychains are immutable and are created atomically with all their keys.
There is no `UpdateTcpAoKeychain` RPC. A referenced chain cannot be deleted.
Operators introduce key material by creating a new named chain or by creating
the original chain with multiple keys. Replacing an existing peer's selection
requires explicit peer deletion and recreation. Cross-namespace ID equality
remains legal. List responses are ordered by chain name and keys by ascending
SendID for deterministic output.

Mutations take effect in server management-loop order. The MVP provides no
compare-and-swap guarantee for multiple writers; deployments that introduce
multiple controllers must serialize their writes externally.

### Peer and Peer-Group Attachment

```protobuf
message TcpAoKeyAttachment {
  // Non-empty means that this peer or peer group explicitly uses the chain.
  string keychain = 1;

  // Selects one keychain entry by SendID. The entry's paired RecvID is the
  // desired RNextKeyID.
  optional uint32 preferred_send_id = 2;
}
```

The selector is an optional scalar field, not a wrapper message. Presence is
required because ID zero is valid. For an attachment with a non-empty keychain,
an absent selector means "use the one-key default", while a present value of
zero explicitly selects SendID zero. A present-empty reset attachment has no
selector.

The selected entry provides both directional values without requiring two
configuration knobs. On a new connection, its SendID selects the initial
CurrentKey and its paired RecvID selects RNextKey. The MVP does not change this
selection on an existing peer: a different preference requires `DeletePeer`
followed by `AddPeer`. In a post-MVP live design, changing
`preferred_send_id` would make the selected local MKT the RNextKey without
directly forcing CurrentKey; a received peer RNextKeyID would move local
CurrentKey when it matches a local MKT's SendID.

Add the same attachment type to the two existing authentication-bearing
configuration messages:

```protobuf
message PeerConf {
  // Existing fields 1 through 17, including auth_password = 1.
  TcpAoKeyAttachment tcp_ao = 18;
}

message PeerGroupConf {
  // Existing fields 1 through 13, including auth_password = 1.
  TcpAoKeyAttachment tcp_ao = 14;
}
```

`Transport` remains unchanged. Repeating the field declaration in `PeerConf`
and `PeerGroupConf` is intentional: both use the same `TcpAoKeyAttachment` type and
already repeat `auth_password`. A non-empty `auth_password` and a non-empty
`tcp_ao.keychain` are mutually exclusive after peer-group inheritance.
`DynamicNeighbor` remains unchanged, but the MVP rejects TCP-AO-enabled dynamic
neighbor groups.

### Deferred Operational Peer State (Post-MVP)

The following state model is retained as a future design sketch. It is not in
the MVP protobuf API.

```protobuf
enum TcpAoApplyStatus {
  TCP_AO_APPLY_STATUS_UNSPECIFIED = 0;
  TCP_AO_APPLY_STATUS_DISABLED = 1;
  TCP_AO_APPLY_STATUS_PENDING = 2;
  TCP_AO_APPLY_STATUS_APPLIED = 3;
  TCP_AO_APPLY_STATUS_DEGRADED = 4;
  TCP_AO_APPLY_STATUS_UNSUPPORTED = 5;
}

enum TcpAoApplyStage {
  TCP_AO_APPLY_STAGE_UNSPECIFIED = 0;
  TCP_AO_APPLY_STAGE_LISTENER = 1;
  TCP_AO_APPLY_STAGE_OUTGOING_SOCKET = 2;
  TCP_AO_APPLY_STAGE_ACCEPTED_SOCKET = 3;
  TCP_AO_APPLY_STAGE_ESTABLISHED_SOCKET = 4;
  TCP_AO_APPLY_STAGE_SELECTOR = 5;
  TCP_AO_APPLY_STAGE_KEY_RETIREMENT = 6;
}

message TcpAoApplyError {
  TcpAoApplyStage stage = 1;
  string message = 2;
  bool retryable = 3;
  google.protobuf.Timestamp time = 4;
}

message TcpAoCounters {
  uint64 good_segments = 1;
  uint64 bad_segments = 2;
  uint64 key_not_found_segments = 3;
  uint64 ao_required_segments = 4;
  uint64 dropped_icmp_messages = 5;
}

message TcpAoInstalledKeyState {
  uint32 send_id = 1;
  uint32 receive_id = 2;
  TcpAoAlgorithm algorithm = 3;
  bool installed_on_listener = 4;
  bool installed_on_connection = 5;
  bool current = 6;
  bool rnext = 7;
  uint64 good_segments = 8;
  uint64 bad_segments = 9;
}

message TcpAoState {
  bool active = 1;
  string keychain = 2;
  TcpAoApplyStatus apply_status = 3;
  optional uint32 desired_preferred_send_id = 4;
  optional uint32 actual_current_send_id = 5;
  optional uint32 actual_receive_next_id = 6;
  repeated TcpAoInstalledKeyState installed_keys = 7;
  TcpAoCounters counters = 8;
  repeated TcpAoApplyError errors = 9;
}
```

Add `TcpAoState tcp_ao = 24` to `PeerState`. Do not reuse the existing gap at
field 14.

The desired selector field reports the resolved effective SendID whenever
TCP-AO is enabled, including an implicit one-key default. Actual fields are
absent when there is no established TCP-AO connection. Installed-key state and
kernel counters describe only the current connection; they are replaced rather
than accumulated when the connection changes.

Linux reports CurrentKey in the SendID domain and RNextKey in the RecvID
domain. `TCP_AO_GET_KEYS` entries are joined to configuration by SendID and
sanity-checked against their RecvID and immutable metadata. A bare numeric ID
must never be resolved without retaining its directional domain.

SendIDs may be reused only after an earlier entry is fully retired. The
proposed post-MVP state API describes only the currently installed key state
and does not aggregate historical per-key counters across removal and reuse.
Any future historical metric needs an internal key-instance identity rather
than a client-visible keychain version.

The recent-error list must be bounded and messages must be sanitized. A peer
state event should be emitted when apply status, actual selectors, installed
keys, counters, or reconciliation errors change. Obsolete reconciliation
errors are removed after the corresponding desired state is applied.

### Deferred Runtime Capabilities (Post-MVP)

The MVP has no capability RPC and performs no proactive support probe. The
following model is deferred.

```protobuf
message TcpAoCapabilities {
  bool supported = 1;
  string unavailable_reason = 2;
  repeated TcpAoAlgorithm algorithms = 3;
  uint32 max_master_key_bytes = 4;
  uint32 max_keys_per_chain = 5;
  bool ipv4 = 6;
  bool ipv6 = 7;
  bool vrf = 8;
  bool peer_prefix_keys = 9;
  bool live_key_update = 10;
  bool live_selector_update = 11;
  bool per_key_counters = 12;
  bool accepted_socket_reconciliation = 13;
}

message GetTcpAoCapabilitiesRequest {}

message GetTcpAoCapabilitiesResponse {
  TcpAoCapabilities capabilities = 1;
}
```

If capability reporting is added later, it must be based on safe runtime
probes. Today the first required socket operation returns the platform or
kernel error and the connection fails closed.

## API Semantics

### Keychain Validation

- A name must be non-empty and unique.
- A chain contains between 1 and 256 keys.
- SendIDs are unique within the chain and provide canonical entry lookup.
- RecvIDs are independently unique within the chain.
- SendID and RecvID are separate namespaces. The same numeric value may appear
  in opposite namespaces, including on different entries.
- SendID and RecvID are each in the inclusive range 0 through 255.
- Algorithm is one of the two initial RFC 5926 profiles.
- `exclude_tcp_options` defaults to false, so non-AO TCP options are
  authenticated unless exclusion is explicitly requested.
- New master keys contain 1 through 80 raw bytes.
- Key material should be generated randomly; encoding is not encryption.

### Selector Validation

- A non-empty `keychain` requires an existing keychain.
- An attachment with an empty `keychain` must not contain a selector; it resets
  the target to its contextual default.
- With one effective key, absent `preferred_send_id` resolves to its SendID.
- With multiple keys, `preferred_send_id` is required.
- `preferred_send_id` references the SendID namespace.
- The selected entry's paired RecvID is the desired RNextKeyID; SendID and
  RecvID need not be equal.
- Scalar presence is significant because zero is a valid SendID.
- After peer-group inheritance, an effective TCP-AO keychain and a non-empty
  `auth_password` are mutually exclusive.
- The desired initial CurrentKey and RNextKey always come from the same selected
  entry. In the future live-rollover design, an established connection's
  actual CurrentKey may temporarily remain on the previous entry until peer
  coordination completes.
- A peer override replaces the complete inherited attachment; it is not merged
  field by field.

### Presence and Older Clients

Current `UpdatePeer` and `UpdatePeerGroup` requests have no field mask. The new
message therefore has special presence semantics:

| Operation | Absent `conf.tcp_ao` |
| --- | --- |
| `AddPeer` | Inherit from the peer group, or disable if no group exists. |
| `UpdatePeer` | Preserve the existing TCP-AO attachment. |
| `AddPeerGroup` | Disable TCP-AO. |
| `UpdatePeerGroup` | Preserve the existing TCP-AO attachment. |

A present attachment has these semantics:

| Target and value | Result |
| --- | --- |
| Any target with non-empty `keychain` | Explicitly use that keychain and the supplied preferred-key selection. |
| Grouped peer with empty `keychain` | Clear the peer override and inherit from its peer group. |
| Ungrouped peer with empty `keychain` | Disable TCP-AO. |
| Peer group with empty `keychain` | Disable TCP-AO for the group. |

A peer cannot explicitly disable TCP-AO while remaining in a TCP-AO-enabled
peer group. Put that peer in a separate group instead. This keeps the public
model free of an attachment mode or inheritance flag.

These rules are required because an older client cannot send the new field and
must not disable TCP-AO while changing an unrelated peer property.

API conversion must retain presence of the attachment message during an update:
absent means preserve, while present-empty means reset to the contextual
default. Applied peer configuration stores either an explicit override or no
override; it does not need the public mode enum. These presence rules determine
the proposed configuration, but do not authorize changing effective TCP-AO on
an existing peer.

### Creation-Time Immutability

The MVP treats effective TCP-AO as creation-time peer configuration:

- `UpdatePeer` first resolves the proposed attachment after applying the
  requested peer-group membership and inheritance. If the resulting effective
  keychain or preferred SendID differs from the peer's installed snapshot, the
  update is rejected. This covers enable, disable, chain replacement,
  preference replacement, and a group move that changes inherited TCP-AO.
- `UpdatePeer` may still change unrelated fields when the effective TCP-AO
  snapshot remains identical. An absent `tcp_ao` preserves the explicit
  override before the effective comparison. A present-empty attachment is
  allowed only when its contextual result is effectively unchanged.
- `UpdatePeerGroup` rejects a change to the group's TCP-AO attachment while the
  group has any static members. An otherwise unused group may be changed;
  TCP-AO-enabled dynamic-neighbor groups remain outside the MVP. Updates that
  do not change the group attachment remain subject to normal peer-group rules.

To change an individual peer, the operator calls `DeletePeer` and then
`AddPeer` with the new attachment. To change a peer-group attachment, the
operator deletes its static members, updates the now-unused group, and adds the
members again. GoBGP deliberately does not turn either update RPC into a hidden
delete/add sequence: the management client owns the disruption, ordering, and
retry policy.

Read APIs return configured state, not a merged attachment:
`Peer.conf.tcp_ao` is present only when that peer has an explicit override. It
remains absent for an inheriting or disabled peer. `PeerGroup.conf.tcp_ao` is
absent when the group is disabled. The MVP does not expose the resolved
keychain or selector; the deferred `PeerState.tcp_ao` design will report them.
This canonical form prevents a read-modify-write client from turning inherited
values into a peer override.

### CRUD and gRPC Status Codes

| Condition | gRPC status |
| --- | --- |
| Duplicate chain name | `ALREADY_EXISTS` |
| Missing chain or preferred SendID | `NOT_FOUND` |
| Invalid IDs, algorithm, secret, preferred-key selection, or request use of an output-only field | `INVALID_ARGUMENT` |
| Referenced chain | `FAILED_PRECONDITION` |
| `UpdatePeer` would change effective TCP-AO | `FAILED_PRECONDITION` |
| Peer-group TCP-AO attachment change while static members exist | `FAILED_PRECONDITION` |
| Authorization failure for key writes | `PERMISSION_DENIED` |

The MVP has no force-delete option. Error details may report safe peer or peer-group
identities, but must never include key material.

### Deferred Desired-State Reconciliation (Post-MVP)

A future live-key mutation would atomically change GoBGP's desired keychain
snapshot. It would not claim that all kernel sockets changed atomically.
Reconciliation would then move listeners and connections toward that snapshot.
The server would continue to serialize mutations; the current MVP API has no
optimistic-concurrency preconditions.

The post-MVP API should report applied, pending, and failed target counts,
while peer state distinguishes `PENDING`, `APPLIED`, and `DEGRADED`. Failures
are retried where safe. An affected socket that cannot be configured correctly
is closed or kept out of service; it is never admitted without the configured
authentication.

Queued reconciliation work carries an internal reconciliation revision so
older work cannot overwrite newer desired state. This revision is an
implementation detail and is never exposed in the API.

Key removal is requested with the exact `(SendID, RecvID)` pair and has stronger
admission checks. It is accepted only when no attachment selects that entry,
its SendID is not an actual CurrentKey, its RecvID is not an actual RNextKey,
and the relevant consumers have converged far enough for safe retirement.

## Next MVP Slice: Declarative File Configuration

Declarative TOML/YAML configuration is not in the first implemented code
slice. The following is the intended follow-up shape.

The top-level configuration follows the existing plural-resource convention.

```toml
[[tcp-ao-keychains]]
  [tcp-ao-keychains.config]
    name = "fabric-ao"

  [[tcp-ao-keychains.keys]]
    [tcp-ao-keychains.keys.config]
      send-id = 1
      receive-id = 1
      algorithm = "hmac-sha1-96"
      exclude-tcp-options = true

      # Read as raw bytes; do not strip a trailing newline.
      master-key-file = "/etc/gobgp/keys/fabric-ao-1"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "10.0.0.1"
    peer-as = 65001
    tcp-ao-keychain = "fabric-ao"
    # The preferred selector may be omitted because the chain has one key.
```

Allow exactly one secret source per key:

- `master-key` for an explicit text value;
- `master-key-base64` for binary data encoded as base64; or
- `master-key-file` for raw file bytes.

Base64 is an encoding, not protection. File permissions and configuration-at-
rest protection remain the operator's responsibility.

Every key in declarative file configuration must have a secret source on every
load. There is no reload-only "omitted means retain" behavior because the same
file must survive a process restart.

### Peer Groups

```toml
[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "edge"
    peer-as = 65002
    tcp-ao-keychain = "fabric-ao"
    tcp-ao-preferred-send-id = 1
```

A static peer may have its own creation-time selection by supplying a full
attachment that references the same chain. Changing that selection later uses
the staged delete/add workflow described below.

In declarative configuration, a peer without its own TCP-AO attachment inherits
from its peer group, or is disabled when it has no group. A peer group without
an attachment is disabled. A member of a TCP-AO-enabled group cannot disable
TCP-AO locally; use a separate peer group.

The YANG/OC and file forms use `tcp-ao-*` leaves in the existing neighbor or
peer-group `config` container, beside `auth-password`. The protobuf API groups
those leaves in `TcpAoKeyAttachment` so attachment and selector presence remain
explicit.

### Dynamic Neighbors (Post-MVP File Model)

The same file model can later attach a TCP-AO-enabled peer group to a dynamic
neighbor:

```toml
[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix = "172.40.0.0/16"
    peer-group = "edge"
```

In that post-MVP design, the dynamic prefix becomes the listener MKT scope and
the selection is applied to each accepted child connection. The remaining MVP
declarative-configuration work is limited to static peers and must reject this
combination until dynamic-neighbor socket support exists.

For asymmetric IDs, the peers reverse their directional values. For example,
if endpoint A configures `send-id = 10` and `receive-id = 20`, endpoint B
configures `send-id = 20` and `receive-id = 10`. Endpoint A selects its entry
with `preferred-send-id = 10` and automatically advertises its paired RecvID 20
as RNextKeyID. Endpoint B selects the corresponding entry with
`preferred-send-id = 20` and advertises RecvID 10.

### Reload Ordering

A reload must parse secret sources and validate the complete keychain-to-
consumer graph before changing authentication state. A retained static peer
must resolve to the same effective TCP-AO snapshot as before. A retained peer
group with static members must retain the same TCP-AO attachment. The loader
rejects a one-step file change that violates either rule; it must not emulate an
in-place migration by internally deleting and adding peers.

A disruptive declarative rotation is therefore staged:

1. add the new complete keychain while existing peers continue using the old
   one;
2. remove the affected peers from the file and reload, which deletes them and
   removes their TCP-AO listener keys through normal peer deletion;
3. update any now-unused peer-group attachment and reload;
4. add the peers with their new effective attachment and reload; and
5. delete the old keychain only after no peer or group references it.

For a peer with an explicit attachment and no group attachment change, steps 3
and 4 may be combined. Keeping the stages explicit makes failure recovery and
the period of session disruption visible to the operator.

Adding or retiring individual keys on live listeners and connections belongs
to the post-MVP mutable-key and hitless-rollover design.

Configuration and validation failures must be propagated. Listener ADD/DEL
errors follow the existing TCP-MD5 behavior and are logged while peer
configuration continues; active socket setup and accepted-child selector setup
still close or reject the affected connection rather than falling back to
unsigned TCP.

The loader must validate these admission rules before applying TCP-AO changes
and must not advance its current-configuration baseline after a failed reload.

## Post-MVP CLI Shape

Dedicated CLI commands are not part of the MVP. In particular, the per-key
`add` and `del` commands below require the post-MVP API for adding and removing
whole immutable entries from an existing chain; they do not mutate an entry's
secret or metadata in place.

```text
gobgp tcp-ao keychain
gobgp tcp-ao keychain NAME
gobgp tcp-ao keychain add NAME
gobgp tcp-ao keychain del NAME

gobgp tcp-ao keychain NAME key add SEND-ID \
  --receive-id N \
  --algorithm hmac-sha1-96 \
  --exclude-tcp-options \
  (--key-file PATH | --key-stdin)

gobgp tcp-ao keychain NAME key del SEND-ID --receive-id N

gobgp tcp-ao attach neighbor ADDRESS keychain NAME \
  [--preferred-send-id N]

gobgp tcp-ao clear neighbor ADDRESS

gobgp tcp-ao attach peer-group NAME keychain NAME \
  [--preferred-send-id N]

gobgp tcp-ao detach peer-group NAME
```

`clear neighbor` sends a present-empty attachment: it clears the explicit peer
override, so a grouped peer returns to peer-group inheritance and an ungrouped
peer becomes disabled. `detach peer-group` disables TCP-AO on that group.

Do not accept a master key as a command-line argument. Arguments are commonly
visible in shell history and process inspection. Use a raw key file, standard
input, or an interactive no-echo prompt.

Planned list and JSON output shows SendIDs, RecvIDs, algorithms, and whether TCP
options are excluded, but never key bytes.

## Runtime Socket Design

### Global Registry

The BGP server owns a global registry keyed by chain name. Registry entries are
immutable and management operations are serialized by the existing server
loop. The MVP has no generation, revision, or background work queue. Deletion
scans peer and peer-group attachments and rejects a referenced chain.

Secret byte slices are deep-copied on ingress and never stored in `Neighbor`,
`PeerGroup`, API state, or log values.

Entries are stored in deterministic SendID order. Validation independently
tracks SendID and RecvID uniqueness because the namespaces may legally have
crossed numeric values. Attachment lookup is always in the SendID namespace.

The MVP does not maintain a reverse index. Before deletion, it scans explicit
peer attachments, peer-group attachments (including groups with no current
members), and effective FSM snapshots, and rejects a chain that is still
referenced. Future live-socket observability may justify an internal reverse
index for TCP-AO consumers. Dynamic-neighbor support is a separate post-MVP
scope extension, not part of the MVP deletion path.

### Active Connections

For every new outgoing socket and every retry:

1. resolve the effective attachment;
2. snapshot the referenced keychain;
3. derive the exact static peer scope and address family;
4. install every chain key before `connect()`;
5. establish the desired initial selectors; and
6. close the socket if any required operation fails.

Post-MVP VRF and link-local support extends step 3 with the L3-master index and
IPv6 zone without changing keychain contents.

No unsigned connection attempt is permitted after an AO configuration failure.

### Passive Listeners

For the MVP, listeners maintain installed entries by exact peer address,
family, chain, and complete immutable key metadata. Prefix scopes and VRF
identity extend that inventory post-MVP. Listener key installation does not set
CurrentKey or RNextKey flags because listeners do not have those per-connection
pointers.

Static peer creation and deletion program exact-scope TCP-AO keys on already-
listening sockets, following the existing TCP-MD5 listener lifecycle. The MVP
does not rebuild listeners to establish an accept-queue boundary.

One shared listener may hold AO keys for some peers, MD5 keys for other peers,
and no authentication for others. AO and MD5 are prohibited only for the same
overlapping peer scope, not globally on the listener.

Do not set socket-global `ao_required` on a mixed-auth shared listener. A
matching peer MKT provides the peer-specific authentication requirement.

### Accepted Connections

Linux has an ADD/DEL-versus-`accept()` race: an established child waiting in
the accept queue may not contain a listener update that occurred during the
handshake. For every normally accepted TCP-AO connection, the MVP must:

1. identify the configured exact static peer;
2. apply the configured CurrentKey and derived RNextKey selection with
   `TCP_AO_INFO`; and
3. close the child before BGP OPEN if selection fails.

`TCP_AO_INFO` catches a child with no usable matching IDs, but it cannot tell
whether equal IDs refer to an old or new secret. Linux copies matching listener
MKTs into a child during handshake completion; that child retains them even if
the listener is updated later.

Like TCP-MD5, the MVP updates listener authentication in place. `AddPeer` and
`DeletePeer` do not replace the listener or drain its SYN or accept queue. A
handshake already completed or queued when listener keys change can therefore
reflect the prior policy. In particular, INFO selectors cannot distinguish an
old and new master key when both use the same SendID/RecvID pair. Strict accept-
queue cutover or accepted-child key reconciliation is outside the MVP.

### Established Connections in the MVP

The MVP does not mutate established sockets and does not internally reset and
recreate a peer for a TCP-AO change. Enabling, disabling, changing a chain, or
changing `preferred_send_id` through `UpdatePeer` is rejected. `DeletePeer`
explicitly tears down the old peer; a later `AddPeer` creates new sockets that
receive the complete immutable chain and initialize CurrentKey and RNextKey
from the selected entry.

### Deferred Live Rollover and FSM Ownership

Live socket changes must go through an FSM-owned command or immutable snapshot;
management code must not race direct access to the FSM connection.

Same-chain key additions install candidates without selecting them. RNext
updates advertise readiness for incoming traffic. Changing
`preferred_send_id` selects the initial CurrentKey and RNextKey for new
connections. On an established connection, it makes the selected local MKT the
RNextKey and advertises that MKT's RecvID. A received peer RNextKeyID moves the
local CurrentKey only when it matches a local MKT's SendID.

## Creation-Time Change Matrix

| Operation | MVP behavior |
| --- | --- |
| `AddPeer` with authentication | Validate and install the complete creation-time snapshot on each applicable live listener without replacing or draining it |
| `UpdatePeer` with unchanged effective TCP-AO | Allow unrelated peer changes |
| `UpdatePeer` enables or disables TCP-AO | Reject; use `DeletePeer`, then `AddPeer` |
| `UpdatePeer` changes keychain or preferred SendID | Reject; use `DeletePeer`, then `AddPeer` |
| `UpdatePeer` changes group membership and therefore effective TCP-AO | Reject; use `DeletePeer`, then `AddPeer` |
| `UpdatePeerGroup` changes TCP-AO with static members | Reject; delete members, update the group, then add members |
| `UpdatePeerGroup` changes TCP-AO with no static members or dynamic-neighbor use | Allow |
| Add or remove a key in the current chain | Not supported; keychains are immutable |
| Delete a referenced chain | Reject with `FAILED_PRECONDITION` |
| Change key secret, IDs, algorithm, or TCP-option exclusion | Create a replacement chain and recreate affected peers |

The lack of established-socket mutation is deliberate. Peer add and delete
update listener keys in place, matching TCP-MD5; the MVP does not reconcile
children already completing or queued in the SYN or accept queue.

## Key Rollover

MVP rollover is disruptive and management-driven. Create a replacement chain
at both endpoints, call `DeletePeer` for each affected peer, and call `AddPeer`
with the replacement attachment. For an inherited attachment, delete the
group's static members, update the unused group, and add the members again.
Delete the old chain after it has no references. GoBGP does not collapse these
steps into `UpdatePeer` or `UpdatePeerGroup`.

### Deferred Hitless Rollover

Hitless rollover is substantially more than allowing
`preferred_send_id` to change on `UpdatePeer`:

- Every established connection has its own CurrentKey and RNextKey, while
  listeners and newly connecting sockets have separate installed-key sets.
- The new immutable MKT must reach every relevant listener, connecting socket,
  and established socket before either endpoint advertises it. Concurrent
  connect and accept activity must use a coherent snapshot.
- Changing local RNextKey requests a peer-side CurrentKey change; it does not
  force local CurrentKey. Both endpoints must cooperate, and convergence is
  asynchronous in each direction.
- Shared keychains fan out to many peers that may be in different connection
  states. Partial installation, restart, or rollback cannot leave any peer
  silently unsigned or using a key the other endpoint has not installed.
- Safe retirement requires observing that no live established socket uses the
  old entry as CurrentKey or RNextKey. Numeric IDs alone cannot distinguish
  reused secret material. A future design that promises strict cutover for new
  connections must separately define how it handles children already
  completing or queued during listener updates.

Consequently, a future implementation needs an FSM-owned live-socket update
path, `TCP_AO_GET_KEYS`-based observation, per-peer apply state, reconciliation
across connection races, and conservative retirement checks. The current
Add/List/Delete keychain API and creation-time peer attachments cannot execute
this workflow.

With those post-MVP mechanisms, a safe shared-chain rollover would be:

1. If the chain has one key and selection is implicit, explicitly pin the old
   key's SendID as preferred-send on every attachment.
2. Add the new immutable key at both TCP-AO endpoints.
3. Wait for every intended peer to report `APPLIED` with the new key installed.
4. At each endpoint in the selected rollout batch, change
   `preferred_send_id` to that endpoint's new key SendID. This immediately
   selects the paired RecvID as RNextKey for established connections and the
   complete entry as the initial choice for new connections. Endpoint A then
   advertises its new RecvID, which asks endpoint B to move CurrentKey to the
   MKT with the matching SendID; endpoint B's preference change does the same
   for endpoint A.
5. Wait for both directions to converge: each established connection's actual
   CurrentKey is the local new key's SendID and its actual RNextKey is the local
   new key's RecvID.
6. Confirm good counters increase and bad, missing-key, and missing-AO counters
   remain stable.
7. Wait an operator-chosen settling interval.
8. Remove the old entry using its `(SendID, RecvID)` pair only after no
   attachment selects it, its SendID is absent from actual CurrentKey, and its
   RecvID is absent from actual RNextKey.

Peers sharing a chain can change their selections in separate batches. A
global chain update therefore does not imply a simultaneous CurrentKey change
for every consumer.

The MVP intentionally has no forced CurrentKey or forced deletion operation.
Linux provides emergency deletion mechanisms, but they can break a connection
and are not part of the normal GoBGP management contract.

## Secret Handling

- `TcpAoKey.master_key` is consumed only by Add and must contain 1 through 80
  bytes.
- Add and List responses always clear `master_key`.
- Response construction copies safe metadata into a redacted API object; it
  must never echo the request object or serialize the internal secret-bearing
  registry entry directly.
- Peer state, peer-group state, watch events, logs, metrics, and errors never
  contain master-key bytes.
- Protobuf byte slices are deep-copied before entering the registry.
- Secret-bearing objects use explicit redacted formatters and are never passed
  to generic `slog.Any` calls.
- Temporary buffers should be zeroed where practical, while recognizing that
  Go does not provide a complete guarantee against copies made by the runtime.
- The Linux ADD wire record contains a fixed-size copy of the master key. Clear
  that record after encoding, clear a partially encoded command on failure, and
  clear the command immediately after `setsockopt` returns.
- gRPC deployments configuring keys must use authenticated, encrypted transport
  and authorization that distinguishes keychain writes from ordinary reads.
- Configuration files and key files must be protected at rest by the operator.
- Base64 and hexadecimal forms are encodings, not encryption.

## Linux UAPI Requirements

These are implementation requirements, not optional style choices:

- Encode the Linux UAPI structures exactly, including alignment and native ABI
  details.
- Represent ADD, DEL, INFO, and IPv4/IPv6 sockaddrs as named fixed-size wire
  records and serialize them with `encoding/binary`; do not scatter raw byte
  offsets through the production marshalling path.
- Flatten each C bitfield group into its complete `uint32` storage word and
  model explicit reserved fields. Because `encoding/binary` adds no Go or C
  padding, every encoded record must have its size checked against the Linux
  UAPI size.
- The TCP port in the key's `sockaddr` is always zero because Linux does not
  implement TCP-AO port matching.
- An exact IPv4 peer uses prefix 32.
- An exact IPv6 peer uses prefix 128.
- Prefix zero is a wildcard and requires an all-zero address.
- Listener `ADD_KEY` calls do not set CurrentKey or RNextKey flags.
- Use kernel algorithm name `hmac(sha1)` for HMAC-SHA-1-96.
- Use kernel algorithm name `cmac(aes128)` for AES-128-CMAC-96 so Linux applies
  the RFC 5926 variable-length master-key handling.
- Map `exclude_tcp_options = true` to `TCP_AO_KEYF_EXCLUDE_OPT`; false leaves
  the flag clear and follows the RFC default.
- Guard C bitfield layouts by architecture. The MVP supports the verified
  little-endian Linux `amd64` and `arm64` layouts; another architecture must
  not enable the implementation until its layout is tested.
- Treat `ENOPROTOOPT` as unsupported.
- Treat `EEXIST` as a configuration conflict in the no-reconciler MVP.
- Log listener ADD/DEL failures with peer context, matching existing TCP-MD5
  management behavior. Never retry the connection without TCP-AO after active
  or accepted-socket setup fails.

The MVP uses an internal pure-Go Linux UAPI layer with platform and architecture
guards plus unsupported-platform stubs. It does not require cgo or unsafe
structure casts. Portable tests compare complete records with committed hex
fixtures generated through named fields in Linux's own UAPI structures; no raw
offsets are duplicated in Go tests. Opt-in live tests additionally verify that
the kernel accepts the resulting records.

Post-MVP scope expansion adds these UAPI requirements:

- A dynamic-neighbor MKT uses the configured, correctly masked peer prefix.
- For VRFs, derive the L3-master interface index and set
  `TCP_AO_KEYF_IFINDEX`; do not blindly use the physical source-interface
  index.
- Preserve IPv6 link-local scope/zone information.

## Lessons from the ExaBGP Implementation

The
[ExaBGP TCP-AO commit](https://github.com/Exa-Networks/exabgp/commit/230af2e330e3db14fafad384779d1d4563b9e754)
is useful as a wiring sketch: it configures active sockets before `connect()`,
programs listener keys, uses friendly algorithm names, validates key byte
length, and reports unsupported kernels. GoBGP's MVP does not treat ExaBGP's
listener timing as an accept-queue cutover guarantee.

It must not be copied as the Linux ABI reference. At the reviewed commit:

- active sockets place the BGP port in the AO sockaddr even though Linux
  requires zero;
- a concrete peer address is paired with prefix zero even though exact peers
  require `/32` or `/128`;
- every add sets CurrentKey and RNextKey flags, including adds to an existing
  listener where Linux rejects them;
- AES maps directly to `cmac(aes)` rather than the TCP-AO `cmac(aes128)` name
  needed for RFC KDF handling; and
- tests reproduce constants and structure sizes but do not invoke the
  production `setsockopt` path.

These issues motivate making a real-kernel ABI proof the first implementation
milestone.

## Testing Strategy

### Implemented First-Slice Coverage

- Production ADD, DEL, and INFO structure sizes and marshalling on Linux
  `amd64` and `arm64`, including IPv4/IPv6 sockaddr encoding, port zero,
  algorithm names, option coverage, selector flags, ID zero, validation, and
  rollback of a partially applied low-level key operation.
- Keychain validation, immutable/deep-copy storage, deterministic listing,
  response redaction, CRUD errors, and deletion reference checks.
- Attachment presence, one-key defaulting, multi-key selection, explicit
  SendID zero, peer-group inheritance, explicit override, present-empty reset,
  nil-preserve updates, rejection of effective TCP-AO changes, memberless group
  changes, dynamic-neighbor rejection, and direct or inherited MD5/AO conflict.
- Real-kernel two-key loopback sessions with selector observation for both RFC
  5926 algorithms over IPv4 and HMAC-SHA-1-96 over IPv6, plus wrong-key and
  unsigned-peer rejection.
- Complete active/passive GoBGP sessions for both algorithms over IPv4,
  including explicit `DeletePeer`/`AddPeer` replacement chains under normal
  live-listener operation.

### Remaining MVP Coverage

- Staged `DeletePeer`/`AddPeer` recreation across both explicit and inherited
  attachments.
- Multiple AO peers sharing one listener and mixed AO/MD5/unsigned scopes.
- Accepted-child selector failure, unsupported-kernel fail-closed behavior,
  and transport-level gRPC tests.
- Declarative load, reload, restart persistence, cleanup ordering, and
  dependency-deletion tests when that MVP slice is implemented.

### Post-MVP Coverage

- Dynamic-neighbor prefixes and newly accepted dynamic peers.
- VRFs with duplicate peer address space and IPv6 link-local/unnumbered peers.
- Live two-key rollover, safe key retirement, listener update during a
  handshake, reconciliation, state, and counters.

Functional CI requires a host kernel with TCP-AO enabled. A container does not
provide a different kernel and is insufficient by itself.

## Implementation Plan

### Completed First Slice

- Added the minimal Add/List/Delete keychain RPCs and attachment fields.
- Added immutable, redacted keychain storage and reference checks.
- Added pure-Go Linux ADD, DEL, and INFO encoding for `amd64` and `arm64`, with
  unsupported-platform stubs and rollback for partially applied key-add or
  key-delete operations.
- Wired exact static peers into shared listeners with TCP-MD5-equivalent
  best-effort management logging, and into outgoing sockets and accepted-child
  selection with fail-closed connection setup.
- Added peer and peer-group attachment presence, inheritance, explicit
  override, creation-time validation, and guards against effective in-place
  TCP-AO changes.
- Verified HMAC-SHA-1-96, AES-128-CMAC-96, IPv4/IPv6, asymmetric IDs,
  wrong-key and unsigned rejection, explicit peer recreation, and live-listener
  key ADD/DEL on a Linux 6.8 Lima VM.

### Next MVP Slice: Declarative Configuration

- Add global keychains and presence-aware attachment leaves beside
  `auth-password` in YANG/OC and TOML/YAML.
- Add secure key-file input and full-graph validation before applying changes.
- Make initial load and reload return keychain and attachment validation errors;
  listener programming failures retain the existing TCP-MD5 log-and-continue
  behavior.
- Add reload tests for create, staged peer deletion and re-addition, unused
  peer-group attachment changes, and dependency deletion ordering.

### Post-MVP: Live Rollover and Observability

- Add candidates without selecting them.
- Apply preferred-key policy through the FSM, deriving RNext from the selected
  entry's RecvID.
- Add `TCP_AO_GET_KEYS`, operational state, counters, and capability reporting.
- Observe peer-coordinated CurrentKey movement.
- Enforce safe retirement and deletion checks.
- Add end-to-end rollover and accept-race tests.

### Post-MVP: Coverage Expansion

- Add dynamic neighbors, VRFs, and link-local/unnumbered peers.
- Add dedicated CLI commands with file/stdin/no-echo secret input.
- Add scheduled lifetimes and optional emergency forced deletion.

## GoBGP-Specific Integration Hazards

- `UpdatePeer` reconstructs a zero-valued OC neighbor. A missing TCP-AO field
  must preserve the explicit attachment before defaults and inheritance are
  applied, so the effective-snapshot admission check does not invent a change.
- Current generated neighbor and peer-group configuration uses value structs
  and reflection-based inheritance. Conversion must preserve
  attachment-message presence and optional selector presence, including an
  explicit ID value of zero.
- `OverwriteNeighborConfigWithPeerGroup` flattens inherited values into the
  effective neighbor. Retain the explicit TCP-AO override (or its absence)
  separately both for the effective comparison and so `ListPeer` does not
  return inherited values in `Peer.conf.tcp_ao`.
- Peer and peer-group API conversion exists in both directions. All current
  paths, including watch-event construction, require deliberate attachment
  handling; the post-MVP state model will require the same audit for state.
- Keychain-content changes must not be copied into `PeerConf.tcp_ao` or mistaken
  for an attachment-reference change.
- A peer-group attachment comparison must occur before mutating the group. If
  static members exist, reject the attachment change rather than attempting a
  member-by-member migration or rollback.
- Existing generic configuration logging may include whole structs. Secret-
  bearing request/config types require redacted logging paths.
- Existing numeric API conversion often casts before range validation. TCP-AO
  IDs must be validated before conversion to eight-bit UAPI fields.
- Listener key ADD/DEL affects future handshakes, but a child whose handshake
  already completed or is queued can retain the previous listener policy. This
  is the same race accepted for TCP-MD5. `TCP_AO_INFO` configures child
  selectors and closes unusable AO children, but cannot distinguish old and new
  master keys when numeric IDs are reused.

## Alternatives Considered

### Inline Keys on Every Peer

Rejected. It duplicates secrets, makes shared rotation difficult, increases the
chance of inconsistent updates, and does not meet the key-management
decoupling requirement.

### One Singleton Global Keychain

Rejected. It imposes a single trust and rotation domain. A collection supports
the singleton deployment as a subset without future API breakage.

### Multiple Keychains per Peer

Rejected for the MVP. TCP-AO selection already occurs among keys within one chain.
Multiple attached chains would add ambiguous overlap and dependency semantics.

### Attachment Mode Enum and Selector Wrapper Messages

Rejected. Attachment-message presence and an empty versus non-empty keychain
already express preserve, reset-to-default, and explicit configuration. The MVP does
not support disabling TCP-AO for one member of an enabled peer group, so it
does not need a separate disabled mode. Proto3 `optional uint32` preserves the
distinction between an absent selector and the valid ID zero without wrapper
messages.

### TCP-AO Attachment under `Transport`

Rejected after comparison with the existing TCP-MD5 model. Although TCP-AO is
programmed on sockets, `auth_password` is a peer-authentication policy in
`PeerConf` and `PeerGroupConf`; TCP-AO is its mutually exclusive replacement.
Putting both policies together makes the API, inheritance, validation, and file
configuration consistent. Runtime socket code resolves the effective
authentication policy independently of its public configuration location.

### Chain-Level CurrentKey and RNextKey

Rejected. Actual state is per socket, and shared-chain peers may rotate in
different batches. Preferred-key selection belongs on attachments.

### Independent Receive-Next Selector

Rejected for the normal management API. One attachment-selected MKT supplies
both its SendID for initial outgoing selection and its paired RecvID for
RNextKey. On an established connection, changing that preference updates only
RNextKey and leaves CurrentKey movement to peer coordination. Independent
directional knobs would primarily serve asymmetric policy or forced recovery
when a peer does not cooperate; those cases are outside the MVP.

### Separate Administrative Key ID

Rejected. Key entries are immutable and SendIDs are unique within a chain, so
the existing `(SendID, RecvID)` pair provides sufficient mutation identity. A
third identity namespace would duplicate protocol state and require extra
mapping. Preferred-send and actual CurrentKey use SendID directly; the selected
entry's paired RecvID supplies desired RNextKey, while actual RNextKey remains in
the RecvID domain. In the proposed post-MVP state model, current operational
state is replaced when a key is removed or a connection changes; it does not
claim continuous historical counters when an ID is eventually reused.

### Mutable Keys

Rejected. A secret or algorithm change under the same IDs is hard to reconcile
safely on live sockets. Immutable entries make rotation explicit. The
post-MVP design may add or remove complete immutable entries from a chain; that
does not make an existing entry mutable.

### Public Optimistic-Concurrency Tokens

Deferred for the MVP. The expected deployment has one effective writer, keychains
are immutable, and the server serializes management operations. A future API
can add an explicit precondition if multi-controller deployments demonstrate
that need.

### Raw Linux Algorithm Names in the Public API

Rejected. Public profiles describe interoperable protocol behavior. Linux
names such as `hmac(sha1)` and `cmac(aes128)` remain internal details.

### Automatic Lifetimes in the MVP

Deferred. They are useful but introduce clock, overlap, restart, and failure
policy. The MVP records only a creation-time preferred selection; scheduled
live rotation requires the post-MVP installation, observation, and retirement
machinery described above.

### HMAC-SHA-256 in the MVP

Deferred. Current Linux behavior and the evolving IETF HMAC-SHA256-128 work do
not yet provide one unambiguous interoperability profile for this API. A future
addition must use an explicitly named algorithm/KDF profile.

### Fail-Open Fallback

Rejected. Falling back to unsigned TCP or MD5 after an AO error violates the
operator's authentication intent.

### cgo for Linux UAPI Structures

Rejected for the initial approach. A guarded pure-Go implementation fits
GoBGP's existing socket-option code. ABI golden tests are required to keep it
safe.

## Future Work

- Scheduled send lifetimes and automatic rollover policy.
- A precisely defined HMAC-SHA256-128 profile after standards and platform
  interoperability are settled.
- Configurable MAC length if a future profile needs it.
- External secret references, KMS integration, and encrypted configuration at
  rest.
- Structured authorization roles for keychain readers and writers.
- Non-Linux implementations.
- Additional architecture support after ABI verification.
- Emergency forced deletion with explicit disruption semantics.
- TCP-AO repair/checkpoint support.
- A repository-wide FieldMask approach for peer updates.
- Evaluation of whether chain-to-chain migration can be made live safely.

## References

- [RFC 5925: The TCP Authentication Option](https://www.rfc-editor.org/rfc/rfc5925.html)
- [RFC 5926: Cryptographic Algorithms for TCP-AO](https://www.rfc-editor.org/rfc/rfc5926.html)
- [RFC 8177: YANG Data Model for Key Chains](https://www.rfc-editor.org/rfc/rfc8177.html)
- [Linux TCP-AO documentation](https://docs.kernel.org/networking/tcp_ao.html)
- [Linux TCP UAPI header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h)
- [Linux TCP-AO implementation](https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_ao.c)
- [Linux TCP-AO selftests](https://github.com/torvalds/linux/tree/master/tools/testing/selftests/net/tcp_ao)
- [Cisco Nexus TCP-AO configuration guide](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/configuration/security/cisco-nexus-9000-series-nx-os-security-configuration-guide-release-106x/chapter.html)
- [OpenConfig keychain model](https://openconfig.net/projects/models/schemadocs/yangdoc/openconfig-keychain.html)
- [ExaBGP TCP-AO commit reviewed during design](https://github.com/Exa-Networks/exabgp/commit/230af2e330e3db14fafad384779d1d4563b9e754)
- [GoBGP Configuration](configuration.md)
- [GoBGP Peer Groups](peer-group.md)
- [GoBGP Dynamic Neighbors](dynamic-neighbor.md)
- [GoBGP Unnumbered BGP](unnumbered-bgp.md)

## Change Log

### 2026-07-08

- Narrowed the MVP to creation-time effective TCP-AO configuration.
  `UpdatePeer` rejects any effective TCP-AO change instead of internally
  resetting and recreating the peer.
- Required operators and declarative workflows to use an explicit
  `DeletePeer` followed by `AddPeer` for disruptive TCP-AO replacement.
- Made peer-group TCP-AO attachment changes invalid while static members exist;
  delete the members, update the unused group, and add the members again.
- Aligned static TCP-AO listener lifecycle with TCP-MD5: peer add and delete
  program live listeners without incarnation replacement or queue draining.
- Expanded the deferred hitless-rollover rationale to cover per-socket state,
  peer-coordinated CurrentKey movement, connection races, fan-out, observation,
  and safe key retirement.
- Removed assumptions that the TCP-AO MVP transactionally migrates MD5 or
  reconciles dynamic peers.
- Replaced production byte-offset assignments in the Linux UAPI marshaller with
  named fixed-size wire records encoded by `encoding/binary`.
- Replaced Go test byte-offset assertions with whole-record hex fixtures
  generated from `<linux/tcp.h>`, preserving an independent ABI oracle and live
  kernel validation without requiring cgo during ordinary tests.

### 2026-07-07

- Established multiple global named keychains with one effective chain per
  peer.
- Removed the separate administrative key ID. Key entries use their SendID and
  RecvID, while attachment selection uses SendID and derives the paired RecvID.
- Replaced separate key input/output messages with one `TcpAoKey`; field 4 is
  the write-only `master_key`, field 5 is the RFC-defaulted
  `exclude_tcp_options` boolean, and there is no redundant secret-present
  response field.
- Removed client-visible keychain versions and mutation preconditions. MVP
  keychains are immutable and have Add/List/Delete RPCs only.
- Simplified `TcpAoKeyAttachment` to a keychain name and one optional scalar
  selector. Message presence and a present-empty reset replace the mode enum; an
  enabled peer group has no per-member disable override in the MVP.
- Placed `tcp_ao` beside `auth_password` in `PeerConf` and `PeerGroupConf` and
  left `Transport` unchanged.
- Separated global key material and attachment-level desired selection. Public
  connection-level state is deferred.
- Removed the independent receive-next selector. `preferred_send_id` identifies
  one key entry; its paired RecvID supplies RNextKey. MVP effective attachment
  changes require explicit peer recreation; future live rollover would update
  only RNextKey and leave CurrentKey movement to peer coordination.
- Implemented the minimal gRPC resource and attachment API without capability
  or operational-state messages.
- Limited the MVP to RFC 5926 HMAC-SHA-1-96 and AES-128-CMAC-96.
- Deferred HMAC-SHA256-128 because its interoperable profile is not yet
  sufficiently clear for the initial API.
- Recorded Linux UAPI requirements and lessons from the reviewed ExaBGP
  implementation.
- Implemented fail-closed static active and passive socket programming for
  Linux `amd64` and `arm64` using ADD, DEL, and INFO only.
- Programmed static TCP-AO listener keys in place during peer add and delete,
  matching the TCP-MD5 listener lifecycle.
- Verified both RFC 5926 algorithms, IPv4/IPv6, two-key selection, wrong-key
  and unsigned rejection, explicit peer recreation with a replacement chain,
  and live-listener key ADD/DEL on Linux 6.8 in Lima.
- Kept declarative file configuration as the remaining MVP slice, and deferred
  dynamic neighbors, VRFs, link-local peers, live rollover, probes, state, and
  counters to post-MVP work.
- Clarified the implemented-first-slice, remaining-MVP, and post-MVP boundaries
  throughout the resource, runtime, UAPI, reload, CLI, and testing sections.
