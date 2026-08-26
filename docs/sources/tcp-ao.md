# TCP Authentication Option (TCP-AO)

TCP-AO authenticates TCP segments and supports multiple keys and algorithm
agility. It is defined by [RFC 5925](https://www.rfc-editor.org/rfc/rfc5925.html),
with its initial algorithms defined by
[RFC 5926](https://www.rfc-editor.org/rfc/rfc5926.html).

GoBGP supports TCP-AO for static and dynamic BGP peers on Linux. The kernel
performs TCP-AO authentication; GoBGP manages keychains, attaches them to
peers, and programs the corresponding socket options.

## Supported Features

- active and passive static IPv4, IPv6, and IPv6 link-local peers;
- passive dynamic IPv4 and IPv6 peers;
- IPv6 unnumbered peers;
- peers attached to GoBGP logical VRFs;
- keys scoped to Linux VRF devices;
- named keychains shared by one or more peers;
- direct neighbor and peer-group attachment;
- separate eight-bit send and receive key identifiers;
- HMAC-SHA-1-96, AES-128-CMAC-96, HMAC-SHA-256-96, and
  HMAC-SHA-256-128;
- optional exclusion of non-AO TCP options from authentication;
- configuration through TOML, the gRPC API, and the `gobgp` CLI; and
- atomic keychain updates through the API and CLI.

TCP-AO requires Linux 6.7 or later with `CONFIG_TCP_AO`. GoBGP provides the
Linux socket implementation on `amd64` and `arm64`. A kernel without TCP-AO
support rejects the socket operation; GoBGP does not fall back to unsigned TCP
or TCP-MD5. See the
[Linux TCP-AO documentation](https://docs.kernel.org/networking/tcp_ao.html)
for kernel details.

## Key Model

A keychain contains between 1 and 256 keys. Each key has:

| Field | Meaning |
| --- | --- |
| `key-id` / send ID | KeyID placed in TCP-AO segments sent by GoBGP. |
| `receive-id` | KeyID expected in TCP-AO segments received from the peer. |
| `crypto-algorithm` | Authentication and key-derivation algorithm. |
| `secret-key` | Base64 encoding of 1 to 80 master-key bytes. |
| `exclude-tcp-options` | Whether non-AO TCP options are excluded from the MAC. Defaults to `false`. |

Send IDs must be unique within a keychain, as must receive IDs. The remote
endpoint normally uses the reciprocal IDs. For example, a local key with send
ID `1` and receive ID `11` corresponds to a remote key with send ID `11` and
receive ID `1`, using the same algorithm and master key.

The file configuration follows the
[OpenConfig keychain model](https://openconfig.net/projects/models/schemadocs/jstree/openconfig-keychain.html)
for the common key fields. GoBGP augments each key with `receive-id` and
`exclude-tcp-options`, which are specific to this TCP-AO implementation.
GoBGP also derives `hmac_sha_256_96` and `hmac_sha_256_128` from the
OpenConfig crypto type so the TCP-AO MAC length is explicit; the generic
`hmac_sha_256` identity is not accepted.
OpenConfig tolerance and key lifetime fields are not currently supported.

## File Configuration

The following example creates a two-key keychain and attaches it to a static
neighbor:

```toml
[global.config]
  as = 65001
  router-id = "192.0.2.1"

[[keychains]]
  [keychains.config]
    name = "fabric"

  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 0
      receive-id = 10
      crypto-algorithm = "hmac_sha_1_96"
      # secret-key contains the base64 encoding of the master key bytes.
      secret-key = "emVybw=="

  [[keychains.keys]]
    [keychains.keys.config]
      key-id = 1
      receive-id = 11
      crypto-algorithm = "aes_128_cmac_96"
      secret-key = "b25l"
      exclude-tcp-options = true

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65002

  [neighbors.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0
```

Supported file configuration algorithm names are:

- `hmac_sha_1_96`;
- `aes_128_cmac_96`;
- `hmac_sha_256_96`; and
- `hmac_sha_256_128`.

`preferred-send-id` selects the initial key used for outgoing segments and the
target of a negotiated key handover. It must match a send ID in the referenced
keychain. On a connected socket, the remote peer's RNextKeyID request can change
the kernel's current outgoing key, so the operational Current key may
temporarily differ from this configured preference during a rollover. The value
is required whenever a keychain is attached. The value `0` is a valid key ID.

### Peer Groups

TCP-AO can be configured on a peer group and inherited by its static members:

```toml
[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "ao-peers"
    peer-as = 65002

  [peer-groups.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-group = "ao-peers"
```

An explicit neighbor attachment takes precedence over an inherited peer-group
attachment.

### Dynamic Neighbors

A dynamic neighbor inherits TCP-AO from its peer group. GoBGP installs the
keychain on the listening socket using the dynamic neighbor prefix, before a
matching connection can be accepted:

```toml
[[peer-groups]]
  [peer-groups.config]
    peer-group-name = "ao-dynamic-peers"
    peer-as = 65002

  [peer-groups.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0

[[dynamic-neighbors]]
  [dynamic-neighbors.config]
    prefix = "192.0.2.0/24"
    peer-group = "ao-dynamic-peers"
```

Preferred-send-ID changes and keychain rotations are applied to existing
dynamic sessions and the prefix-scoped listener keys. The referenced keychain
or bind interface cannot be replaced while the peer group has a configured
dynamic range or a live dynamic session; remove the range first. TCP-AO
dynamic ranges cannot overlap other dynamic ranges because Linux does not
provide longest-prefix selection between matching MKTs.

### Logical VRFs

A TCP-AO neighbor can be attached to an existing GoBGP logical VRF with the
normal `vrf` field:

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65002
    vrf = "blue"

  [neighbors.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0
```

The VRF must be defined under `[[vrfs]]` as usual. This selects the GoBGP
routing table independently of Linux VRF-device socket scoping.

### Linux VRF Devices

TCP-AO keys follow the normal socket device configuration. Use
`bind-to-device` for the BGP listener and `bind-interface` for an active peer:

```toml
[global.config]
  bind-to-device = "blue"

[[neighbors]]
  [neighbors.config]
    neighbor-address = "192.0.2.2"
    peer-as = 65002

  [neighbors.transport.config]
    bind-interface = "blue"

  [neighbors.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0
```

When the configured device is enslaved to a Linux VRF, GoBGP uses its VRF
master as the TCP-AO L3 key scope.

### Link-local and Unnumbered Peers

An unnumbered peer can attach a TCP-AO keychain in the same way as an addressed
peer:

```toml
[[neighbors]]
  [neighbors.config]
    neighbor-interface = "eth0"
    peer-as = 65002

  [neighbors.tcp-ao.config]
    keychain = "fabric"
    preferred-send-id = 0
```

GoBGP discovers the remote IPv6 link-local address from the Linux neighbor
table. Explicit link-local peer addresses must include an IPv6 zone, for
example `fe80::2%eth0`.

## CLI

List all keychains or one named keychain:

```shell
$ gobgp keychain
$ gobgp keychain fabric
```

The output contains key IDs, algorithms, and TCP-option policy. Master keys are
write-only and are not returned or displayed.

Create a keychain. Repeat `--key` to add multiple entries:

```shell
$ gobgp keychain add fabric \
    --key '0,10,hmac-sha-1-96,emVybw==' \
    --key '1,11,aes-128-cmac-96,b25l,exclude-tcp-options'
```

The key syntax is:

```text
send-id,receive-id,algorithm,base64-master-key[,exclude-tcp-options]
```

Update a keychain by adding and deleting entries in one operation. Both flags
are repeatable. A delete selector uses only the send and receive IDs:

```shell
$ gobgp keychain update fabric \
    --add-key '2,12,hmac-sha-1-96,dHdv' \
    --delete-key '1,11'
```

Delete an unreferenced keychain:

```shell
$ gobgp keychain del fabric
```

Attach a keychain when adding a neighbor:

```shell
$ gobgp neighbor add 192.0.2.2 as 65002 \
    tcp-ao-keychain fabric \
    tcp-ao-preferred-send-id 0
```

The CLI does not currently manage peer groups. Use file configuration or the
gRPC API for peer-group attachments.

Inspect the configured attachment and the live kernel key state of an
established peer:

```shell
$ gobgp neighbor 192.0.2.2
...
  TCP-AO keychain is fabric, preferred send ID: 0
  TCP-AO socket counters:
    Key not found: 0, AO required: 0, Dropped ICMP: 0
  TCP-AO socket key state:
    Send ID Receive ID Current Receive next Packets good Packets bad
          0         10    true        false          123           0
...
```

The counters report TCP-AO packets for which the kernel could not find a key,
unsigned packets received where TCP-AO was required, and ICMP errors ignored
for the protected connection. The table reflects the MKTs currently installed
on the socket rather than a comparison with the configured keychain. The same
observed state is available as `state.tcp_ao` in JSON output:

```shell
$ gobgp -j neighbor 192.0.2.2
```

## gRPC API

The API defines these keychain operations:

```protobuf
rpc AddTcpAoKeychain(AddTcpAoKeychainRequest)
    returns (AddTcpAoKeychainResponse);
rpc UpdateTcpAoKeychain(UpdateTcpAoKeychainRequest)
    returns (UpdateTcpAoKeychainResponse);
rpc DeleteTcpAoKeychain(DeleteTcpAoKeychainRequest)
    returns (DeleteTcpAoKeychainResponse);
rpc ListTcpAoKeychain(ListTcpAoKeychainRequest)
    returns (stream ListTcpAoKeychainResponse);
```

`TcpAoKey.master_key` contains raw master-key bytes in add and update requests.
It is write-only and is redacted from all responses. File and CLI configuration
decode their base64 input before populating this field.

`PeerState.tcp_ao.keys` reports the MKTs currently installed on the connected
socket, including their send and receive IDs, current and receive-next status,
and packet counters. The values are read directly from the kernel with
`getsockopt(TCP_AO_GET_KEYS)`.

Attach a keychain through `Peer.tcp_ao`:

```go
peer.TcpAo = &api.TcpAoPeerConfig{
	Keychain:        "fabric",
	PreferredSendId: 0,
}
```

See [`proto/api/gobgp.proto`](../../proto/api/gobgp.proto) for the complete
message definitions.

## Runtime Updates

Keychain configuration updates are atomic: the entire request is validated
before the stored keychain is changed. Invalid additions or deletions leave the
existing keychain unchanged. Deleting a preferred send key or a referenced
keychain is rejected.

After a valid update is stored, GoBGP applies it to listening and established
peer sockets on a best-effort basis. New keys are installed before old keys are
removed. A socket failure does not fail the configuration request or roll back
the stored keychain. If an addition fails on a socket, deletion is skipped on
that socket to preserve its previously working key set. New connections always
install the latest stored keychain.

Peer state continues to report the MKTs actually present on each live socket.
In particular, the kernel may retain a deleted key while it is still current
or receive-next. Consumers can compare the observed list with the configured
keychain when they need to determine whether a socket has converged.

Changing the preferred send ID requests a TCP-AO key handover through the
socket's receive-next selection. The kernel changes the current send key after
the remote peer signals that it is ready to receive that key. Operators remain
responsible for confirming that the remote peer no longer uses a key before
deleting it.

Changing a peer to a different keychain with `UpdatePeer` is rejected; delete
and add the peer to make that change. A peer-group attachment also cannot be
changed while the group has static members or dynamic neighbors. A dynamic
peer group's preferred send ID can be changed in place.

File reloads use the same API operations and therefore follow the same rules.

## Security Considerations

Base64 is an encoding, not encryption. Protect configuration files containing
`secret-key`, for example with mode `0600`, and avoid logging their contents.

The CLI passes base64 master keys as command-line arguments. Depending on the
environment, they may be retained in shell history or visible in process
listings. Prefer a protected configuration file or a gRPC client with suitable
secret handling when this exposure is unacceptable.

TCP-AO and TCP-MD5 (`auth-password`) are mutually exclusive for a peer. Both
endpoints must configure compatible keys, directional IDs, algorithms, and
TCP-option authentication policy.

## Current Limitations

- Linux `amd64` and `arm64` only;
- no key lifetimes, scheduled rollover, or tolerance windows;
- no automatic retry of a failed update on an existing socket; and
- no master-key file or external secret-provider support.

## Verification

Inspect the configured keychain:

```shell
$ gobgp keychain fabric
Name                  Send ID Receive ID Algorithm          Exclude TCP options
fabric                      0         10 hmac-sha-1-96      false
fabric                      1         11 aes-128-cmac-96    true
```

Inspect the peer attachment:

```shell
$ gobgp neighbor 192.0.2.2
...
  TCP-AO keychain is fabric, preferred send ID: 0
  TCP-AO socket key state:
    Send ID Receive ID Current Receive next Packets good Packets bad
          0         10    true        false          123           0
...
```
