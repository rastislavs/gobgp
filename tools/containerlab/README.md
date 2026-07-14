# Two-node GoBGP Containerlab

This lab starts two GoBGP containers connected by a point-to-point `eth1` link.
They establish an IPv4 eBGP session and advertise one documentation prefix each.

| Node | AS | Peering address | Advertised prefix |
| --- | ---: | --- | --- |
| `gobgp1` | 65001 | `10.0.0.1/30` | `198.51.100.0/24` |
| `gobgp2` | 65002 | `10.0.0.2/30` | `203.0.113.0/24` |

## Prerequisites

- Docker
- [Containerlab](https://containerlab.dev/install/)
- Make
- A Linux host or Linux virtual machine capable of creating container links

Run the commands from the lab directory:

```shell
cd tools/containerlab
```

If your installation requires elevated privileges, override the command when
running Make, for example `make deploy CONTAINERLAB="sudo containerlab"`.

## Build and deploy

Build the local image:

```shell
make build
```

Deploy the lab, rebuilding the image through Docker's cache first:

```shell
make deploy
```

The equivalent direct image-build command is
`docker build --file Dockerfile --tag gobgp:local ../..`. The repository root
must be the build context so Docker can access the GoBGP source tree.

The node health checks turn healthy after the BGP session is established and the
remote test prefix is present. Inspect their status with:

```shell
make inspect
```

## Verify the lab

Show the peering-link addresses, BGP neighbors, and routing tables on both nodes:

```shell
make verify
```

Each neighbor should be in the `Establ` state. The routing table on `gobgp1`
should contain `203.0.113.0/24` through AS 65002, while `gobgp2` should contain
`198.51.100.0/24` through AS 65001.

You can also test direct link connectivity:

```shell
docker exec clab-gobgp-gobgp1 ping -c 2 10.0.0.2
```

## Destroy the lab

```shell
make destroy
```
