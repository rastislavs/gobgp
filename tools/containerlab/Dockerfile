# syntax=docker/dockerfile:1
# Build from this directory with the repository root as the context:
# docker build --file Dockerfile --tag gobgp:local ../..

ARG GO_VERSION=1.24.5
ARG ALPINE_VERSION=3.22

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -tags netgo \
      -ldflags="-s -w -buildid=" -o /out/gobgp ./cmd/gobgp && \
    CGO_ENABLED=0 go build -trimpath -tags netgo \
      -ldflags="-s -w -buildid=" -o /out/gobgpd ./cmd/gobgpd

FROM alpine:${ALPINE_VERSION}

RUN apk add --no-cache ca-certificates iproute2

COPY --from=builder /out/gobgp /out/gobgpd /usr/local/bin/

WORKDIR /etc/gobgp

EXPOSE 179/tcp 50051/tcp

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/gobgpd"]
