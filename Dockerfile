# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------
# Produces a single static (CGO-free) binary with the web UI embedded, so
# nothing outside this stage's output is needed at runtime.
FROM golang:1.22-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
COPY web ./web

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/enumerator ./cmd/enumerator

# ---- netdiscover build stage -------------------------------------------
# Alpine doesn't package netdiscover (Debian/Kali-only), so it's built from
# source here and copied into the runtime stage below like any other tool.
FROM alpine:3.20 AS netdiscover-build
RUN apk add --no-cache git build-base autoconf automake libnet-dev libpcap-dev linux-headers
RUN git clone --depth 1 https://github.com/netdiscover-scanner/netdiscover.git /src \
	&& cd /src && autoreconf -vi && ./configure && make -j"$(nproc)"

# ---- runtime stage -----------------------------------------------------
# The static binary itself needs nothing beyond libc, but the app shells
# out to nmap/netdiscover/dnsrecon/traceroute/mtr when they're on PATH
# (internal/discovery's *Path() lookups) for richer scanning and topology
# discovery — none of that is usable from a distroless image with no
# package manager, so this trades that minimal footprint for Alpine plus
# the five optional tools.
FROM alpine:3.20 AS runtime

RUN apk add --no-cache nmap dnsrecon traceroute mtr libnet libpcap \
	&& adduser -D -u 10001 enumerator
COPY --from=netdiscover-build /src/src/netdiscover /usr/bin/netdiscover

COPY --from=build /out/enumerator /enumerator

ENV PORT=8080
EXPOSE 8080

USER enumerator
# ICMP ping, traceroute, and mtr all need a raw or unprivileged-datagram
# ICMP socket (see internal/discovery/icmp.go); nmap works unprivileged via
# -sT regardless. Without --cap-add=NET_RAW at `docker run` time, ICMP
# probing/traceroute/mtr are silently skipped and the app falls back to
# TCP-only discovery — it still runs, just with less signal.
ENTRYPOINT ["/enumerator"]
