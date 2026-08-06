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

# ---- runtime stage -----------------------------------------------------
# A static binary needs almost nothing: distroless "static" gives us CA
# certs (unused here, kept for parity) and nsswitch config for DNS, with no
# shell or package manager to shrink the attack surface and the footprint.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/enumerator /enumerator

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/enumerator"]
