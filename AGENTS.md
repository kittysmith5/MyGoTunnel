# AGENTS.md

## Project Overview

MyGoTunnel is a small Go QUIC tunnel project. It exposes a local SOCKS5 client, forwards CONNECT requests through a QUIC stream, authenticates the tunnel with a shared token, and has the server connect to the final target address.

## Repository Layout

- `cmd/client/main.go`: local SOCKS5 listener and QUIC tunnel client.
- `cmd/server/main.go`: QUIC tunnel server, token validation, and outbound target dialing.
- `internal/config`: JSON config loading and defaults.
- `internal/socks5`: SOCKS5 handshake, CONNECT request parsing, and replies.
- `internal/tunnel`: line-oriented protocol helpers (`AUTH`, `CONNECT`, `OK`, `ERR`) carried over QUIC streams.
- `internal/relay`: bidirectional stream copy helpers.
- `configs/`: local JSON configs. These are ignored by git and may contain secrets.
- `certs/`: local TLS certificate/key files. These are ignored by git.

## Common Commands

Run formatting before committing:

```sh
gofmt -w ./cmd ./internal
```

Run tests/checks:

```sh
go test ./...
```

Run the server:

```sh
go run ./cmd/server -config configs/server.json
```

Run the client:

```sh
go run ./cmd/client -config configs/client.json
```

Build binaries:

```sh
go build ./cmd/server
go build ./cmd/client
```

## Development Notes

- Keep imports on the local module path `mygotunnel/...`.
- Prefer small package-level helpers in the relevant `internal` package instead of adding cross-cutting abstractions.
- Preserve the current protocol shape unless intentionally changing both client and server:
  - client sends `AUTH <token>\n`
  - server replies `OK\n` or `ERR\n`
  - client sends `CONNECT <host:port>\n`
  - server replies `OK\n` or `ERR\n`
  - after `OK`, both sides relay raw bytes over the QUIC stream
- `internal/socks5` currently supports TCP CONNECT for IPv4, domain names, and IPv6. Keep SOCKS5 reply codes meaningful when adding failure paths.
- `internal/relay.CopyBidirectional` may receive buffered readers so already-read bytes are not lost. Do not replace those readers with raw streams/conns without checking call sites.
- Avoid logging auth tokens, certificate contents, private keys, or full local config contents.

## Configuration And Secrets

- `configs/*.json` and `certs/*.pem` are intended to be local-only and are ignored by git.
- Do not commit real `auth_token` values, private keys, or production server addresses.
- If example configuration is needed, add sanitized sample files with placeholder values, such as `configs/client.example.json`.
- Server config defaults:
  - `listen_addr`: `:9001`
  - `cert_file`: `certs/cert.pem`
  - `key_file`: `certs/key.pem`
- Client config defaults:
  - `local_addr`: `127.0.0.1:1080`

## Testing Guidance

- Add focused unit tests for parsing and protocol helpers when changing `internal/socks5`, `internal/tunnel`, or `internal/config`.
- For network behavior, prefer local loopback integration tests with short deadlines to avoid hanging test runs.
- Always run `go test ./...` after behavioral changes.

## Git Hygiene

- The worktree may contain local config/certificate files or user changes. Do not overwrite or normalize unrelated changes.
- Keep generated binaries and local runtime artifacts out of the repository.
- Before finishing code changes, check:

```sh
git status --short
go test ./...
```
