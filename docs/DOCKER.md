# Docker

The image runs the gateway by default and carries the MCP guard. It runs as an
unprivileged user (uid 10001), keeps everything it owns under `/data`, and is
built from a base image pinned by digest.

```bash
docker build -t mandate .
```

## Gateway

Put a `gateway.json` into a volume. A relative `store` is resolved against the
configuration file, so `"store": "store"` becomes `/data/store`.

```json
{
  "store": "store",
  "auth": {"kind": "api_keys"},
  "routes": [{
    "audience": "mandate://procurement",
    "base_url": "https://erp.example.com/api/v2",
    "allowed_methods": ["POST"],
    "allowed_paths": ["/orders"]
  }]
}
```

```bash
docker volume create mandate-data
docker run --rm -v mandate-data:/data -v "$PWD/gateway.json:/tmp/gateway.json:ro" \
  --entrypoint cp mandate /tmp/gateway.json /data/gateway.json

docker run --rm -v mandate-data:/data mandate gateway check --config /data/gateway.json
docker run --rm -v mandate-data:/data mandate \
  keys new --db /data/store/mandate.sqlite --tenant acme --name ci

docker run -d --name mandate -p 127.0.0.1:8080:8080 -v mandate-data:/data mandate
curl -fsS localhost:8080/health
```

The container listens on `0.0.0.0:8080` inside; the example publishes it on
the host's loopback only. The gateway speaks plain HTTP, and every request
carries a bearer key: for agents on other machines, put a TLS-terminating
proxy in front of that loopback port rather than publishing it on the
network. The health check calls `/health` every 30
seconds.

A key manager (`enforcer_signer` with `aws-kms`, `gcp-kms` or `vault-transit`)
keeps the signing key out of the volume altogether; its credentials come in
through the environment, as for any container.

## MCP guard

The guard speaks MCP over stdio, so the agent runtime starts the container
itself and keeps stdin open (`-i`):

```bash
docker volume create mandate-mcp
docker run --rm -v mandate-mcp:/data -v "$PWD/guard.json:/tmp/guard.json:ro" \
  --entrypoint cp mandate /tmp/guard.json /data/guard.json
docker run --rm -v mandate-mcp:/data mandate mcp init --config /data/guard.json

docker run -i --rm -v mandate-mcp:/data mandate \
  mcp serve --config /data/guard.json
```

`init` writes the principal, the agent and the grant into the volume once;
`serve` then finds them there on every start.

The upstream MCP server the guard starts (`upstream.command` in `guard.json`)
has to exist inside the image. A server installed with `npx` or `uvx` on the
host does not; for those, run the guard on the host with
`pip install "mandate[mcp] @ git+https://github.com/BEKO2210/mandate"`, or build an image on top of this one that
adds the upstream.

## Files

`/data` holds the ledger (`store/mandate.sqlite`), the development keys when no
key manager is configured, and the configuration. Back up the volume like any
database; the receipt chain can be verified from a copy without any key:

```bash
docker run --rm -v mandate-data:/data mandate chain verify --db /data/store/mandate.sqlite
```
