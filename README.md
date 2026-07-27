# kodi-profile-sync-server

Development implementation of the mwoDevelop Kodi profile synchronization
store and loopback HTTP API.

Implemented:

- immutable schema 2 revisions;
- SQLite WAL storage and migrations;
- candidate and active channel pointers;
- compare-and-swap publication;
- idempotency keys;
- exact canary assignments;
- native Ed25519 signatures through BoringSSL/OpenSSL;
- strict domain, role and enrollment binding for signed documents;
- public-key registry for verified local operation;
- one-time, TTL-bound pairing codes;
- per-installation enrollment generation, bearer token and signing key;
- authenticated heartbeat and assignment lookup;
- promotion gated by successful reports from required enrollments.

The HTTP process is still intentionally loopback-only. It can run with a
schema 1 public-key registry or with an explicit unsafe development override.
The unsafe flag replaces signature verification and must never be used for
QNAP.

Run tests:

```bash
PYTHONPATH=src pytest -q
PYTHONPATH=src python tests/e2e/verified_loopback.py
```

Run the local smoke server:

```bash
PYTHONPATH=src python -m profile_sync_server.http \
  --database .local/state.sqlite \
  --unsafe-accept-signatures
```

Run with verified signatures:

```bash
PYTHONPATH=src python -m profile_sync_server.http \
  --database .local/state.sqlite \
  --key-registry .local/key-registry.json
```

Create a short-lived pairing code from the host:

```bash
PYTHONPATH=src python -m profile_sync_server.admin \
  --database .local/state.sqlite \
  create-pairing \
  --logical-device-id sony-tv \
  --channel home-stable
```

Container builds target both `linux/amd64` and the QNAP-required
`linux/arm/v7`. The image is not a production release until it has passed the
device E2E and is referenced by immutable digest.

Remaining production blockers:

- protected admin API and persistent promoter key rotation;
- authenticated HTTPS deployment;
- signed promotion/checkpoint event persistence;
- content-addressed blob upload sessions and GC;
- multi-architecture image and real QNAP ARMv7 smoke.
