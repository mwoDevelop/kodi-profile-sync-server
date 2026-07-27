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
- signed-document verification boundary;
- promotion gated by successful reports from required enrollments.

The HTTP process is intentionally development-only. It refuses non-loopback
listeners and refuses to start unless `--unsafe-accept-signatures` is passed.
This flag replaces signature verification and must never be used for QNAP.

Run tests:

```bash
PYTHONPATH=src pytest -q
```

Run the local smoke server:

```bash
PYTHONPATH=src python -m profile_sync_server.http \
  --database .local/state.sqlite \
  --unsafe-accept-signatures
```

Production blockers:

- qualified enrollment signing/verifying implementation on Kodi ARMv7/x86;
- pairing, key registry and revocation;
- authenticated HTTPS deployment;
- signed promotion/checkpoint event persistence;
- content-addressed blob upload sessions and GC;
- multi-architecture image and real QNAP ARMv7 smoke.
