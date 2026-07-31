# kodi-profile-sync-server

Verified implementation of the mwoDevelop Kodi profile synchronization store
and HTTPS API.

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
- promotion gated by successful reports from required enrollments;
- TLS 1.2+ required for every non-loopback listener;
- online, integrity-checked, mode-0600 SQLite backups and offline restore.

The process can run on loopback for development. A non-loopback listener
requires a schema 1 public-key registry, explicit opt-in and a TLS certificate
plus key. The unsafe flag replaces signature verification and is rejected for
non-loopback operation.

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

Run a production-style TLS listener:

```bash
PYTHONPATH=src python -m profile_sync_server.http \
  --listen 0.0.0.0 --allow-non-loopback \
  --database .local/state.sqlite \
  --key-registry .local/key-registry.json \
  --tls-cert .local/tls/server.crt \
  --tls-key .local/tls/server.key
```

Create a short-lived pairing code from the host:

```bash
PYTHONPATH=src python -m profile_sync_server.admin \
  --database .local/state.sqlite \
  create-pairing \
  --logical-device-id sony-tv \
  --channel home-stable \
  --target-tag home \
  --target-tag android-tv:armeabi-v7a
```

Target tags are assigned by the administrator during one-time enrollment. They
are persisted with the enrollment and a signed candidate assignment must carry
the same set, so a client cannot select a more privileged profile layer by
self-reporting different tags.

Create an online-consistent backup while the service is running, or restore
one while the service is stopped and the target database is absent:

```bash
PYTHONPATH=src python -m profile_sync_server.admin \
  --database /data/state.sqlite backup \
  --output /data/backups/state-20260731.sqlite
PYTHONPATH=src python -m profile_sync_server.admin \
  --database /data/state.sqlite restore \
  --input /data/backups/state-20260731.sqlite
```

Container builds target both `linux/amd64` and the QNAP-required
`linux/arm/v7`. The image is not a production release until it has passed the
device E2E and is referenced by immutable digest.

Host-only administration remains deliberately outside the network API. Key
rotation is performed by atomically replacing the read-only registry and
restarting the container. Profile revisions are small signed JSON documents;
content-addressed blob upload is not required by the supported profile policy.
