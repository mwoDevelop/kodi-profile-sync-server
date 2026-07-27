#!/usr/bin/env python3
"""Verified-signature loopback E2E for the profile sync server."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from profile_sync_server.crypto import (
    native_ed25519,
    public_key_record,
    sign_document,
)
from profile_sync_server.store import ProfileStore, canonical_json


CHANNEL = "home-stable"
REVISION_SEED = bytes.fromhex("11" * 32)
PROMOTER_SEED = bytes.fromhex("22" * 32)
BLUE_SEED = bytes.fromhex("33" * 32)
SONY_SEED = bytes.fromhex("44" * 32)
PAIRED_SEED = bytes.fromhex("55" * 32)
BLUE = "enr:bluestacks-consumer"
SONY = "enr:sony-consumer"


def request(
    base,
    method,
    path,
    document=None,
    idempotency_key=None,
    access_token=None,
):
    payload = None
    headers = {}
    if document is not None:
        payload = canonical_json(document)
        headers["Content-Type"] = "application/json"
    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key
    if access_token is not None:
        headers["Authorization"] = "Bearer " + access_token
    operation = urllib.request.Request(
        base + path, data=payload, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(operation, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def wait_ready(base, process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("verified loopback server exited early")
        try:
            status, document = request(base, "GET", "/health")
            if status == 200:
                return document
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise TimeoutError("verified loopback server did not become ready")


def main():
    repository = Path(__file__).resolve().parents[2]
    backend = native_ed25519()
    with tempfile.TemporaryDirectory(
        prefix="mwo-profile-sync-server-e2e-"
    ) as temporary:
        root = Path(temporary)
        registry = {
            "schema": 1,
            "keys": {
                "publisher-1": public_key_record(
                    REVISION_SEED, ["revision"], backend=backend
                ),
                "promoter-1": public_key_record(
                    PROMOTER_SEED,
                    ["assignment", "promotion"],
                    backend=backend,
                ),
                "blue-key": public_key_record(
                    BLUE_SEED,
                    ["report"],
                    enrollment_id=BLUE,
                    backend=backend,
                ),
                "sony-key": public_key_record(
                    SONY_SEED,
                    ["report"],
                    enrollment_id=SONY,
                    backend=backend,
                ),
            },
        }
        registry_path = root / "key-registry.json"
        registry_path.write_bytes(canonical_json(registry))
        registry_path.chmod(0o600)
        database_path = root / "state.sqlite"
        provisioning = ProfileStore(
            database_path,
            verify_signed_document=lambda _kind, _document: False,
        )
        provisioning.create_pairing_code(
            "paired-readonly",
            CHANNEL,
            code="87654321",
            ttl_seconds=300,
        )
        port = 18766
        base = "http://127.0.0.1:%d" % port
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(repository / "src")
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "profile_sync_server.http",
                "--database",
                str(database_path),
                "--port",
                str(port),
                "--key-registry",
                str(registry_path),
            ],
            cwd=repository,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            health = wait_ready(base, process)
            if health != {"mode": "verified-loopback", "status": "ok"}:
                raise RuntimeError("server did not enter verified mode")
            paired_public = public_key_record(
                PAIRED_SEED, ["report"], backend=backend
            )["public_key"]
            status, paired = request(
                base,
                "POST",
                "/v1/pair",
                {
                    "code": "87654321",
                    "logical_device_id": "paired-readonly",
                    "channel": CHANNEL,
                    "key_id": "paired-readonly-key",
                    "public_key": paired_public,
                },
            )
            if status != 200 or paired.get("enrollment_generation") != 1:
                raise RuntimeError("one-time pairing failed")
            status, heartbeat = request(
                base,
                "POST",
                "/v1/devices/heartbeat",
                {
                    "enrollment_id": paired["enrollment_id"],
                    "logical_device_id": "paired-readonly",
                    "enrollment_generation": 1,
                    "channel": CHANNEL,
                },
                access_token=paired["access_token"],
            )
            if status != 200 or heartbeat.get("status") != "ok":
                raise RuntimeError("authenticated heartbeat failed")

            identity = {
                "schema": 2,
                "policy_sha256": "a" * 64,
                "kodi_major": 21,
                "adapters": {},
            }
            revision = {
                **identity,
                "revision_id": "sha256:"
                + hashlib.sha256(canonical_json(identity)).hexdigest(),
            }
            revision = sign_document(
                "revision",
                revision,
                "publisher-1",
                REVISION_SEED,
                backend=backend,
            )
            status, _ = request(
                base, "POST", "/v1/revisions", revision
            )
            if status != 200:
                raise RuntimeError("signed revision was rejected")
            status, downloaded = request(
                base,
                "GET",
                "/v1/enrollments/%s/revisions/%s"
                % (paired["enrollment_id"], revision["revision_id"]),
                access_token=paired["access_token"],
            )
            if status != 200 or downloaded != revision:
                raise RuntimeError("authenticated revision download failed")
            status, _ = request(
                base,
                "POST",
                "/v1/channels/%s/candidates" % CHANNEL,
                {
                    "revision_id": revision["revision_id"],
                    "base_revision": None,
                    "expected_candidate_head": None,
                },
                "publish-e2e-0001",
            )
            if status != 200:
                raise RuntimeError("candidate publish failed")

            invalid_assignment = sign_document(
                "assignment",
                {
                    "enrollment_id": BLUE,
                    "channel": CHANNEL,
                    "revision_id": revision["revision_id"],
                },
                "promoter-1",
                PROMOTER_SEED,
                backend=backend,
            )
            invalid_assignment["revision_id"] = "sha256:" + "b" * 64
            status, _ = request(
                base,
                "POST",
                "/v1/channels/%s/assignments" % CHANNEL,
                invalid_assignment,
                "assign-invalid-e2e",
            )
            if status != 400:
                raise RuntimeError("tampered assignment was not rejected")

            assignments = (
                (BLUE, BLUE_SEED, "blue-key"),
                (SONY, SONY_SEED, "sony-key"),
            )
            for index, (enrollment, _seed, _key_id) in enumerate(
                assignments, 1
            ):
                assignment = sign_document(
                    "assignment",
                    {
                        "enrollment_id": enrollment,
                        "channel": CHANNEL,
                        "revision_id": revision["revision_id"],
                    },
                    "promoter-1",
                    PROMOTER_SEED,
                    backend=backend,
                )
                status, _ = request(
                    base,
                    "POST",
                    "/v1/channels/%s/assignments" % CHANNEL,
                    assignment,
                    "assign-e2e-%04d" % index,
                )
                if status != 200:
                    raise RuntimeError("signed assignment failed")

            for index, (enrollment, seed, key_id) in enumerate(
                assignments, 1
            ):
                report = sign_document(
                    "report",
                    {
                        "enrollment_id": enrollment,
                        "channel": CHANNEL,
                        "revision_id": revision["revision_id"],
                        "result": "success",
                    },
                    key_id,
                    seed,
                    backend=backend,
                )
                status, _ = request(
                    base,
                    "POST",
                    "/v1/reports",
                    report,
                    "report-e2e-%04d" % index,
                )
                if status != 200:
                    raise RuntimeError("signed report failed")

            event = sign_document(
                "promotion",
                {
                    "channel": CHANNEL,
                    "revision_id": revision["revision_id"],
                    "generation": 1,
                },
                "promoter-1",
                PROMOTER_SEED,
                backend=backend,
            )
            status, promoted = request(
                base,
                "POST",
                "/v1/channels/%s/promote" % CHANNEL,
                {
                    "candidate_revision": revision["revision_id"],
                    "expected_active_revision": None,
                    "required_enrollments": [BLUE, SONY],
                    "event": event,
                },
                "promote-e2e-0001",
            )
            if status != 200 or promoted.get("generation") != 1:
                raise RuntimeError("verified promotion failed")
            status, active = request(
                base,
                "GET",
                "/v1/enrollments/%s/assignment?channel=%s"
                % (paired["enrollment_id"], CHANNEL),
                access_token=paired["access_token"],
            )
            if (
                status != 200
                or active.get("assignment_kind") != "active"
                or active.get("revision_id") != revision["revision_id"]
            ):
                raise RuntimeError("active assignment lookup failed")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.returncode not in (0, -15):
                error = process.stderr.read().strip()
                raise RuntimeError(
                    "verified loopback server failed: %s" % error[-500:]
                )
        print(
            json.dumps(
                {
                    "schema": 1,
                    "crypto_backend": backend.name,
                    "tamper_rejection": "pass",
                    "signed_revision": "pass",
                    "signed_canary_reports": 2,
                    "signed_promotion": "pass",
                    "one_time_pairing": "pass",
                    "authenticated_heartbeat": "pass",
                    "authenticated_revision_download": "pass",
                    "authenticated_assignment": "pass",
                    "result": "pass",
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
