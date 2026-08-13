import hashlib
import os
import shutil
import sqlite3
import time

import pytest

from profile_sync_server.crypto import (
    native_ed25519,
    public_key_record,
    sign_document,
)
from profile_sync_server.store import (
    Conflict,
    ProfileStore,
    Unauthorized,
    ValidationError,
    canonical_json,
)


CHANNEL = "home-stable"
BLUE = "enr:bluestacks-consumer"
SONY = "enr:sony-consumer"


def revision(value):
    identity = {
        "schema": 2,
        "policy_sha256": "a" * 64,
        "kodi_major": 21,
        "adapters": {
            "test": {
                "adapter": "settings_xml",
                "apply_mode": "hot_apply",
                "managed_settings": ["value"],
                "values": {"value": value},
            }
        },
    }
    return {
        **identity,
        "revision_id": "sha256:"
        + hashlib.sha256(canonical_json(identity)).hexdigest(),
        "signature": "test-signature",
    }


def layered_revision():
    identity = {
        "schema": 3,
        "policy_sha256": "b" * 64,
        "kodi_major": 21,
        "base": {"adapters": {}},
        "layers": [
            {
                "id": "android-tv",
                "selector": {
                    "all_target_tags": ["android-tv:armeabi-v7a"]
                },
                "adapters": {},
            }
        ],
    }
    return {
        **identity,
        "revision_id": "sha256:"
        + hashlib.sha256(canonical_json(identity)).hexdigest(),
        "signature": "test-signature",
    }


def signed(kind, **values):
    return {"kind": kind, "signature": "test-signature", **values}


def store(tmp_path, verifier=lambda _kind, document: "signature" in document):
    return ProfileStore(tmp_path / "state.sqlite", verifier)


def test_online_backup_is_atomic_private_and_integrity_checked(tmp_path):
    state = store(tmp_path)
    manifest = revision("backup")
    state.put_revision(manifest)

    destination = tmp_path / "backups" / "state.sqlite"
    result = state.backup(destination)

    assert result["bytes"] == destination.stat().st_size
    assert result["sha256"] == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert os.stat(destination).st_mode & 0o777 == 0o600
    with sqlite3.connect(destination) as database:
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert database.execute(
            "SELECT COUNT(*) FROM revisions"
        ).fetchone()[0] == 1

    with pytest.raises(Conflict, match="backup already exists"):
        state.backup(destination)


def test_restore_requires_valid_offline_backup_and_explicit_empty_target(tmp_path):
    source = store(tmp_path / "source")
    source.put_revision(revision("restore"))
    backup = tmp_path / "backup.sqlite"
    source.backup(backup)

    target_path = tmp_path / "restored" / "state.sqlite"
    result = ProfileStore.restore_backup(backup, target_path)
    assert result["sha256"] == hashlib.sha256(target_path.read_bytes()).hexdigest()
    restored = ProfileStore(target_path, lambda _kind, _document: True)
    assert restored.readiness()["database_schema"] == 4

    with pytest.raises(Conflict, match="restore target already exists"):
        ProfileStore.restore_backup(backup, target_path)

    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(b"not a sqlite database")
    with pytest.raises(ValidationError, match="backup is not a valid SQLite"):
        ProfileStore.restore_backup(corrupt, tmp_path / "bad.sqlite")


def assignment_v2(
    enrollment,
    enrollment_generation,
    revision_id,
    assignment_kind,
    channel_generation,
    target_tags=(),
    apply_policy="enforce",
    nonce="assignment-nonce-0001",
):
    now = int(time.time())
    identity = {
        "schema": 2,
        "enrollment_id": enrollment,
        "enrollment_generation": enrollment_generation,
        "channel": CHANNEL,
        "channel_generation": channel_generation,
        "revision_id": revision_id,
        "target_tags": sorted(target_tags),
        "assignment_kind": assignment_kind,
        "apply_policy": apply_policy,
        "nonce": nonce,
        "issued_at": now,
        "expires_at": now + 3600,
    }
    return {
        **identity,
        "assignment_id": "sha256:"
        + hashlib.sha256(canonical_json(identity)).hexdigest(),
        "signature": "test-signature",
    }

def test_revision_is_immutable_and_digest_verified(tmp_path):
    state = store(tmp_path)
    manifest = revision("one")

    assert state.put_revision(manifest)["revision_id"] == manifest["revision_id"]
    assert state.put_revision(manifest)["revision_id"] == manifest["revision_id"]
    damaged = dict(manifest)
    damaged["kodi_major"] = 22
    with pytest.raises(ValidationError, match="digest mismatch"):
        state.put_revision(damaged)

    schema_three = layered_revision()
    assert state.put_revision(schema_three)["revision_id"] == schema_three[
        "revision_id"
    ]


def test_candidate_cas_and_idempotency(tmp_path):
    state = store(tmp_path)
    candidate = revision("candidate")
    state.put_revision(candidate)

    first = state.publish_candidate(
        CHANNEL,
        candidate["revision_id"],
        None,
        None,
        "publish-0001",
    )
    retry = state.publish_candidate(
        CHANNEL,
        candidate["revision_id"],
        None,
        None,
        "publish-0001",
    )

    assert retry == first
    with pytest.raises(Conflict, match="candidate head changed"):
        state.publish_candidate(
            CHANNEL,
            candidate["revision_id"],
            None,
            None,
            "publish-0002",
        )


def test_admin_request_binds_role_operation_and_rejects_nonce_replay(tmp_path):
    state = store(tmp_path)
    document = {
        "schema": 1,
        "actor_role": "publish",
        "operation": "publish_candidate",
        "idempotency_key": "admin-publish-0001",
        "nonce": "admin-request-nonce-0001",
        "issued_at": 1000,
        "expires_at": 1120,
        "payload": {"revision_id": "sha256:" + "a" * 64},
        "signature": {
            "algorithm": "Ed25519",
            "key_id": "publisher-admin",
            "value": "test",
        },
    }

    assert state.authorize_admin_request(
        document,
        "publish_candidate",
        "admin-publish-0001",
        now=1050,
    ) == document["payload"]
    assert state.authorize_admin_request(
        document,
        "publish_candidate",
        "admin-publish-0001",
        now=1050,
    ) == document["payload"]

    replay = dict(document)
    replay["payload"] = {"revision_id": "sha256:" + "b" * 64}
    with pytest.raises(Conflict, match="nonce replayed"):
        state.authorize_admin_request(
            replay,
            "publish_candidate",
            "admin-publish-0001",
            now=1050,
        )
    with pytest.raises(Unauthorized, match="authorization"):
        state.authorize_admin_request(
            document, "promote", "admin-publish-0001", now=1050
        )


def test_promotion_requires_signed_success_from_every_canary(tmp_path):
    state = store(tmp_path)
    candidate = revision("candidate")
    state.put_revision(candidate)
    state.publish_candidate(
        CHANNEL,
        candidate["revision_id"],
        None,
        None,
        "publish-0001",
    )
    for index, enrollment in enumerate((BLUE, SONY), 1):
        assignment = signed(
            "assignment",
            enrollment_id=enrollment,
            channel=CHANNEL,
            revision_id=candidate["revision_id"],
        )
        state.assign_candidate(assignment, "assign-%04d" % index)
    state.record_report(
        signed(
            "report",
            enrollment_id=BLUE,
            channel=CHANNEL,
            revision_id=candidate["revision_id"],
            result="success",
        ),
        "report-0001",
    )

    event = signed("promotion", generation=1)
    with pytest.raises(Conflict, match="required canary"):
        state.promote(
            CHANNEL,
            candidate["revision_id"],
            None,
            [BLUE, SONY],
            event,
            "promote-0001",
        )

    state.record_report(
        signed(
            "report",
            enrollment_id=SONY,
            channel=CHANNEL,
            revision_id=candidate["revision_id"],
            result="success",
        ),
        "report-0002",
    )
    result = state.promote(
        CHANNEL,
        candidate["revision_id"],
        None,
        [BLUE, SONY],
        event,
        "promote-0002",
    )

    assert result["active_revision"] == candidate["revision_id"]
    assert result["generation"] == 1
    assert state.assignment(BLUE, CHANNEL) == {
        "revision_id": candidate["revision_id"],
        "assignment_kind": "active",
    }


def test_assignment_and_report_signatures_are_required(tmp_path):
    state = store(tmp_path, verifier=lambda _kind, _document: False)

    with pytest.raises(ValidationError, match="revision signature"):
        state.put_revision(revision("unsigned-for-verifier"))
    with pytest.raises(ValidationError, match="assignment signature"):
        state.assign_candidate({}, "assign-0001")
    with pytest.raises(ValidationError, match="report signature"):
        state.record_report({}, "report-0001")


def test_report_is_verified_against_enrollment_key_not_static_registry(
    tmp_path,
):
    backend = native_ed25519()
    seed = b"r" * 32
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: False,
    )
    state.create_pairing_code(
        "bluestacks1", CHANNEL, code="12345678", ttl_seconds=60
    )
    enrolled = state.pair(
        "12345678",
        "bluestacks1",
        CHANNEL,
        "device-report-key",
        public_key_record(seed, ["report"], backend=backend)["public_key"],
    )
    manifest = revision("dynamic-report")
    state.verify_signed_document = lambda _kind, _document: True
    state.put_revision(manifest)
    state.publish_candidate(
        CHANNEL, manifest["revision_id"], None, None, "publish-0001"
    )
    state.assign_candidate(
        signed(
            "assignment",
            enrollment_id=enrolled["enrollment_id"],
            channel=CHANNEL,
            revision_id=manifest["revision_id"],
            target_tags=[],
        ),
        "assign-0001",
    )
    report = sign_document(
        "report",
        {
            "enrollment_id": enrolled["enrollment_id"],
            "channel": CHANNEL,
            "revision_id": manifest["revision_id"],
            "result": "success",
        },
        "device-report-key",
        seed,
        backend=backend,
    )

    assert state.record_report(report, "report-0001")["result"] == "success"

    tampered = dict(report)
    tampered["result"] = "failure"
    with pytest.raises(ValidationError, match="report signature"):
        state.record_report(tampered, "report-0002")


def test_pairing_token_heartbeat_and_revocation(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
        bootstrap_keys={"promoter-1": {"allowed_kinds": ["assignment"]}},
    )
    manifest = revision("authenticated-download")
    state.put_revision(manifest)
    pairing = state.create_pairing_code(
        "sony-tv",
        CHANNEL,
        code="12345678",
        ttl_seconds=60,
        target_tags=["home", "android-tv:armeabi-v7a"],
    )
    assert pairing["code"] == "12345678"
    assert pairing["target_tags"] == [
        "android-tv:armeabi-v7a",
        "home",
    ]
    enrolled = state.pair(
        "12345678",
        "sony-tv",
        CHANNEL,
        "sony-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )

    assert enrolled["enrollment_generation"] == 1
    assert enrolled["target_tags"] == [
        "android-tv:armeabi-v7a",
        "home",
    ]
    assert enrolled["trust"] == {
        "promoter-1": {"allowed_kinds": ["assignment"]}
    }
    heartbeat = state.heartbeat(
        {
            "enrollment_id": enrolled["enrollment_id"],
            "logical_device_id": "sony-tv",
            "enrollment_generation": 1,
            "channel": CHANNEL,
        },
        enrolled["access_token"],
    )
    assert heartbeat["status"] == "ok"
    assert (
        state.revision(
            manifest["revision_id"],
            enrolled["enrollment_id"],
            enrolled["access_token"],
        )
        == manifest
    )
    with pytest.raises(Unauthorized, match="authentication failed"):
        state.revision(
            manifest["revision_id"],
            enrolled["enrollment_id"],
            "x" * 43,
        )
    with pytest.raises(Unauthorized, match="pairing rejected"):
        state.pair(
            "12345678",
            "sony-tv",
            CHANNEL,
            "other-key",
            "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
        )
    state.revoke_enrollment(enrolled["enrollment_id"])
    with pytest.raises(Unauthorized, match="authentication failed"):
        state.heartbeat(
            {
                "enrollment_id": enrolled["enrollment_id"],
                "logical_device_id": "sony-tv",
                "enrollment_generation": 1,
                "channel": CHANNEL,
            },
            enrolled["access_token"],
        )
    with pytest.raises(Unauthorized, match="authentication failed"):
        state.revision(
            manifest["revision_id"],
            enrolled["enrollment_id"],
            enrolled["access_token"],
        )


def test_heartbeat_persists_redacted_capability_snapshot(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    pairing = state.create_pairing_code(
        "x88-pro-20",
        CHANNEL,
        code="12345678",
        ttl_seconds=60,
        target_tags=["home", "android-tv:armeabi-v7a"],
    )
    enrolled = state.pair(
        pairing["code"],
        "x88-pro-20",
        CHANNEL,
        "x88-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )
    heartbeat_document = {
        "enrollment_id": enrolled["enrollment_id"],
        "logical_device_id": "x88-pro-20",
        "enrollment_generation": 1,
        "channel": CHANNEL,
        "client_version": "1.1.0",
        "client_capabilities": ["convergence:v1", "profile-sync:v3"],
        "platform": "android-tv/armeabi-v7a",
    }

    state.heartbeat(heartbeat_document, enrolled["access_token"])
    fleet = state.integration_fleet_snapshot(now=1234)

    assert fleet["schema"] == 1
    assert fleet["database_schema"] == 4
    assert fleet["generated_at"] == 1234
    assert fleet["devices"] == [
        {
            "enrollment_id": enrolled["enrollment_id"],
            "logical_device_id": "x88-pro-20",
            "enrollment_generation": 1,
            "channel": CHANNEL,
            "target_tags": ["android-tv:armeabi-v7a", "home"],
            "revoked": False,
            "created_at": fleet["devices"][0]["created_at"],
            "last_seen_at": fleet["devices"][0]["last_seen_at"],
            "client_version": "1.1.0",
            "client_capabilities": ["convergence:v1", "profile-sync:v3"],
            "platform": "android-tv/armeabi-v7a",
            "heartbeat_document_sha256": hashlib.sha256(
                canonical_json(heartbeat_document)
            ).hexdigest(),
        }
    ]
    serialized = str(fleet)
    assert enrolled["access_token"] not in serialized
    assert "public_key" not in serialized


def test_legacy_heartbeat_remains_compatible_and_clears_no_secrets(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    state.create_pairing_code(
        "legacy-device", CHANNEL, code="12345678", ttl_seconds=60
    )
    enrolled = state.pair(
        "12345678",
        "legacy-device",
        CHANNEL,
        "legacy-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )

    state.heartbeat(
        {
            "enrollment_id": enrolled["enrollment_id"],
            "logical_device_id": "legacy-device",
            "enrollment_generation": 1,
            "channel": CHANNEL,
        },
        enrolled["access_token"],
    )

    device = state.integration_fleet_snapshot()["devices"][0]
    assert device["client_version"] is None
    assert device["client_capabilities"] == []
    assert device["platform"] is None


def test_integration_rollout_snapshot_omits_signed_documents(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    manifest = revision("integration-rollout")
    state.put_revision(manifest)
    state.publish_candidate(
        CHANNEL,
        manifest["revision_id"],
        None,
        None,
        "publish-integration-rollout",
    )
    state.create_pairing_code(
        "bluestacks1", CHANNEL, code="12345678", ttl_seconds=60
    )
    enrolled = state.pair(
        "12345678",
        "bluestacks1",
        CHANNEL,
        "bluestacks-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )
    assignment = assignment_v2(
        enrolled["enrollment_id"],
        1,
        manifest["revision_id"],
        "candidate",
        0,
    )
    state.assign_candidate(assignment, "assign-integration-rollout")

    snapshot = state.integration_rollout_snapshot(now=4321)

    assert snapshot == {
        "schema": 1,
        "generated_at": 4321,
        "assignments": [
            {
                "assignment_id": assignment["assignment_id"],
                "assignment_kind": "candidate",
                "enrollment_id": enrolled["enrollment_id"],
                "logical_device_id": "bluestacks1",
                "enrollment_generation": 1,
                "channel": CHANNEL,
                "revision_id": manifest["revision_id"],
                "apply_policy": "enforce",
                "issued_at": assignment["issued_at"],
                "expires_at": assignment["expires_at"],
                "report_result": None,
            }
        ],
    }
    assert "signature" not in str(snapshot)


def test_assignment_target_tags_are_bound_to_enrollment(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    manifest = revision("targeted")
    state.put_revision(manifest)
    state.publish_candidate(
        CHANNEL,
        manifest["revision_id"],
        None,
        None,
        "publish-targeted",
    )
    state.create_pairing_code(
        "linux-consumer",
        CHANNEL,
        code="23456789",
        ttl_seconds=60,
        target_tags=["linux-flatpak:x86_64", "home"],
    )
    enrolled = state.pair(
        "23456789",
        "linux-consumer",
        CHANNEL,
        "linux-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )
    mismatched = signed(
        "assignment",
        enrollment_id=enrolled["enrollment_id"],
        channel=CHANNEL,
        revision_id=manifest["revision_id"],
        target_tags=["home"],
    )
    with pytest.raises(Conflict, match="target tags differ"):
        state.assign_candidate(mismatched, "assign-targeted-mismatch")

    assignment = signed(
        "assignment",
        enrollment_id=enrolled["enrollment_id"],
        channel=CHANNEL,
        revision_id=manifest["revision_id"],
        target_tags=["linux-flatpak:x86_64", "home"],
    )
    response = state.assign_candidate(assignment, "assign-targeted")

    assert response["target_tags"] == ["home", "linux-flatpak:x86_64"]
    assert state.assignment(
        enrolled["enrollment_id"],
        CHANNEL,
        enrolled["access_token"],
    ) == {
        "assignment_kind": "candidate",
        "document": assignment,
    }


def test_signed_active_bootstrap_is_exact_idempotent_and_reportable(tmp_path):
    device_seed = b"z" * 32
    device_public_key = public_key_record(
        device_seed, ["report"], enrollment_id="enr:placeholder"
    )["public_key"]
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    manifest = revision("active-bootstrap")
    state.put_revision(manifest)
    state.publish_candidate(
        CHANNEL, manifest["revision_id"], None, None, "publish-bootstrap"
    )
    state.promote(
        CHANNEL,
        manifest["revision_id"],
        None,
        [],
        signed("promotion", generation=1),
        "promote-bootstrap",
    )
    state.create_pairing_code(
        "linux-bootstrap",
        CHANNEL,
        code="34567890",
        ttl_seconds=60,
        target_tags=["linux-flatpak:x86_64", "home"],
    )
    enrolled = state.pair(
        "34567890",
        "linux-bootstrap",
        CHANNEL,
        "linux-bootstrap-key",
        device_public_key,
    )
    assignment = signed(
        "assignment",
        enrollment_id=enrolled["enrollment_id"],
        channel=CHANNEL,
        revision_id=manifest["revision_id"],
        target_tags=["home", "linux-flatpak:x86_64"],
    )

    first = state.bootstrap_active(CHANNEL, assignment, "bootstrap-0001")
    retry = state.bootstrap_active(CHANNEL, assignment, "bootstrap-0001")

    assert retry == first
    assert first["assignment_source"] == "active-bootstrap"
    assert state.assignment(
        enrolled["enrollment_id"], CHANNEL, enrolled["access_token"]
    ) == {"assignment_kind": "candidate", "document": assignment}
    report = sign_document(
        "report",
        {
            "enrollment_id": enrolled["enrollment_id"],
            "channel": CHANNEL,
            "revision_id": manifest["revision_id"],
            "result": "success",
        },
        "linux-bootstrap-key",
        device_seed,
    )
    assert state.record_report(report, "report-bootstrap")["result"] == "success"


def test_assignment_v2_promotes_signed_active_batch_and_keeps_both_reports(
    tmp_path,
):
    device_seed = b"v" * 32
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    manifest = revision("active-v2")
    state.put_revision(manifest)
    state.publish_candidate(
        CHANNEL, manifest["revision_id"], None, None, "publish-v2"
    )
    state.create_pairing_code(
        "active-v2-device",
        CHANNEL,
        code="56789012",
        ttl_seconds=60,
        target_tags=["home"],
    )
    enrolled = state.pair(
        "56789012",
        "active-v2-device",
        CHANNEL,
        "active-v2-key",
        public_key_record(device_seed, ["report"])["public_key"],
    )
    candidate = assignment_v2(
        enrolled["enrollment_id"],
        1,
        manifest["revision_id"],
        "candidate",
        0,
        ["home"],
        nonce="candidate-nonce-0001",
    )
    state.assign_candidate(candidate, "assign-v2-candidate")
    candidate_report_identity = {
        "assignment_id": candidate["assignment_id"],
        "assignment_kind": "candidate",
        "channel_generation": 0,
        "enrollment_generation": 1,
        "enrollment_id": enrolled["enrollment_id"],
        "channel": CHANNEL,
        "revision_id": manifest["revision_id"],
        "result": "success",
    }
    candidate_report = sign_document(
        "report",
        candidate_report_identity,
        "active-v2-key",
        device_seed,
    )
    state.record_report(candidate_report, "report-v2-candidate")

    active = assignment_v2(
        enrolled["enrollment_id"],
        1,
        manifest["revision_id"],
        "active",
        1,
        ["home"],
        nonce="active-batch-nonce-0001",
    )
    event = signed(
        "promotion",
        generation=1,
        active_assignment_ids=[active["assignment_id"]],
    )
    promoted = state.promote(
        CHANNEL,
        manifest["revision_id"],
        None,
        [enrolled["enrollment_id"]],
        event,
        "promote-v2",
        active_assignments=[active],
    )

    assert promoted["active_assignment_ids"] == [active["assignment_id"]]
    assert state.assignment(
        enrolled["enrollment_id"], CHANNEL, enrolled["access_token"]
    ) == {"assignment_kind": "active", "document": active}

    active_report = sign_document(
        "report",
        {
            "assignment_id": active["assignment_id"],
            "assignment_kind": "active",
            "channel_generation": 1,
            "enrollment_generation": 1,
            "enrollment_id": enrolled["enrollment_id"],
            "channel": CHANNEL,
            "revision_id": manifest["revision_id"],
            "result": "success",
        },
        "active-v2-key",
        device_seed,
    )
    state.record_report(active_report, "report-v2-active")
    with state.connect() as database:
        assert database.execute(
            "SELECT COUNT(*) FROM assignment_reports"
        ).fetchone()[0] == 2


def test_blob_is_content_addressed_and_reachable_only_from_assignment(tmp_path):
    payload = b"\x89PNG\r\n\x1a\nserver-blob"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    identity = {
        "schema": 2,
        "policy_sha256": "d" * 64,
        "kodi_major": 21,
        "adapters": {
            "kodi.favourites": {
                "adapter": "kodi_favourites_v1",
                "artwork": [
                    {
                        "sha256": digest,
                        "size": len(payload),
                        "media_type": "image/png",
                    }
                ],
            }
        },
    }
    manifest = {
        **identity,
        "revision_id": "sha256:"
        + hashlib.sha256(canonical_json(identity)).hexdigest(),
        "signature": "test-signature",
    }
    state = store(tmp_path)
    state.put_revision(manifest)
    state.put_blob(digest, payload, "image/png")
    assert state.put_blob(digest, payload, "image/png")["stored"] is False
    state.publish_candidate(
        CHANNEL, manifest["revision_id"], None, None, "publish-blob"
    )
    state.create_pairing_code(
        "blob-device",
        CHANNEL,
        code="67890123",
        ttl_seconds=60,
        target_tags=["home"],
    )
    enrolled = state.pair(
        "67890123",
        "blob-device",
        CHANNEL,
        "blob-device-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )
    assignment = assignment_v2(
        enrolled["enrollment_id"],
        1,
        manifest["revision_id"],
        "candidate",
        0,
        ["home"],
        nonce="blob-assignment-nonce-0001",
    )
    state.assign_candidate(assignment, "assign-blob")

    assert state.blob(
        digest, enrolled["enrollment_id"], enrolled["access_token"]
    ) == (payload, "image/png")
    other_payload = b"\x89PNG\r\n\x1a\nother"
    unrelated = "sha256:" + hashlib.sha256(other_payload).hexdigest()
    state.put_blob(unrelated, other_payload, "image/png")
    with pytest.raises(Unauthorized, match="not reachable"):
        state.blob(
            unrelated,
            enrolled["enrollment_id"],
            enrolled["access_token"],
        )

    epoch = tmp_path / "epoch"
    assert state.backup_epoch(epoch)["blob_count"] == 2
    restored_path = tmp_path / "restored-epoch" / "state.sqlite"
    assert ProfileStore.restore_epoch(epoch, restored_path)["blob_count"] == 2
    restored = ProfileStore(
        restored_path, verify_signed_document=lambda _kind, _document: True
    )
    assert restored.blob(
        digest, enrolled["enrollment_id"], enrolled["access_token"]
    ) == (payload, "image/png")

    damaged = tmp_path / "damaged-epoch"
    shutil.copytree(epoch, damaged)
    value = digest.split(":", 1)[1]
    (damaged / "blobs" / value[:2] / value).unlink()
    with pytest.raises(ValidationError, match="blob is missing"):
        ProfileStore.restore_epoch(
            damaged, tmp_path / "bad-restore" / "state.sqlite"
        )


def test_active_bootstrap_rejects_wrong_scope_tags_and_revocation(tmp_path):
    state = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )
    active = revision("active")
    stale = revision("stale")
    state.put_revision(active)
    state.put_revision(stale)
    state.publish_candidate(
        CHANNEL, active["revision_id"], None, None, "publish-active"
    )
    state.promote(
        CHANNEL,
        active["revision_id"],
        None,
        [],
        signed("promotion", generation=1),
        "promote-active",
    )
    state.create_pairing_code(
        "bootstrap-scope",
        CHANNEL,
        code="45678901",
        ttl_seconds=60,
        target_tags=["home"],
    )
    enrolled = state.pair(
        "45678901",
        "bootstrap-scope",
        CHANNEL,
        "bootstrap-scope-key",
        "dQW21pY0MyWT7V8Qt1OH1J__hnMZs5VZFcjFNjkt5oU",
    )

    def assignment(**changes):
        values = {
            "enrollment_id": enrolled["enrollment_id"],
            "channel": CHANNEL,
            "revision_id": active["revision_id"],
            "target_tags": ["home"],
        }
        values.update(changes)
        return signed("assignment", **values)

    with pytest.raises(Conflict, match="channel differs"):
        state.bootstrap_active("other-stable", assignment(), "bootstrap-channel")
    with pytest.raises(Conflict, match="active revision"):
        state.bootstrap_active(
            CHANNEL,
            assignment(revision_id=stale["revision_id"]),
            "bootstrap-stale",
        )
    with pytest.raises(Conflict, match="target tags differ"):
        state.bootstrap_active(
            CHANNEL, assignment(target_tags=[]), "bootstrap-tags"
        )
    state.revoke_enrollment(enrolled["enrollment_id"])
    with pytest.raises(Conflict, match="not eligible"):
        state.bootstrap_active(CHANNEL, assignment(), "bootstrap-revoked")


def test_existing_database_migrates_target_tag_columns(tmp_path):
    database_path = tmp_path / "state.sqlite"
    with sqlite3.connect(database_path) as database:
        database.executescript(
            """
            CREATE TABLE pairing_codes (
                code_sha256 TEXT PRIMARY KEY,
                logical_device_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                roles TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts_remaining INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE enrollments (
                enrollment_id TEXT PRIMARY KEY,
                logical_device_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                channel TEXT NOT NULL,
                roles TEXT NOT NULL,
                key_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                token_sha256 TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER,
                UNIQUE(logical_device_id, generation)
            );
            """
        )

    state = ProfileStore(
        database_path,
        verify_signed_document=lambda _kind, _document: True,
    )
    with state.connect() as database:
        for table in ("pairing_codes", "enrollments"):
            columns = {
                row["name"] for row in database.execute(f"PRAGMA table_info({table})")
            }
            assert "target_tags" in columns
