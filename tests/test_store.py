import hashlib
import os
import sqlite3

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
    assert restored.readiness()["database_schema"] == 2

    with pytest.raises(Conflict, match="restore target already exists"):
        ProfileStore.restore_backup(backup, target_path)

    corrupt = tmp_path / "corrupt.sqlite"
    corrupt.write_bytes(b"not a sqlite database")
    with pytest.raises(ValidationError, match="backup is not a valid SQLite"):
        ProfileStore.restore_backup(corrupt, tmp_path / "bad.sqlite")


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
