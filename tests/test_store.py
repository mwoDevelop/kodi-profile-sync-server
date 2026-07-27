import hashlib

import pytest

from profile_sync_server.store import (
    Conflict,
    ProfileStore,
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
    }


def signed(kind, **values):
    return {"kind": kind, "signature": "test-signature", **values}


def store(tmp_path, verifier=lambda _kind, document: "signature" in document):
    return ProfileStore(tmp_path / "state.sqlite", verifier)


def test_revision_is_immutable_and_digest_verified(tmp_path):
    state = store(tmp_path)
    manifest = revision("one")

    assert state.put_revision(manifest)["revision_id"] == manifest["revision_id"]
    assert state.put_revision(manifest)["revision_id"] == manifest["revision_id"]
    damaged = dict(manifest)
    damaged["kodi_major"] = 22
    with pytest.raises(ValidationError, match="digest mismatch"):
        state.put_revision(damaged)


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

    with pytest.raises(ValidationError, match="assignment signature"):
        state.assign_candidate({}, "assign-0001")
    with pytest.raises(ValidationError, match="report signature"):
        state.record_report({}, "report-0001")
