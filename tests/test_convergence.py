import copy

import pytest

from profile_sync_server.convergence import (
    ConvergenceContractError,
    content_id,
    validate_convergence_assignment,
    validate_convergence_report,
    validate_release_intent,
)
from profile_sync_server.crypto import (
    SignedDocumentVerifier,
    native_ed25519,
    public_key_record,
    sign_document,
)


PROMOTER_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
ASSIGNMENT_SEED = b"a" * 32
DEVICE_SEED = b"d" * 32
NOW = 2_000_000_000


def digest(character):
    return "sha256:" + character * 64


def verifier():
    backend = native_ed25519()
    return SignedDocumentVerifier(
        {
            "offline-promoter-1": public_key_record(
                PROMOTER_SEED, ["release_intent"], backend=backend
            ),
            "qnap-assignment-1": public_key_record(
                ASSIGNMENT_SEED, ["convergence_assignment"], backend=backend
            ),
        },
        backend=backend,
    )


def signed_intent():
    identity = {
        "schema": 1,
        "bundle_id": digest("b"),
        "channel": "stable",
        "assignment_key_id": "qnap-assignment-1",
        "allowed_logical_devices": ["bluestacks1", "x88pro20"],
        "max_assignments": 2,
        "minimum_agent_version": "1.1.0",
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
    }
    identity["release_intent_id"] = content_id(identity, "release_intent_id")
    return sign_document(
        "release_intent",
        identity,
        "offline-promoter-1",
        PROMOTER_SEED,
    )


def enrollment():
    return {
        "enrollment_id": "enr:bluestacks-0001",
        "logical_device_id": "bluestacks1",
        "generation": 3,
        "channel": "stable",
        "target_tags": ["android:bluestacks", "canary:primary"],
        "revoked": 0,
    }


def signed_assignment():
    identity = {
        "schema": 1,
        "release_intent": signed_intent(),
        "bundle_id": digest("b"),
        "enrollment_id": "enr:bluestacks-0001",
        "enrollment_generation": 3,
        "logical_device_id": "bluestacks1",
        "channel": "stable",
        "target_tags": ["android:bluestacks", "canary:primary"],
        "rollout_id": "rollout:00000001",
        "wave_id": 0,
        "apply_policy": "observe",
        "nonce": "nonce:000000000001",
        "issued_at": NOW,
        "expires_at": NOW + 1800,
    }
    identity["assignment_id"] = content_id(identity, "assignment_id")
    return sign_document(
        "convergence_assignment",
        identity,
        "qnap-assignment-1",
        ASSIGNMENT_SEED,
    )


def test_release_intent_and_assignment_are_signature_digest_and_scope_bound():
    verify = verifier()
    intent = validate_release_intent(signed_intent(), verify, now=NOW)
    assignment = validate_convergence_assignment(
        signed_assignment(), verify, enrollment(), now=NOW
    )

    assert intent["bundle_id"] == digest("b")
    assert assignment["release_intent_id"] == intent["release_intent_id"]
    assert assignment["logical_device_id"] == "bluestacks1"
    assert assignment["apply_policy"] == "observe"


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda item: item.update(bundle_id=digest("c")), "signature"),
        (
            lambda item: item["release_intent"].update(
                allowed_logical_devices=["x88pro20"]
            ),
            "signature",
        ),
        (
            lambda item: item["signature"].update(key_id="offline-promoter-1"),
            "signature",
        ),
        (lambda item: item.update(expires_at=NOW + 7200), "signature"),
    ),
)
def test_assignment_rejects_tampering_before_scope_evaluation(mutation, message):
    document = signed_assignment()
    mutation(document)

    with pytest.raises(ConvergenceContractError, match=message):
        validate_convergence_assignment(document, verifier(), enrollment(), now=NOW)


def test_valid_signature_cannot_exceed_intent_device_or_time_scope():
    intent = signed_intent()
    identity = {
        key: value for key, value in signed_assignment().items() if key != "signature"
    }
    identity["release_intent"] = intent
    identity["logical_device_id"] = "sony-tv"
    identity["enrollment_id"] = "enr:sony-tv-0001"
    identity["assignment_id"] = content_id(identity, "assignment_id")
    document = sign_document(
        "convergence_assignment",
        identity,
        "qnap-assignment-1",
        ASSIGNMENT_SEED,
    )
    sony = {
        **enrollment(),
        "logical_device_id": "sony-tv",
        "enrollment_id": "enr:sony-tv-0001",
    }

    with pytest.raises(ConvergenceContractError, match="exceeds release intent"):
        validate_convergence_assignment(document, verifier(), sony, now=NOW)

    expired = signed_assignment()
    with pytest.raises(ConvergenceContractError, match="not currently valid"):
        validate_convergence_assignment(
            expired, verifier(), enrollment(), now=NOW + 4000
        )


def test_convergence_report_is_device_signed_and_exact_assignment_bound():
    assignment = validate_convergence_assignment(
        signed_assignment(), verifier(), enrollment(), now=NOW
    )
    backend = native_ed25519()
    device_verifier = SignedDocumentVerifier(
        {
            "device-key-1": public_key_record(
                DEVICE_SEED,
                ["convergence_report"],
                enrollment_id=assignment["enrollment_id"],
                backend=backend,
            )
        },
        backend=backend,
    )
    report = sign_document(
        "convergence_report",
        {
            "schema": 1,
            **{
                key: assignment[key]
                for key in (
                    "assignment_id",
                    "bundle_id",
                    "enrollment_id",
                    "enrollment_generation",
                    "rollout_id",
                    "wave_id",
                )
            },
            "result": "observed",
            "observed_at": NOW + 1,
            "code_state": "unchanged",
            "profile_state": "unchanged",
            "secret_state": "not_applicable",
        },
        "device-key-1",
        DEVICE_SEED,
        backend=backend,
    )

    assert (
        validate_convergence_report(report, assignment, device_verifier)["result"]
        == "observed"
    )
    replay = copy.deepcopy(report)
    replay["bundle_id"] = digest("c")
    with pytest.raises(ConvergenceContractError, match="signature"):
        validate_convergence_report(replay, assignment, device_verifier)
