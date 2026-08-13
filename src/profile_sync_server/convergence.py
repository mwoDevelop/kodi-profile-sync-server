"""Constrained release-intent and convergence-assignment contracts."""

from __future__ import annotations

import hashlib
import re
import time

from .store import canonical_json


HASH_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
CHANNEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ENROLLMENT = re.compile(r"^enr:[A-Za-z0-9._-]{8,128}$")
LOGICAL_DEVICE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NONCE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
TAG = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[A-Za-z0-9.+-]*)?$")
RESULTS = {
    "success",
    "failure",
    "observed",
    "drift_blocked",
    "external_dependency_failure",
    "client_upgrade_required",
    "restart_required",
}


class ConvergenceContractError(ValueError):
    pass


def content_id(document, id_field):
    if not isinstance(document, dict) or not isinstance(id_field, str):
        raise ConvergenceContractError("invalid content identity")
    identity = {
        key: value
        for key, value in document.items()
        if key not in {id_field, "signature"}
    }
    return "sha256:" + hashlib.sha256(canonical_json(identity)).hexdigest()


def _sorted_unique(values, pattern, field, limit=64, *, allow_empty=False):
    if (
        not isinstance(values, list)
        or (not allow_empty and not values)
        or len(values) > limit
        or values != sorted(set(values))
        or any(
            not isinstance(value, str) or not pattern.fullmatch(value)
            for value in values
        )
    ):
        raise ConvergenceContractError(f"invalid {field}")
    return values


def validate_release_intent(document, verify_signed_document, now=None):
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ConvergenceContractError("unsupported release intent schema")
    allowed = {
        "schema",
        "release_intent_id",
        "bundle_id",
        "channel",
        "assignment_key_id",
        "allowed_logical_devices",
        "max_assignments",
        "minimum_agent_version",
        "issued_at",
        "expires_at",
        "signature",
    }
    if set(document) != allowed:
        raise ConvergenceContractError("invalid release intent fields")
    if not verify_signed_document("release_intent", document):
        raise ConvergenceContractError("invalid release intent signature")
    intent_id = document.get("release_intent_id")
    if not isinstance(intent_id, str) or not HASH_ID.fullmatch(intent_id):
        raise ConvergenceContractError("invalid release intent id")
    if intent_id != content_id(document, "release_intent_id"):
        raise ConvergenceContractError("release intent digest mismatch")
    if not HASH_ID.fullmatch(str(document.get("bundle_id", ""))):
        raise ConvergenceContractError("invalid release intent bundle")
    if not CHANNEL.fullmatch(str(document.get("channel", ""))):
        raise ConvergenceContractError("invalid release intent channel")
    if not KEY_ID.fullmatch(str(document.get("assignment_key_id", ""))):
        raise ConvergenceContractError("invalid delegated assignment key")
    devices = _sorted_unique(
        document.get("allowed_logical_devices"),
        LOGICAL_DEVICE,
        "allowed logical devices",
    )
    maximum = document.get("max_assignments")
    if not isinstance(maximum, int) or maximum < len(devices) or maximum > 256:
        raise ConvergenceContractError("invalid maximum assignments")
    if not VERSION.fullmatch(str(document.get("minimum_agent_version", ""))):
        raise ConvergenceContractError("invalid minimum agent version")
    issued_at = document.get("issued_at")
    expires_at = document.get("expires_at")
    if (
        not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or expires_at - issued_at > 30 * 24 * 60 * 60
    ):
        raise ConvergenceContractError("invalid release intent validity")
    now = int(time.time()) if now is None else int(now)
    if issued_at > now + 300 or expires_at < now:
        raise ConvergenceContractError("release intent is not currently valid")
    return {
        "release_intent_id": intent_id,
        "bundle_id": document["bundle_id"],
        "channel": document["channel"],
        "assignment_key_id": document["assignment_key_id"],
        "allowed_logical_devices": devices,
        "max_assignments": maximum,
        "minimum_agent_version": document["minimum_agent_version"],
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def validate_convergence_assignment(
    document, verify_signed_document, enrollment, now=None
):
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ConvergenceContractError("unsupported convergence assignment schema")
    allowed = {
        "schema",
        "assignment_id",
        "release_intent",
        "bundle_id",
        "enrollment_id",
        "enrollment_generation",
        "logical_device_id",
        "channel",
        "target_tags",
        "rollout_id",
        "wave_id",
        "apply_policy",
        "nonce",
        "issued_at",
        "expires_at",
        "signature",
    }
    if set(document) != allowed:
        raise ConvergenceContractError("invalid convergence assignment fields")
    if not verify_signed_document("convergence_assignment", document):
        raise ConvergenceContractError("invalid convergence assignment signature")
    intent = validate_release_intent(
        document.get("release_intent"), verify_signed_document, now=now
    )
    signature = document.get("signature")
    if (
        not isinstance(signature, dict)
        or signature.get("key_id") != intent["assignment_key_id"]
    ):
        raise ConvergenceContractError("assignment is not signed by delegated key")
    assignment_id = document.get("assignment_id")
    if not isinstance(assignment_id, str) or not HASH_ID.fullmatch(assignment_id):
        raise ConvergenceContractError("invalid convergence assignment id")
    if assignment_id != content_id(document, "assignment_id"):
        raise ConvergenceContractError("convergence assignment digest mismatch")
    if document.get("bundle_id") != intent["bundle_id"]:
        raise ConvergenceContractError("assignment bundle exceeds release intent")
    if document.get("channel") != intent["channel"]:
        raise ConvergenceContractError("assignment channel exceeds release intent")
    required_enrollment = {
        "enrollment_id": document.get("enrollment_id"),
        "generation": document.get("enrollment_generation"),
        "logical_device_id": document.get("logical_device_id"),
        "channel": document.get("channel"),
    }
    if (
        not isinstance(enrollment, dict)
        or enrollment.get("revoked")
        or any(
            enrollment.get(key) != value for key, value in required_enrollment.items()
        )
        or not ENROLLMENT.fullmatch(str(required_enrollment["enrollment_id"] or ""))
        or not isinstance(required_enrollment["generation"], int)
        or required_enrollment["generation"] < 1
        or not LOGICAL_DEVICE.fullmatch(
            str(required_enrollment["logical_device_id"] or "")
        )
    ):
        raise ConvergenceContractError("assignment enrollment is not eligible")
    if document["logical_device_id"] not in intent["allowed_logical_devices"]:
        raise ConvergenceContractError("assignment device exceeds release intent")
    tags = _sorted_unique(
        document.get("target_tags"), TAG, "assignment target tags", allow_empty=True
    )
    if tags != enrollment.get("target_tags", []):
        raise ConvergenceContractError("assignment target tags differ from enrollment")
    if not RUN_ID.fullmatch(str(document.get("rollout_id", ""))):
        raise ConvergenceContractError("invalid rollout id")
    wave_id = document.get("wave_id")
    if not isinstance(wave_id, int) or wave_id < 0 or wave_id > 1024:
        raise ConvergenceContractError("invalid wave id")
    if document.get("apply_policy") not in {"observe", "enforce"}:
        raise ConvergenceContractError("invalid convergence apply policy")
    if not NONCE.fullmatch(str(document.get("nonce", ""))):
        raise ConvergenceContractError("invalid convergence assignment nonce")
    issued_at = document.get("issued_at")
    expires_at = document.get("expires_at")
    now = int(time.time()) if now is None else int(now)
    if (
        not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or expires_at - issued_at > 24 * 60 * 60
        or issued_at > now + 300
        or expires_at < now
        or issued_at < intent["issued_at"]
        or expires_at > intent["expires_at"]
    ):
        raise ConvergenceContractError("invalid convergence assignment validity")
    return {
        "assignment_id": assignment_id,
        "release_intent_id": intent["release_intent_id"],
        "bundle_id": intent["bundle_id"],
        "enrollment_id": document["enrollment_id"],
        "enrollment_generation": document["enrollment_generation"],
        "logical_device_id": document["logical_device_id"],
        "channel": document["channel"],
        "target_tags": tags,
        "rollout_id": document["rollout_id"],
        "wave_id": wave_id,
        "apply_policy": document["apply_policy"],
        "expires_at": expires_at,
    }


def validate_convergence_report(document, assignment, verify_device_report):
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ConvergenceContractError("unsupported convergence report schema")
    if set(document) != {
        "schema",
        "assignment_id",
        "bundle_id",
        "enrollment_id",
        "enrollment_generation",
        "rollout_id",
        "wave_id",
        "result",
        "observed_at",
        "code_state",
        "profile_state",
        "secret_state",
        "signature",
    }:
        raise ConvergenceContractError("invalid convergence report fields")
    if not verify_device_report("convergence_report", document):
        raise ConvergenceContractError("invalid convergence report signature")
    expected = {
        key: assignment[key]
        for key in (
            "assignment_id",
            "bundle_id",
            "enrollment_id",
            "enrollment_generation",
            "rollout_id",
            "wave_id",
        )
    }
    if any(document.get(key) != value for key, value in expected.items()):
        raise ConvergenceContractError("report does not match convergence assignment")
    if document.get("result") not in RESULTS:
        raise ConvergenceContractError("invalid convergence report result")
    if not isinstance(document.get("observed_at"), int) or document["observed_at"] < 0:
        raise ConvergenceContractError("invalid convergence report time")
    for field in ("code_state", "profile_state", "secret_state"):
        if document.get(field) not in {
            "unchanged",
            "changed",
            "failed",
            "not_applicable",
        }:
            raise ConvergenceContractError(f"invalid {field}")
    return {**expected, "result": document["result"]}
