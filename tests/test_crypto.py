import copy

from profile_sync_server.crypto import (
    SignedDocumentVerifier,
    native_ed25519,
    public_key_record,
    sign_document,
)


RFC8032_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4449c5697b326919703bac031cae7f60"
)
RFC8032_PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a"
    "0ee172f3daa62325af021a68f707511a"
)
RFC8032_SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a"
    "84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46b"
    "d25bf5f0595bbe24655141438e7a100b"
)


def test_native_backend_matches_rfc8032_and_rejects_tamper():
    backend = native_ed25519()

    assert backend.public_from_seed(RFC8032_SEED) == RFC8032_PUBLIC_KEY
    assert backend.sign(RFC8032_SEED, b"") == RFC8032_SIGNATURE
    assert backend.verify(RFC8032_PUBLIC_KEY, b"", RFC8032_SIGNATURE)
    tampered = bytearray(RFC8032_SIGNATURE)
    tampered[0] ^= 1
    assert not backend.verify(
        RFC8032_PUBLIC_KEY, b"", bytes(tampered)
    )


def test_signed_document_is_domain_and_role_bound():
    backend = native_ed25519()
    verifier = SignedDocumentVerifier(
        {
            "promoter-1": public_key_record(
                RFC8032_SEED,
                ["assignment", "promotion"],
                backend=backend,
            )
        },
        backend=backend,
    )
    document = sign_document(
        "assignment",
        {
            "channel": "home-stable",
            "enrollment_id": "enr:consumer-0001",
            "revision_id": "sha256:" + "a" * 64,
        },
        "promoter-1",
        RFC8032_SEED,
        backend=backend,
    )

    assert verifier("assignment", document)
    assert not verifier("promotion", document)
    tampered = copy.deepcopy(document)
    tampered["revision_id"] = "sha256:" + "b" * 64
    assert not verifier("assignment", tampered)


def test_report_key_is_bound_to_exact_enrollment():
    backend = native_ed25519()
    verifier = SignedDocumentVerifier(
        {
            "device-key-1": public_key_record(
                RFC8032_SEED,
                ["report"],
                enrollment_id="enr:consumer-0001",
                backend=backend,
            )
        },
        backend=backend,
    )
    report = sign_document(
        "report",
        {
            "channel": "home-stable",
            "enrollment_id": "enr:consumer-0001",
            "revision_id": "sha256:" + "a" * 64,
            "result": "success",
        },
        "device-key-1",
        RFC8032_SEED,
        backend=backend,
    )

    assert verifier("report", report)
    forged_identity = copy.deepcopy(report)
    forged_identity["enrollment_id"] = "enr:consumer-0002"
    assert not verifier("report", forged_identity)
