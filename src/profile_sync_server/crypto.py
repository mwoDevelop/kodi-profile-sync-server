"""Native Ed25519 and strict signed-document verification.

Kodi exposes either BoringSSL's direct ED25519 API or OpenSSL's EVP API from
its process. The server uses the same adapter contract and no pure-Python
cryptographic implementation.
"""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import json
import re
import ssl  # Load the process SSL backend before probing exported symbols.
from pathlib import Path

from .store import canonical_json


ALGORITHM = "Ed25519"
DOMAIN = b"mwo-profile-sync/signed-document/v1\0"
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
KINDS = {"assignment", "promotion", "report", "revision"}
SIGNATURE_FIELDS = {"algorithm", "key_id", "value"}


class CryptoUnavailable(RuntimeError):
    pass


class SignatureFormatError(ValueError):
    pass


def _buffer(payload):
    return (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)


def _message_buffer(payload):
    return _buffer(payload) if payload else None


def _b64url_encode(payload):
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _b64url_decode(value, expected_size):
    if not isinstance(value, str) or not value:
        raise SignatureFormatError("signature value must be a string")
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise SignatureFormatError("signature value is not canonical base64url")
    padding = "=" * (-len(value) % 4)
    try:
        payload = base64.b64decode(
            value + padding, altchars=b"-_", validate=True
        )
    except (ValueError, base64.binascii.Error) as error:
        raise SignatureFormatError("signature value is not base64url") from error
    if len(payload) != expected_size:
        raise SignatureFormatError("signature value has an invalid size")
    if _b64url_encode(payload) != value:
        raise SignatureFormatError("signature value is not canonical")
    return payload


def signed_payload(kind, document):
    if kind not in KINDS:
        raise SignatureFormatError("unsupported signed-document kind")
    if not isinstance(document, dict):
        raise SignatureFormatError("signed document must be an object")
    unsigned = {
        key: value for key, value in document.items() if key != "signature"
    }
    return DOMAIN + kind.encode("ascii") + b"\0" + canonical_json(unsigned)


class _BoringSSL:
    name = "boringssl-direct"

    def __init__(self, library):
        self.library = library
        library.ED25519_keypair_from_seed.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.ED25519_keypair_from_seed.restype = None
        library.ED25519_sign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        library.ED25519_sign.restype = ctypes.c_int
        library.ED25519_verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.ED25519_verify.restype = ctypes.c_int

    def public_from_seed(self, seed):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        public_key = (ctypes.c_ubyte * 32)()
        private_key = (ctypes.c_ubyte * 64)()
        try:
            self.library.ED25519_keypair_from_seed(
                public_key, private_key, _buffer(seed)
            )
            return bytes(public_key)
        finally:
            ctypes.memset(private_key, 0, len(private_key))

    def sign(self, seed, message):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        public_key = (ctypes.c_ubyte * 32)()
        private_key = (ctypes.c_ubyte * 64)()
        signature = (ctypes.c_ubyte * 64)()
        try:
            self.library.ED25519_keypair_from_seed(
                public_key, private_key, _buffer(seed)
            )
            if (
                self.library.ED25519_sign(
                    signature,
                    _message_buffer(message),
                    len(message),
                    private_key,
                )
                != 1
            ):
                raise CryptoUnavailable("BoringSSL ED25519_sign failed")
            return bytes(signature)
        finally:
            ctypes.memset(private_key, 0, len(private_key))

    def verify(self, public_key, message, signature):
        if len(public_key) != 32 or len(signature) != 64:
            return False
        return (
            self.library.ED25519_verify(
                _message_buffer(message),
                len(message),
                _buffer(signature),
                _buffer(public_key),
            )
            == 1
        )


class _OpenSSL:
    name = "openssl-evp"

    def __init__(self, library):
        self.library = library
        library.OBJ_sn2nid.argtypes = [ctypes.c_char_p]
        library.OBJ_sn2nid.restype = ctypes.c_int
        self.nid = library.OBJ_sn2nid(b"ED25519")
        if self.nid <= 0:
            raise CryptoUnavailable("OpenSSL has no Ed25519 object identifier")
        library.EVP_PKEY_new_raw_private_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_PKEY_new_raw_private_key.restype = ctypes.c_void_p
        library.EVP_PKEY_new_raw_public_key.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_PKEY_new_raw_public_key.restype = ctypes.c_void_p
        library.EVP_PKEY_get_raw_public_key.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        library.EVP_PKEY_get_raw_public_key.restype = ctypes.c_int
        library.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
        library.EVP_MD_CTX_new.restype = ctypes.c_void_p
        library.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]
        library.EVP_DigestSignInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.EVP_DigestSignInit.restype = ctypes.c_int
        library.EVP_DigestSign.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_DigestSign.restype = ctypes.c_int
        library.EVP_DigestVerifyInit.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.EVP_DigestVerifyInit.restype = ctypes.c_int
        library.EVP_DigestVerify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        library.EVP_DigestVerify.restype = ctypes.c_int

    def _private_key(self, seed):
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        key = self.library.EVP_PKEY_new_raw_private_key(
            self.nid, None, _buffer(seed), len(seed)
        )
        if not key:
            raise CryptoUnavailable("EVP_PKEY_new_raw_private_key failed")
        return key

    def public_from_seed(self, seed):
        key = self._private_key(seed)
        try:
            output = (ctypes.c_ubyte * 32)()
            output_size = ctypes.c_size_t(len(output))
            if (
                self.library.EVP_PKEY_get_raw_public_key(
                    key, output, ctypes.byref(output_size)
                )
                != 1
                or output_size.value != len(output)
            ):
                raise CryptoUnavailable("EVP_PKEY_get_raw_public_key failed")
            return bytes(output)
        finally:
            self.library.EVP_PKEY_free(key)

    def sign(self, seed, message):
        key = self._private_key(seed)
        context = self.library.EVP_MD_CTX_new()
        if not context:
            self.library.EVP_PKEY_free(key)
            raise CryptoUnavailable("EVP_MD_CTX_new failed")
        try:
            if (
                self.library.EVP_DigestSignInit(
                    context, None, None, None, key
                )
                != 1
            ):
                raise CryptoUnavailable("EVP_DigestSignInit failed")
            output = (ctypes.c_ubyte * 64)()
            output_size = ctypes.c_size_t(len(output))
            if (
                self.library.EVP_DigestSign(
                    context,
                    output,
                    ctypes.byref(output_size),
                    _message_buffer(message),
                    len(message),
                )
                != 1
                or output_size.value != len(output)
            ):
                raise CryptoUnavailable("EVP_DigestSign failed")
            return bytes(output)
        finally:
            self.library.EVP_MD_CTX_free(context)
            self.library.EVP_PKEY_free(key)

    def verify(self, public_key, message, signature):
        if len(public_key) != 32 or len(signature) != 64:
            return False
        key = self.library.EVP_PKEY_new_raw_public_key(
            self.nid, None, _buffer(public_key), len(public_key)
        )
        if not key:
            raise CryptoUnavailable("EVP_PKEY_new_raw_public_key failed")
        context = self.library.EVP_MD_CTX_new()
        if not context:
            self.library.EVP_PKEY_free(key)
            raise CryptoUnavailable("EVP_MD_CTX_new failed")
        try:
            if (
                self.library.EVP_DigestVerifyInit(
                    context, None, None, None, key
                )
                != 1
            ):
                raise CryptoUnavailable("EVP_DigestVerifyInit failed")
            return (
                self.library.EVP_DigestVerify(
                    context,
                    _buffer(signature),
                    len(signature),
                    _message_buffer(message),
                    len(message),
                )
                == 1
            )
        finally:
            self.library.EVP_MD_CTX_free(context)
            self.library.EVP_PKEY_free(key)


def native_ed25519():
    candidates = [
        ("process-global", ctypes.CDLL(None)),
        (ctypes.util.find_library("crypto"), None),
        ("libcrypto.so.3", None),
        ("libcrypto.so", None),
        ("/system/lib64/libcrypto.so", None),
        ("/system/lib/libcrypto.so", None),
    ]
    seen = set()
    for candidate, library in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if library is None:
            try:
                library = ctypes.CDLL(candidate)
            except OSError:
                continue
        if all(
            hasattr(library, symbol)
            for symbol in (
                "ED25519_keypair_from_seed",
                "ED25519_sign",
                "ED25519_verify",
            )
        ):
            return _BoringSSL(library)
        if all(
            hasattr(library, symbol)
            for symbol in (
                "OBJ_sn2nid",
                "EVP_PKEY_new_raw_private_key",
                "EVP_PKEY_new_raw_public_key",
            )
        ):
            return _OpenSSL(library)
    raise CryptoUnavailable("no accessible native Ed25519 implementation")


def sign_document(kind, document, key_id, seed, backend=None):
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise SignatureFormatError("invalid key id")
    backend = backend or native_ed25519()
    output = {key: value for key, value in document.items() if key != "signature"}
    signature = backend.sign(seed, signed_payload(kind, output))
    output["signature"] = {
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "value": _b64url_encode(signature),
    }
    return output


def decode_public_key(value):
    """Decode one canonical Ed25519 public key stored by enrollment."""
    return _b64url_decode(value, 32)


def verify_document_with_key(
    kind, document, expected_key_id, public_key, backend=None
):
    try:
        signature = document.get("signature")
        if not isinstance(signature, dict) or set(signature) != SIGNATURE_FIELDS:
            return False
        if (
            signature["algorithm"] != ALGORITHM
            or signature["key_id"] != expected_key_id
        ):
            return False
        value = _b64url_decode(signature["value"], 64)
        return (backend or native_ed25519()).verify(
            public_key, signed_payload(kind, document), value
        )
    except (AttributeError, SignatureFormatError, TypeError, ValueError):
        return False


class SignedDocumentVerifier:
    def __init__(self, keys, backend=None):
        if not isinstance(keys, dict):
            raise SignatureFormatError("key registry must be an object")
        self.backend = backend or native_ed25519()
        self.keys = {}
        for key_id, record in keys.items():
            if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
                raise SignatureFormatError("invalid registry key id")
            if not isinstance(record, dict) or set(record) not in (
                {"public_key", "allowed_kinds"},
                {"public_key", "allowed_kinds", "enrollment_id"},
            ):
                raise SignatureFormatError("invalid registry key record")
            kinds = record["allowed_kinds"]
            if (
                not isinstance(kinds, list)
                or not kinds
                or len(kinds) != len(set(kinds))
                or any(kind not in KINDS for kind in kinds)
            ):
                raise SignatureFormatError("invalid registry allowed kinds")
            enrollment_id = record.get("enrollment_id")
            if enrollment_id is not None and (
                not isinstance(enrollment_id, str) or not enrollment_id
            ):
                raise SignatureFormatError("invalid registry enrollment id")
            self.keys[key_id] = {
                "public_key": _b64url_decode(record["public_key"], 32),
                "allowed_kinds": frozenset(kinds),
                "enrollment_id": enrollment_id,
            }

    def public_bundle(self, allowed_kinds=None):
        allowed = set(allowed_kinds or KINDS)
        return {
            key_id: {
                "public_key": _b64url_encode(record["public_key"]),
                "allowed_kinds": sorted(
                    record["allowed_kinds"].intersection(allowed)
                ),
            }
            for key_id, record in self.keys.items()
            if record["allowed_kinds"].intersection(allowed)
            and record["enrollment_id"] is None
        }

    @classmethod
    def from_file(cls, path, backend=None):
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if (
            not isinstance(document, dict)
            or set(document) != {"schema", "keys"}
            or document["schema"] != 1
        ):
            raise SignatureFormatError("unsupported key registry")
        return cls(document["keys"], backend=backend)

    def __call__(self, kind, document):
        try:
            signature = document.get("signature")
            if not isinstance(signature, dict) or set(signature) != SIGNATURE_FIELDS:
                return False
            if signature["algorithm"] != ALGORITHM:
                return False
            key_id = signature["key_id"]
            if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
                return False
            record = self.keys.get(key_id)
            if record is None or kind not in record["allowed_kinds"]:
                return False
            if (
                record["enrollment_id"] is not None
                and document.get("enrollment_id") != record["enrollment_id"]
            ):
                return False
            return verify_document_with_key(
                kind,
                document,
                key_id,
                record["public_key"],
                backend=self.backend,
            )
        except (AttributeError, SignatureFormatError, TypeError, ValueError):
            return False


def public_key_record(seed, allowed_kinds, enrollment_id=None, backend=None):
    backend = backend or native_ed25519()
    record = {
        "public_key": _b64url_encode(backend.public_from_seed(seed)),
        "allowed_kinds": list(allowed_kinds),
    }
    if enrollment_id is not None:
        record["enrollment_id"] = enrollment_id
    return record
