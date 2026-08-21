"""Transactional SQLite state for immutable Kodi profile revisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from .metadata import DATABASE_SCHEMA_VERSION


CHANNEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REVISION = re.compile(r"^sha256:[a-f0-9]{64}$")
ENROLLMENT = re.compile(r"^enr:[A-Za-z0-9._-]{8,128}$")
LOGICAL_DEVICE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PAIRING_CODE = re.compile(r"^[0-9]{8}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TARGET_TAG = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
CLIENT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$")
PLATFORM = re.compile(r"^[a-z0-9][a-z0-9._:/+-]{0,127}$")
ASSIGNMENT_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
ROLES = {"read", "publish"}
ASSIGNMENT_KINDS = {"candidate", "active"}
APPLY_POLICIES = {"observe", "enforce"}
REPORT_RESULTS = {
    "success",
    "failure",
    "observed",
    "drift_blocked",
    "external_dependency_failure",
}
ADMIN_ROLE_OPERATIONS = {
    "publish": {
        "put_revision",
        "publish_candidate",
        "assign_candidate",
        "bootstrap_active",
        "put_blob",
    },
    "promote": {"promote"},
    "admin": {
        "put_revision",
        "publish_candidate",
        "assign_candidate",
        "bootstrap_active",
        "put_blob",
        "promote",
        "revoke_enrollment",
    },
}
BLOB_MEDIA_TYPES = {"image/jpeg", "image/png", "image/webp"}
MAX_BLOB_BYTES = 8 * 1024 * 1024
MAX_BLOB_STORE_BYTES = 512 * 1024 * 1024
MIN_BLOB_DISK_RESERVE = 64 * 1024 * 1024


class ValidationError(ValueError):
    pass


class Conflict(RuntimeError):
    pass


class NotFound(RuntimeError):
    pass


class Unauthorized(RuntimeError):
    pass


def canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def valid_blob_media(payload, media_type):
    if media_type == "image/png":
        return payload.startswith(b"\x89PNG\r\n\x1a\n")
    if media_type == "image/jpeg":
        return payload.startswith(b"\xff\xd8\xff") and payload.endswith(
            b"\xff\xd9"
        )
    if media_type == "image/webp":
        return (
            len(payload) >= 12
            and payload[:4] == b"RIFF"
            and payload[8:12] == b"WEBP"
        )
    return False


def revision_identity(manifest):
    return {
        key: value
        for key, value in manifest.items()
        if key not in {"revision_id", "created_utc", "signature"}
    }


def assignment_identity(document):
    return {
        key: value
        for key, value in document.items()
        if key not in {"assignment_id", "signature"}
    }


def validate_assignment_v2(
    document, expected_kind=None, now=None, validate_time=True
):
    if not isinstance(document, dict) or document.get("schema") != 2:
        raise ValidationError("unsupported assignment schema")
    assignment_id = document.get("assignment_id")
    if not isinstance(assignment_id, str) or not ASSIGNMENT_ID.fullmatch(
        assignment_id
    ):
        raise ValidationError("invalid assignment id")
    expected_id = "sha256:" + hashlib.sha256(
        canonical_json(assignment_identity(document))
    ).hexdigest()
    if assignment_id != expected_id:
        raise ValidationError("assignment digest mismatch")
    enrollment_id = document.get("enrollment_id")
    if not isinstance(enrollment_id, str) or not ENROLLMENT.fullmatch(
        enrollment_id
    ):
        raise ValidationError("invalid enrollment")
    if not isinstance(document.get("enrollment_generation"), int) or document[
        "enrollment_generation"
    ] < 1:
        raise ValidationError("invalid enrollment generation")
    if not CHANNEL.fullmatch(str(document.get("channel", ""))):
        raise ValidationError("invalid channel")
    if not isinstance(document.get("channel_generation"), int) or document[
        "channel_generation"
    ] < 0:
        raise ValidationError("invalid channel generation")
    if not REVISION.fullmatch(str(document.get("revision_id", ""))):
        raise ValidationError("invalid revision id")
    kind = document.get("assignment_kind")
    if kind not in ASSIGNMENT_KINDS or (
        expected_kind is not None and kind != expected_kind
    ):
        raise ValidationError("invalid assignment kind")
    if document.get("apply_policy") not in APPLY_POLICIES:
        raise ValidationError("invalid assignment apply policy")
    nonce = document.get("nonce")
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ValidationError("invalid assignment nonce")
    issued_at = document.get("issued_at")
    expires_at = document.get("expires_at")
    if (
        not isinstance(issued_at, int)
        or not isinstance(expires_at, int)
        or expires_at <= issued_at
        or expires_at - issued_at > 7 * 24 * 60 * 60
    ):
        raise ValidationError("invalid assignment validity")
    now = int(time.time()) if now is None else int(now)
    if validate_time and (issued_at > now + 300 or expires_at < now):
        raise ValidationError("assignment is not currently valid")
    target_tags = ProfileStore._validate_target_tags(
        document.get("target_tags", [])
    )
    return {
        "assignment_id": assignment_id,
        "enrollment_id": enrollment_id,
        "enrollment_generation": document["enrollment_generation"],
        "channel": document["channel"],
        "channel_generation": document["channel_generation"],
        "revision_id": document["revision_id"],
        "assignment_kind": kind,
        "apply_policy": document["apply_policy"],
        "target_tags": target_tags,
    }


def validate_revision(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema") not in {2, 3}:
        raise ValidationError("unsupported revision schema")
    if manifest["schema"] == 2:
        if not isinstance(manifest.get("adapters"), dict):
            raise ValidationError("invalid schema 2 revision")
    else:
        base = manifest.get("base")
        layers = manifest.get("layers")
        if (
            not isinstance(base, dict)
            or set(base) != {"adapters"}
            or not isinstance(base["adapters"], dict)
            or not isinstance(layers, list)
        ):
            raise ValidationError("invalid schema 3 revision")
    revision_id = manifest.get("revision_id")
    if not isinstance(revision_id, str) or not REVISION.fullmatch(revision_id):
        raise ValidationError("invalid revision id")
    expected = "sha256:" + hashlib.sha256(
        canonical_json(revision_identity(manifest))
    ).hexdigest()
    if revision_id != expected:
        raise ValidationError("revision digest mismatch")
    return revision_id


class ProfileStore:
    def __init__(self, path, verify_signed_document, bootstrap_keys=None):
        if verify_signed_document is None:
            raise ValueError("a signed-document verifier is required")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.blob_root = self.path.parent / "blobs" / "sha256"
        self.verify_signed_document = verify_signed_document
        self.bootstrap_keys = bootstrap_keys or {}
        self._migrate()

    def connect(self):
        database = sqlite3.connect(self.path, timeout=10)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA foreign_keys=ON")
        database.execute("PRAGMA busy_timeout=10000")
        database.execute("PRAGMA journal_mode=WAL")
        return database

    def _migrate(self):
        with self.connect() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS revisions (
                    revision_id TEXT PRIMARY KEY,
                    manifest TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS channels (
                    channel TEXT PRIMARY KEY,
                    candidate_revision TEXT,
                    active_revision TEXT,
                    generation INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(candidate_revision) REFERENCES revisions(revision_id),
                    FOREIGN KEY(active_revision) REFERENCES revisions(revision_id)
                );
                CREATE TABLE IF NOT EXISTS assignments (
                    enrollment_id TEXT PRIMARY KEY,
                    channel TEXT NOT NULL,
                    revision_id TEXT NOT NULL,
                    assignment_kind TEXT NOT NULL,
                    document TEXT NOT NULL,
                    FOREIGN KEY(revision_id) REFERENCES revisions(revision_id)
                );
                CREATE TABLE IF NOT EXISTS reports (
                    enrollment_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    revision_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    document TEXT NOT NULL,
                    PRIMARY KEY(enrollment_id, channel, revision_id)
                );
                CREATE TABLE IF NOT EXISTS assignment_reports (
                    assignment_id TEXT NOT NULL,
                    enrollment_id TEXT NOT NULL,
                    enrollment_generation INTEGER NOT NULL,
                    channel TEXT NOT NULL,
                    channel_generation INTEGER NOT NULL,
                    revision_id TEXT NOT NULL,
                    assignment_kind TEXT NOT NULL,
                    result TEXT NOT NULL,
                    document TEXT NOT NULL,
                    PRIMARY KEY(enrollment_id, assignment_id)
                );
                CREATE TABLE IF NOT EXISTS admin_requests (
                    actor_key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(actor_key_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS blobs (
                    digest TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    response TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pairing_codes (
                    code_sha256 TEXT PRIMARY KEY,
                    logical_device_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    roles TEXT NOT NULL,
                    target_tags TEXT NOT NULL DEFAULT '[]',
                    expires_at INTEGER NOT NULL,
                    attempts_remaining INTEGER NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS enrollments (
                    enrollment_id TEXT PRIMARY KEY,
                    logical_device_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    channel TEXT NOT NULL,
                    roles TEXT NOT NULL,
                    key_id TEXT NOT NULL UNIQUE,
                    public_key TEXT NOT NULL,
                    encryption_key_id TEXT,
                    encryption_public_key TEXT,
                    token_sha256 TEXT NOT NULL,
                    target_tags TEXT NOT NULL DEFAULT '[]',
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER,
                    client_version TEXT,
                    client_capabilities TEXT NOT NULL DEFAULT '[]',
                    platform TEXT,
                    heartbeat_document_sha256 TEXT,
                    UNIQUE(logical_device_id, generation)
                );
                """
            )
            for table in ("pairing_codes", "enrollments"):
                columns = {
                    row["name"]
                    for row in database.execute(f"PRAGMA table_info({table})")
                }
                if "target_tags" not in columns:
                    database.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        "target_tags TEXT NOT NULL DEFAULT '[]'"
                    )
            enrollment_columns = {
                row["name"]
                for row in database.execute("PRAGMA table_info(enrollments)")
            }
            for column, declaration in (
                ("client_version", "TEXT"),
                ("client_capabilities", "TEXT NOT NULL DEFAULT '[]'"),
                ("platform", "TEXT"),
                ("heartbeat_document_sha256", "TEXT"),
                ("encryption_key_id", "TEXT"),
                ("encryption_public_key", "TEXT"),
            ):
                if column not in enrollment_columns:
                    database.execute(
                        "ALTER TABLE enrollments ADD COLUMN %s %s"
                        % (column, declaration)
                    )
            database.execute(
                "PRAGMA user_version=%d" % DATABASE_SCHEMA_VERSION
            )

    def readiness(self):
        with self.connect() as database:
            database.execute("SELECT 1").fetchone()
            schema = int(
                database.execute("PRAGMA user_version").fetchone()[0]
            )
            integrity = database.execute("PRAGMA quick_check").fetchone()[0]
        if schema != DATABASE_SCHEMA_VERSION:
            raise RuntimeError("unsupported database schema")
        if integrity != "ok":
            raise RuntimeError("database integrity check failed")
        return {
            "database": "ready",
            "database_schema": schema,
        }

    @staticmethod
    def _validated_database(path):
        path = Path(path)
        try:
            with sqlite3.connect(
                "file:%s?mode=ro" % path.resolve(), uri=True
            ) as database:
                integrity = database.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0]
                version = database.execute("PRAGMA user_version").fetchone()[0]
        except (OSError, sqlite3.DatabaseError) as error:
            raise ValidationError(
                "backup is not a valid SQLite database"
            ) from error
        if integrity != "ok" or version not in {2, DATABASE_SCHEMA_VERSION}:
            raise ValidationError(
                "backup is not a valid SQLite database"
            )
        return path

    @staticmethod
    def _publish_database(source, destination, exists_message):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise Conflict(exists_message)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".%s." % destination.name,
            dir=str(destination.parent),
        )
        temporary = Path(temporary_name)
        os.close(descriptor)
        try:
            os.chmod(temporary, 0o600)
            with sqlite3.connect(
                "file:%s?mode=ro" % Path(source).resolve(), uri=True
            ) as input_database, sqlite3.connect(temporary) as output_database:
                input_database.backup(output_database)
                output_database.execute("PRAGMA journal_mode=DELETE")
                if (
                    output_database.execute("PRAGMA integrity_check").fetchone()[0]
                    != "ok"
                ):
                    raise ValidationError(
                        "backup is not a valid SQLite database"
                    )
            ProfileStore._validated_database(temporary)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise Conflict(exists_message) from error
            os.chmod(destination, 0o600)
        finally:
            temporary.unlink(missing_ok=True)
        payload = destination.read_bytes()
        return {
            "path": str(destination),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def backup(self, destination):
        return self._publish_database(
            self.path, destination, "backup already exists"
        )

    def backup_epoch(self, destination):
        destination = Path(destination)
        if destination.exists():
            raise Conflict("backup epoch already exists")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(
            tempfile.mkdtemp(
                prefix=".%s." % destination.name,
                dir=str(destination.parent),
            )
        )
        try:
            database_result = self._publish_database(
                self.path,
                temporary / "state.sqlite",
                "backup database already exists",
            )
            inventory = []
            with sqlite3.connect(temporary / "state.sqlite") as database:
                database.row_factory = sqlite3.Row
                rows = database.execute(
                    "SELECT digest, size, media_type FROM blobs ORDER BY digest"
                ).fetchall()
            for row in rows:
                source = self._blob_path(row["digest"])
                payload = source.read_bytes()
                if (
                    len(payload) != row["size"]
                    or "sha256:" + hashlib.sha256(payload).hexdigest()
                    != row["digest"]
                    or not valid_blob_media(payload, row["media_type"])
                ):
                    raise Conflict("backup epoch contains an invalid blob")
                target = (
                    temporary
                    / "blobs"
                    / row["digest"].split(":", 1)[1][:2]
                    / row["digest"].split(":", 1)[1]
                )
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(payload)
                os.chmod(target, 0o600)
                inventory.append(
                    {
                        "sha256": row["digest"],
                        "size": row["size"],
                        "media_type": row["media_type"],
                    }
                )
            epoch = {
                "schema": 1,
                "database": {
                    "file": "state.sqlite",
                    "bytes": database_result["bytes"],
                    "sha256": database_result["sha256"],
                },
                "blobs": inventory,
            }
            manifest = temporary / "inventory.json"
            manifest.write_bytes(canonical_json(epoch) + b"\n")
            os.chmod(manifest, 0o600)
            os.replace(temporary, destination)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return {
            "path": str(destination),
            "database_sha256": database_result["sha256"],
            "blob_count": len(inventory),
        }

    @classmethod
    def restore_backup(cls, source, destination):
        source = cls._validated_database(source)
        return cls._publish_database(
            source, destination, "restore target already exists"
        )

    @classmethod
    def restore_epoch(cls, source, destination):
        source = Path(source)
        destination = Path(destination)
        if destination.exists() or (destination.parent / "blobs").exists():
            raise Conflict("restore target already exists")
        try:
            epoch = json.loads(
                (source / "inventory.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as error:
            raise ValidationError("invalid backup epoch inventory") from error
        if (
            not isinstance(epoch, dict)
            or epoch.get("schema") != 1
            or not isinstance(epoch.get("database"), dict)
            or not isinstance(epoch.get("blobs"), list)
        ):
            raise ValidationError("invalid backup epoch inventory")
        database_source = source / "state.sqlite"
        database_payload = database_source.read_bytes()
        database_meta = epoch["database"]
        if (
            database_meta.get("file") != "state.sqlite"
            or database_meta.get("bytes") != len(database_payload)
            or database_meta.get("sha256")
            != hashlib.sha256(database_payload).hexdigest()
        ):
            raise ValidationError("backup epoch database digest mismatch")
        cls._validated_database(database_source)
        staged_blobs = []
        for blob in epoch["blobs"]:
            if not isinstance(blob, dict) or set(blob) != {
                "sha256",
                "size",
                "media_type",
            }:
                raise ValidationError("invalid backup epoch blob inventory")
            digest = blob["sha256"]
            if not isinstance(digest, str) or not REVISION.fullmatch(digest):
                raise ValidationError("invalid backup epoch blob digest")
            value = digest.split(":", 1)[1]
            blob_source = source / "blobs" / value[:2] / value
            try:
                payload = blob_source.read_bytes()
            except OSError as error:
                raise ValidationError(
                    "backup epoch blob is missing"
                ) from error
            if (
                blob.get("size") != len(payload)
                or "sha256:" + hashlib.sha256(payload).hexdigest() != digest
                or not valid_blob_media(payload, blob.get("media_type"))
            ):
                raise ValidationError("backup epoch blob digest mismatch")
            staged_blobs.append((digest, payload))
        result = cls._publish_database(
            database_source, destination, "restore target already exists"
        )
        blob_root = destination.parent / "blobs" / "sha256"
        try:
            for digest, payload in staged_blobs:
                value = digest.split(":", 1)[1]
                target = blob_root / value[:2] / value
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(payload)
                os.chmod(target, 0o600)
        except Exception:
            destination.unlink(missing_ok=True)
            shutil.rmtree(destination.parent / "blobs", ignore_errors=True)
            raise
        return {**result, "blob_count": len(staged_blobs)}

    @staticmethod
    def _token_digest(token):
        return hashlib.sha256(
            b"mwo-profile-sync/token/v1\0" + token.encode("ascii")
        ).hexdigest()

    @staticmethod
    def _pairing_digest(code):
        return hashlib.sha256(
            b"mwo-profile-sync/pairing-code/v1\0" + code.encode("ascii")
        ).hexdigest()

    @staticmethod
    def _validate_roles(roles):
        if (
            not isinstance(roles, (list, tuple))
            or not roles
            or len(roles) != len(set(roles))
            or any(role not in ROLES for role in roles)
        ):
            raise ValidationError("invalid enrollment roles")
        return sorted(roles)

    @staticmethod
    def _validate_target_tags(target_tags):
        if (
            not isinstance(target_tags, (list, tuple))
            or len(target_tags) != len(set(target_tags))
            or len(target_tags) > 16
            or any(
                not isinstance(tag, str) or not TARGET_TAG.fullmatch(tag)
                for tag in target_tags
            )
        ):
            raise ValidationError("invalid enrollment target tags")
        return sorted(target_tags)

    def create_pairing_code(
        self,
        logical_device_id,
        channel,
        roles=("read",),
        ttl_seconds=300,
        attempts=5,
        code=None,
        target_tags=(),
    ):
        if not LOGICAL_DEVICE.fullmatch(str(logical_device_id)):
            raise ValidationError("invalid logical device id")
        if not CHANNEL.fullmatch(str(channel)):
            raise ValidationError("invalid channel")
        roles = self._validate_roles(roles)
        target_tags = self._validate_target_tags(target_tags)
        if (
            not isinstance(ttl_seconds, int)
            or ttl_seconds < 30
            or ttl_seconds > 1800
        ):
            raise ValidationError("invalid pairing code TTL")
        if not isinstance(attempts, int) or attempts < 1 or attempts > 10:
            raise ValidationError("invalid pairing attempt limit")
        if code is None:
            code = "%08d" % secrets.randbelow(100_000_000)
        if not isinstance(code, str) or not PAIRING_CODE.fullmatch(code):
            raise ValidationError("invalid pairing code")
        expires_at = int(time.time()) + ttl_seconds
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "DELETE FROM pairing_codes WHERE expires_at < ? OR consumed=1",
                (int(time.time()),),
            )
            try:
                database.execute(
                    """
                    INSERT INTO pairing_codes (
                        code_sha256, logical_device_id, channel, roles,
                        target_tags, expires_at, attempts_remaining, consumed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        self._pairing_digest(code),
                        logical_device_id,
                        channel,
                        canonical_json(roles).decode("utf-8"),
                        canonical_json(target_tags).decode("utf-8"),
                        expires_at,
                        attempts,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise Conflict("pairing code collision") from error
        return {
            "code": code,
            "logical_device_id": logical_device_id,
            "channel": channel,
            "roles": roles,
            "target_tags": target_tags,
            "expires_at": expires_at,
        }

    def pair(
        self,
        code,
        logical_device_id,
        channel,
        key_id,
        public_key,
        encryption_key_id=None,
        encryption_public_key=None,
    ):
        if not isinstance(code, str) or not PAIRING_CODE.fullmatch(code):
            raise Unauthorized("pairing rejected")
        if not LOGICAL_DEVICE.fullmatch(str(logical_device_id)):
            raise Unauthorized("pairing rejected")
        if not CHANNEL.fullmatch(str(channel)):
            raise Unauthorized("pairing rejected")
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            raise ValidationError("invalid enrollment key id")
        from .crypto import _b64url_decode

        _b64url_decode(public_key, 32)
        if (encryption_key_id is None) != (encryption_public_key is None):
            raise ValidationError("encryption key pair metadata is incomplete")
        if encryption_key_id is not None:
            if not isinstance(encryption_key_id, str) or not KEY_ID.fullmatch(
                encryption_key_id
            ):
                raise ValidationError("invalid encryption key id")
            _b64url_decode(encryption_public_key, 32)
        now = int(time.time())
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            pairing = database.execute(
                "SELECT * FROM pairing_codes WHERE code_sha256=?",
                (self._pairing_digest(code),),
            ).fetchone()
            if (
                pairing is None
                or pairing["consumed"]
                or pairing["expires_at"] < now
                or pairing["attempts_remaining"] <= 0
            ):
                raise Unauthorized("pairing rejected")
            if (
                pairing["logical_device_id"] != logical_device_id
                or pairing["channel"] != channel
            ):
                database.execute(
                    """
                    UPDATE pairing_codes
                    SET attempts_remaining=attempts_remaining-1
                    WHERE code_sha256=?
                    """,
                    (self._pairing_digest(code),),
                )
                raise Unauthorized("pairing rejected")
            generation = (
                database.execute(
                    """
                    SELECT COALESCE(MAX(generation), 0) + 1
                    FROM enrollments WHERE logical_device_id=?
                    """,
                    (logical_device_id,),
                ).fetchone()[0]
            )
            enrollment_id = "enr:" + secrets.token_urlsafe(18)
            access_token = secrets.token_urlsafe(32)
            roles = json.loads(pairing["roles"])
            target_tags = self._validate_target_tags(json.loads(pairing["target_tags"]))
            try:
                database.execute(
                    """
                    INSERT INTO enrollments (
                        enrollment_id, logical_device_id, generation, channel,
                        roles, key_id, public_key, encryption_key_id,
                        encryption_public_key, token_sha256, target_tags,
                        revoked, created_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)
                    """,
                    (
                        enrollment_id,
                        logical_device_id,
                        generation,
                        channel,
                        canonical_json(roles).decode("utf-8"),
                        key_id,
                        public_key,
                        encryption_key_id,
                        encryption_public_key,
                        self._token_digest(access_token),
                        canonical_json(target_tags).decode("utf-8"),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise Conflict("enrollment key id already exists") from error
            database.execute(
                "UPDATE pairing_codes SET consumed=1 WHERE code_sha256=?",
                (self._pairing_digest(code),),
            )
        return {
            "enrollment_id": enrollment_id,
            "enrollment_generation": generation,
            "logical_device_id": logical_device_id,
            "channel": channel,
            "roles": roles,
            "target_tags": target_tags,
            "access_token": access_token,
            "trust": self.bootstrap_keys,
            "encryption": (
                {
                    "key_id": encryption_key_id,
                    "suite": "DHKEM_X25519_HKDF_SHA256",
                }
                if encryption_key_id is not None
                else None
            ),
        }

    def secret_envelope_request(
        self, enrollment_id, access_token, delivery_mode="shadow"
    ):
        if delivery_mode not in {"shadow", "canary", "active"}:
            raise ValidationError("invalid secret delivery mode")
        with self.connect() as database:
            enrollment = self._authenticate(
                database, enrollment_id, access_token
            )
            if not enrollment["encryption_key_id"] or not enrollment[
                "encryption_public_key"
            ]:
                raise Conflict("enrollment has no encryption capability")
            capabilities = json.loads(enrollment["client_capabilities"])
            if "secret-envelope-v1" not in capabilities:
                raise Conflict("client has not reported secret-envelope-v1")
            return {
                "logical_device_id": enrollment["logical_device_id"],
                "enrollment_id": enrollment["enrollment_id"],
                "enrollment_generation": enrollment["generation"],
                "encryption_key_id": enrollment["encryption_key_id"],
                "encryption_public_key": enrollment["encryption_public_key"],
                "delivery_mode": delivery_mode,
            }

    def register_encryption_key(
        self,
        enrollment_id,
        access_token,
        enrollment_generation,
        encryption_key_id,
        encryption_public_key,
    ):
        if not isinstance(encryption_key_id, str) or not KEY_ID.fullmatch(
            encryption_key_id
        ):
            raise ValidationError("invalid encryption key id")
        from .crypto import _b64url_decode

        _b64url_decode(encryption_public_key, 32)
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            enrollment = self._authenticate(database, enrollment_id, access_token)
            if enrollment["generation"] != enrollment_generation:
                raise Conflict("enrollment generation differs")
            existing = (
                enrollment["encryption_key_id"],
                enrollment["encryption_public_key"],
            )
            requested = (encryption_key_id, encryption_public_key)
            if existing == requested:
                return {
                    "enrollment_id": enrollment_id,
                    "enrollment_generation": enrollment_generation,
                    "encryption_key_id": encryption_key_id,
                    "status": "unchanged",
                }
            if any(existing):
                raise Conflict("enrollment encryption key already exists")
            database.execute(
                "UPDATE enrollments SET encryption_key_id=?, "
                "encryption_public_key=? WHERE enrollment_id=?",
                (encryption_key_id, encryption_public_key, enrollment_id),
            )
        return {
            "enrollment_id": enrollment_id,
            "enrollment_generation": enrollment_generation,
            "encryption_key_id": encryption_key_id,
            "status": "registered",
        }

    def _authenticate(self, database, enrollment_id, access_token, role="read"):
        if (
            not isinstance(enrollment_id, str)
            or not ENROLLMENT.fullmatch(enrollment_id)
            or not isinstance(access_token, str)
            or len(access_token) < 32
        ):
            raise Unauthorized("authentication failed")
        enrollment = database.execute(
            "SELECT * FROM enrollments WHERE enrollment_id=?",
            (enrollment_id,),
        ).fetchone()
        if (
            enrollment is None
            or enrollment["revoked"]
            or not hmac.compare_digest(
                enrollment["token_sha256"],
                self._token_digest(access_token),
            )
            or role not in json.loads(enrollment["roles"])
        ):
            raise Unauthorized("authentication failed")
        return enrollment

    def heartbeat(self, document, access_token):
        enrollment_id = document.get("enrollment_id")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            enrollment = self._authenticate(
                database, enrollment_id, access_token
            )
            expected = {
                "logical_device_id": enrollment["logical_device_id"],
                "enrollment_generation": enrollment["generation"],
                "channel": enrollment["channel"],
            }
            if any(document.get(key) != value for key, value in expected.items()):
                raise Unauthorized("heartbeat identity mismatch")
            client_version = document.get("client_version")
            if client_version is not None and (
                not isinstance(client_version, str)
                or not CLIENT_VERSION.fullmatch(client_version)
            ):
                raise ValidationError("invalid heartbeat client version")
            capabilities = self._validate_target_tags(
                document.get("client_capabilities", [])
            )
            platform = document.get("platform")
            if platform is not None and (
                not isinstance(platform, str) or not PLATFORM.fullmatch(platform)
            ):
                raise ValidationError("invalid heartbeat platform")
            heartbeat_sha256 = hashlib.sha256(canonical_json(document)).hexdigest()
            database.execute(
                """
                UPDATE enrollments
                SET last_seen_at=?, client_version=?, client_capabilities=?,
                    platform=?, heartbeat_document_sha256=?
                WHERE enrollment_id=?
                """,
                (
                    int(time.time()),
                    client_version,
                    canonical_json(capabilities).decode("utf-8"),
                    platform,
                    heartbeat_sha256,
                    enrollment_id,
                ),
            )
        return {
            "enrollment_id": enrollment_id,
            "status": "ok",
            "revoked": False,
        }

    def integration_fleet_snapshot(self, now=None):
        """Return the redacted, authenticated fleet view for the control plane."""
        now = int(time.time()) if now is None else int(now)
        with self.connect() as database:
            enrollments = database.execute(
                """
                SELECT enrollment_id, logical_device_id, generation, channel,
                       target_tags, revoked, created_at, last_seen_at,
                       client_version, client_capabilities, platform,
                       heartbeat_document_sha256
                FROM enrollments
                ORDER BY logical_device_id, generation
                """
            ).fetchall()
            channels = database.execute(
                """
                SELECT channel, candidate_revision, active_revision, generation
                FROM channels ORDER BY channel
                """
            ).fetchall()
        return {
            "schema": 1,
            "generated_at": now,
            "database_schema": DATABASE_SCHEMA_VERSION,
            "devices": [
                {
                    "enrollment_id": row["enrollment_id"],
                    "logical_device_id": row["logical_device_id"],
                    "enrollment_generation": row["generation"],
                    "channel": row["channel"],
                    "target_tags": self._validate_target_tags(
                        json.loads(row["target_tags"])
                    ),
                    "revoked": bool(row["revoked"]),
                    "created_at": row["created_at"],
                    "last_seen_at": row["last_seen_at"],
                    "client_version": row["client_version"],
                    "client_capabilities": self._validate_target_tags(
                        json.loads(row["client_capabilities"] or "[]")
                    ),
                    "platform": row["platform"],
                    "heartbeat_document_sha256": row[
                        "heartbeat_document_sha256"
                    ],
                }
                for row in enrollments
            ],
            "channels": [dict(row) for row in channels],
        }

    def integration_rollout_snapshot(self, now=None):
        """Return redacted assignment/report state without signed documents."""
        now = int(time.time()) if now is None else int(now)
        with self.connect() as database:
            assignments = database.execute(
                """
                SELECT a.enrollment_id, e.logical_device_id, e.generation,
                       a.channel, a.revision_id, a.assignment_kind, a.document
                FROM assignments AS a
                LEFT JOIN enrollments AS e
                  ON e.enrollment_id = a.enrollment_id
                ORDER BY a.channel, e.logical_device_id, a.enrollment_id
                """
            ).fetchall()
            assignment_reports = {
                row["assignment_id"]: row
                for row in database.execute(
                    """
                    SELECT assignment_id, result FROM assignment_reports
                    ORDER BY assignment_id
                    """
                )
            }
            legacy_reports = {
                (row["enrollment_id"], row["channel"], row["revision_id"]): row
                for row in database.execute(
                    """
                    SELECT enrollment_id, channel, revision_id, result
                    FROM reports
                    """
                )
            }
        result = []
        for row in assignments:
            document = json.loads(row["document"])
            assignment_id = document.get("assignment_id")
            report = assignment_reports.get(assignment_id)
            if report is None:
                report = legacy_reports.get(
                    (row["enrollment_id"], row["channel"], row["revision_id"])
                )
            result.append(
                {
                    "assignment_id": assignment_id,
                    "assignment_kind": row["assignment_kind"],
                    "enrollment_id": row["enrollment_id"],
                    "logical_device_id": row["logical_device_id"],
                    "enrollment_generation": row["generation"],
                    "channel": row["channel"],
                    "revision_id": row["revision_id"],
                    "apply_policy": document.get("apply_policy"),
                    "issued_at": document.get("issued_at"),
                    "expires_at": document.get("expires_at"),
                    "report_result": report["result"] if report else None,
                }
            )
        return {"schema": 1, "generated_at": now, "assignments": result}

    def revoke_enrollment(self, enrollment_id):
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            changed = database.execute(
                "UPDATE enrollments SET revoked=1 WHERE enrollment_id=?",
                (enrollment_id,),
            ).rowcount
            if not changed:
                raise NotFound("enrollment does not exist")
        return {"enrollment_id": enrollment_id, "revoked": True}

    def authorize_admin_request(
        self, document, operation, idempotency_key, now=None
    ):
        if not isinstance(document, dict) or document.get("schema") != 1:
            raise Unauthorized("admin authentication failed")
        role = document.get("actor_role")
        if (
            role not in ADMIN_ROLE_OPERATIONS
            or operation not in ADMIN_ROLE_OPERATIONS[role]
            or document.get("operation") != operation
            or document.get("idempotency_key") != idempotency_key
            or not isinstance(document.get("payload"), dict)
        ):
            raise Unauthorized("admin authorization failed")
        nonce = document.get("nonce")
        if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
            raise Unauthorized("admin authentication failed")
        issued_at = document.get("issued_at")
        expires_at = document.get("expires_at")
        now = int(time.time()) if now is None else int(now)
        if (
            not isinstance(issued_at, int)
            or not isinstance(expires_at, int)
            or expires_at <= issued_at
            or expires_at - issued_at > 300
            or issued_at > now + 30
            or expires_at < now
        ):
            raise Unauthorized("admin request is not currently valid")
        kind = "admin" if role == "admin" else "admin_" + role
        if not self.verify_signed_document(kind, document):
            raise Unauthorized("admin signature is invalid")
        signature = document.get("signature", {})
        actor_key_id = signature.get("key_id")
        if not isinstance(actor_key_id, str) or not KEY_ID.fullmatch(
            actor_key_id
        ):
            raise Unauthorized("admin authentication failed")
        request_sha256 = hashlib.sha256(canonical_json(document)).hexdigest()
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "DELETE FROM admin_requests WHERE expires_at < ?", (now,)
            )
            existing = database.execute(
                """
                SELECT request_sha256 FROM admin_requests
                WHERE actor_key_id=? AND nonce=?
                """,
                (actor_key_id, nonce),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != request_sha256:
                    raise Conflict("admin nonce replayed with different request")
            else:
                database.execute(
                    "INSERT INTO admin_requests VALUES (?, ?, ?, ?)",
                    (actor_key_id, nonce, request_sha256, expires_at),
                )
        return document["payload"]

    def _idempotent(self, database, key, operation, action):
        if not isinstance(key, str) or len(key) < 8:
            raise ValidationError("invalid idempotency key")
        row = database.execute(
            "SELECT operation, response FROM idempotency WHERE idempotency_key=?",
            (key,),
        ).fetchone()
        if row:
            if row["operation"] != operation:
                raise Conflict("idempotency key reused for another operation")
            return json.loads(row["response"])
        response = action()
        database.execute(
            "INSERT INTO idempotency VALUES (?, ?, ?)",
            (key, operation, canonical_json(response).decode("utf-8")),
        )
        return response

    def put_revision(self, manifest):
        if not self.verify_signed_document("revision", manifest):
            raise ValidationError("invalid revision signature")
        revision_id = validate_revision(manifest)
        payload = canonical_json(manifest).decode("utf-8")
        with self.connect() as database:
            row = database.execute(
                "SELECT manifest FROM revisions WHERE revision_id=?",
                (revision_id,),
            ).fetchone()
            if row and row["manifest"] != payload:
                raise Conflict("immutable revision already has different bytes")
            database.execute(
                "INSERT OR IGNORE INTO revisions VALUES (?, ?)",
                (revision_id, payload),
            )
        return {"revision_id": revision_id}

    def _blob_path(self, digest):
        if not isinstance(digest, str) or not REVISION.fullmatch(digest):
            raise ValidationError("invalid blob digest")
        value = digest.split(":", 1)[1]
        return self.blob_root / value[:2] / value

    def put_blob(self, digest, payload, media_type):
        if not isinstance(payload, bytes) or len(payload) > MAX_BLOB_BYTES:
            raise ValidationError("invalid blob size")
        if media_type not in BLOB_MEDIA_TYPES or not valid_blob_media(
            payload, media_type
        ):
            raise ValidationError("invalid blob media type")
        expected = "sha256:" + hashlib.sha256(payload).hexdigest()
        if digest != expected:
            raise ValidationError("blob digest mismatch")
        destination = self._blob_path(digest)
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            row = database.execute(
                "SELECT size, media_type FROM blobs WHERE digest=?", (digest,)
            ).fetchone()
            if row is not None:
                if (
                    row["size"] != len(payload)
                    or row["media_type"] != media_type
                    or not destination.is_file()
                    or destination.read_bytes() != payload
                ):
                    raise Conflict("immutable blob already differs")
                return {
                    "sha256": digest,
                    "size": len(payload),
                    "media_type": media_type,
                    "stored": False,
                }
            total = database.execute(
                "SELECT COALESCE(SUM(size), 0) FROM blobs"
            ).fetchone()[0]
            if total + len(payload) > MAX_BLOB_STORE_BYTES:
                raise Conflict("blob store quota exceeded")
            self.blob_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if shutil.disk_usage(self.blob_root).free - len(payload) < (
                MIN_BLOB_DISK_RESERVE
            ):
                raise Conflict("blob store disk reserve reached")
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".blob.", dir=str(destination.parent)
            )
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o600)
                try:
                    os.link(temporary, destination)
                except FileExistsError as error:
                    raise Conflict("blob file already exists") from error
            finally:
                temporary.unlink(missing_ok=True)
            database.execute(
                "INSERT INTO blobs VALUES (?, ?, ?, ?)",
                (digest, len(payload), media_type, int(time.time())),
            )
        return {
            "sha256": digest,
            "size": len(payload),
            "media_type": media_type,
            "stored": True,
        }

    @staticmethod
    def _manifest_references_blob(value, digest, size, media_type):
        if isinstance(value, dict):
            if value.get("sha256") == digest:
                return (
                    value.get("size") == size
                    and value.get("media_type") == media_type
                )
            return any(
                ProfileStore._manifest_references_blob(
                    item, digest, size, media_type
                )
                for item in value.values()
            )
        if isinstance(value, list):
            return any(
                ProfileStore._manifest_references_blob(
                    item, digest, size, media_type
                )
                for item in value
            )
        return False

    def blob(self, digest, enrollment_id, access_token):
        path = self._blob_path(digest)
        with self.connect() as database:
            enrollment = self._authenticate(
                database, enrollment_id, access_token
            )
            assignment = database.execute(
                """
                SELECT revision_id FROM assignments
                WHERE enrollment_id=? AND channel=?
                """,
                (enrollment_id, enrollment["channel"]),
            ).fetchone()
            if assignment is None:
                raise Unauthorized("blob is not reachable from assignment")
            row = database.execute(
                "SELECT size, media_type FROM blobs WHERE digest=?", (digest,)
            ).fetchone()
            revision = database.execute(
                "SELECT manifest FROM revisions WHERE revision_id=?",
                (assignment["revision_id"],),
            ).fetchone()
            if (
                row is None
                or revision is None
                or not self._manifest_references_blob(
                    json.loads(revision["manifest"]),
                    digest,
                    row["size"],
                    row["media_type"],
                )
            ):
                raise Unauthorized("blob is not reachable from assignment")
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise NotFound("blob does not exist") from error
        if (
            len(payload) != row["size"]
            or "sha256:" + hashlib.sha256(payload).hexdigest() != digest
        ):
            raise Conflict("blob integrity check failed")
        return payload, row["media_type"]

    def revision(self, revision_id, enrollment_id, access_token):
        if not isinstance(revision_id, str) or not REVISION.fullmatch(
            revision_id
        ):
            raise NotFound("revision does not exist")
        with self.connect() as database:
            self._authenticate(database, enrollment_id, access_token)
            row = database.execute(
                "SELECT manifest FROM revisions WHERE revision_id=?",
                (revision_id,),
            ).fetchone()
            if row is None:
                raise NotFound("revision does not exist")
            return json.loads(row["manifest"])

    def publish_candidate(
        self,
        channel,
        revision_id,
        base_revision,
        expected_candidate_head,
        idempotency_key,
    ):
        if not CHANNEL.fullmatch(channel):
            raise ValidationError("invalid channel")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")

            def action():
                if not database.execute(
                    "SELECT 1 FROM revisions WHERE revision_id=?",
                    (revision_id,),
                ).fetchone():
                    raise NotFound("revision does not exist")
                database.execute(
                    "INSERT OR IGNORE INTO channels(channel) VALUES (?)",
                    (channel,),
                )
                current = database.execute(
                    "SELECT * FROM channels WHERE channel=?", (channel,)
                ).fetchone()
                if current["candidate_revision"] != expected_candidate_head:
                    raise Conflict("candidate head changed")
                if current["active_revision"] != base_revision:
                    raise Conflict("active revision changed")
                database.execute(
                    "UPDATE channels SET candidate_revision=? WHERE channel=?",
                    (revision_id, channel),
                )
                database.execute(
                    "DELETE FROM assignments WHERE channel=?", (channel,)
                )
                return {
                    "channel": channel,
                    "candidate_revision": revision_id,
                    "active_revision": current["active_revision"],
                }

            return self._idempotent(
                database, idempotency_key, "publish_candidate", action
            )

    def assign_candidate(self, document, idempotency_key):
        if not self.verify_signed_document("assignment", document):
            raise ValidationError("invalid assignment signature")
        contract = (
            validate_assignment_v2(document, expected_kind="candidate")
            if document.get("schema") == 2
            else None
        )
        enrollment = document.get("enrollment_id")
        channel = document.get("channel")
        revision_id = document.get("revision_id")
        target_tags = self._validate_target_tags(document.get("target_tags", []))
        if not isinstance(enrollment, str) or not ENROLLMENT.fullmatch(enrollment):
            raise ValidationError("invalid enrollment")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")

            def action():
                row = database.execute(
                    "SELECT candidate_revision, generation FROM channels WHERE channel=?",
                    (channel,),
                ).fetchone()
                if not row or row["candidate_revision"] != revision_id:
                    raise Conflict("assignment does not target current candidate")
                enrolled = database.execute(
                    """
                    SELECT channel, generation, target_tags, revoked
                    FROM enrollments WHERE enrollment_id=?
                    """,
                    (enrollment,),
                ).fetchone()
                if enrolled is not None:
                    if enrolled["revoked"] or enrolled["channel"] != channel:
                        raise Conflict("assignment enrollment is not eligible")
                    enrolled_tags = self._validate_target_tags(
                        json.loads(enrolled["target_tags"])
                    )
                    if enrolled_tags != target_tags:
                        raise Conflict("assignment target tags differ from enrollment")
                    if contract is not None and (
                        contract["enrollment_generation"]
                        != enrolled["generation"]
                        or contract["channel_generation"] != row["generation"]
                    ):
                        raise Conflict("assignment generation differs")
                elif contract is not None:
                    raise Conflict("assignment enrollment is not eligible")
                database.execute(
                    """
                    INSERT OR REPLACE INTO assignments
                    VALUES (?, ?, ?, 'candidate', ?)
                    """,
                    (
                        enrollment,
                        channel,
                        revision_id,
                        canonical_json(document).decode("utf-8"),
                    ),
                )
                return {
                    "enrollment_id": enrollment,
                    "channel": channel,
                    "revision_id": revision_id,
                    "assignment_kind": "candidate",
                    "target_tags": target_tags,
                    **(
                        {
                            "assignment_id": contract["assignment_id"],
                            "channel_generation": contract[
                                "channel_generation"
                            ],
                            "apply_policy": contract["apply_policy"],
                        }
                        if contract is not None
                        else {}
                    ),
                }

            return self._idempotent(
                database, idempotency_key, "assign_candidate", action
            )

    def bootstrap_active(self, channel, document, idempotency_key):
        """Create a signed client-compatible assignment for active state.

        The server never signs assignments.  A schema-2 document is stored as
        an active assignment.  A legacy document remains a candidate for
        compatibility with released 0.1.8 read-only clients.
        """
        if not CHANNEL.fullmatch(str(channel)):
            raise ValidationError("invalid channel")
        if not self.verify_signed_document("assignment", document):
            raise ValidationError("invalid assignment signature")
        contract = (
            validate_assignment_v2(document, expected_kind="active")
            if document.get("schema") == 2
            else None
        )
        enrollment = document.get("enrollment_id")
        document_channel = document.get("channel")
        revision_id = document.get("revision_id")
        target_tags = self._validate_target_tags(document.get("target_tags", []))
        if not isinstance(enrollment, str) or not ENROLLMENT.fullmatch(enrollment):
            raise ValidationError("invalid enrollment")
        if document_channel != channel:
            raise Conflict("bootstrap assignment channel differs from endpoint")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")

            def action():
                current = database.execute(
                    "SELECT active_revision, generation FROM channels WHERE channel=?",
                    (channel,),
                ).fetchone()
                if not current or current["active_revision"] != revision_id:
                    raise Conflict(
                        "bootstrap assignment does not target active revision"
                    )
                enrolled = database.execute(
                    """
                    SELECT channel, generation, target_tags, revoked
                    FROM enrollments WHERE enrollment_id=?
                    """,
                    (enrollment,),
                ).fetchone()
                if (
                    enrolled is None
                    or enrolled["revoked"]
                    or enrolled["channel"] != channel
                ):
                    raise Conflict("bootstrap enrollment is not eligible")
                enrolled_tags = self._validate_target_tags(
                    json.loads(enrolled["target_tags"])
                )
                if enrolled_tags != target_tags:
                    raise Conflict(
                        "bootstrap target tags differ from enrollment"
                    )
                if contract is not None and (
                    contract["enrollment_generation"]
                    != enrolled["generation"]
                    or contract["channel_generation"] != current["generation"]
                ):
                    raise Conflict("bootstrap assignment generation differs")
                stored_kind = "active" if contract is not None else "candidate"
                database.execute(
                    """
                    INSERT OR REPLACE INTO assignments
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        enrollment,
                        channel,
                        revision_id,
                        stored_kind,
                        canonical_json(document).decode("utf-8"),
                    ),
                )
                return {
                    "enrollment_id": enrollment,
                    "channel": channel,
                    "revision_id": revision_id,
                    "assignment_kind": stored_kind,
                    "assignment_source": "active-bootstrap",
                    "target_tags": target_tags,
                    **(
                        {
                            "assignment_id": contract["assignment_id"],
                            "channel_generation": contract[
                                "channel_generation"
                            ],
                            "apply_policy": contract["apply_policy"],
                        }
                        if contract is not None
                        else {}
                    ),
                }

            return self._idempotent(
                database, idempotency_key, "bootstrap_active", action
            )

    def record_report(self, document, idempotency_key):
        enrollment = document.get("enrollment_id")
        channel = document.get("channel")
        revision_id = document.get("revision_id")
        result = document.get("result")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")
            from .crypto import decode_public_key, verify_document_with_key

            enrolled = database.execute(
                """
                SELECT key_id, public_key, revoked FROM enrollments
                WHERE enrollment_id=?
                """,
                (enrollment,),
            ).fetchone()
            if enrolled is None:
                verified = self.verify_signed_document("report", document)
            else:
                verified = not enrolled["revoked"] and verify_document_with_key(
                    "report",
                    document,
                    enrolled["key_id"],
                    decode_public_key(enrolled["public_key"]),
                )
            if not verified:
                raise ValidationError("invalid report signature")
            if result not in REPORT_RESULTS:
                raise ValidationError("invalid report result")

            def action():
                assignment = database.execute(
                    """
                    SELECT revision_id, assignment_kind, document FROM assignments
                    WHERE enrollment_id=? AND channel=?
                    """,
                    (enrollment, channel),
                ).fetchone()
                if not assignment or assignment["revision_id"] != revision_id:
                    raise Conflict("report does not match assignment")
                assignment_document = json.loads(assignment["document"])
                if assignment_document.get("schema") == 2:
                    contract = validate_assignment_v2(
                        assignment_document,
                        expected_kind=assignment["assignment_kind"],
                        validate_time=False,
                    )
                    expected = {
                        "assignment_id": contract["assignment_id"],
                        "assignment_kind": contract["assignment_kind"],
                        "enrollment_generation": contract[
                            "enrollment_generation"
                        ],
                        "channel_generation": contract[
                            "channel_generation"
                        ],
                    }
                    if any(
                        document.get(key) != value
                        for key, value in expected.items()
                    ):
                        raise Conflict("report does not match assignment")
                    database.execute(
                        """
                        INSERT OR REPLACE INTO assignment_reports (
                            assignment_id, enrollment_id,
                            enrollment_generation, channel,
                            channel_generation, revision_id,
                            assignment_kind, result, document
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            contract["assignment_id"],
                            enrollment,
                            contract["enrollment_generation"],
                            channel,
                            contract["channel_generation"],
                            revision_id,
                            contract["assignment_kind"],
                            result,
                            canonical_json(document).decode("utf-8"),
                        ),
                    )
                    return {
                        "assignment_id": contract["assignment_id"],
                        "assignment_kind": contract["assignment_kind"],
                        "channel_generation": contract[
                            "channel_generation"
                        ],
                        "enrollment_id": enrollment,
                        "revision_id": revision_id,
                        "result": result,
                    }
                database.execute(
                    "INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?)",
                    (
                        enrollment,
                        channel,
                        revision_id,
                        result,
                        canonical_json(document).decode("utf-8"),
                    ),
                )
                return {
                    "enrollment_id": enrollment,
                    "revision_id": revision_id,
                    "result": result,
                }

            return self._idempotent(
                database, idempotency_key, "record_report", action
            )

    def promote(
        self,
        channel,
        candidate_revision,
        expected_active_revision,
        required_enrollments,
        event,
        idempotency_key,
        active_assignments=None,
    ):
        if not self.verify_signed_document("promotion", event):
            raise ValidationError("invalid promotion signature")
        active_contracts = None
        if active_assignments is not None:
            if not isinstance(active_assignments, list) or not active_assignments:
                raise ValidationError("active assignment batch is empty")
            active_contracts = []
            seen = set()
            for document in active_assignments:
                if not self.verify_signed_document("assignment", document):
                    raise ValidationError("invalid active assignment signature")
                contract = validate_assignment_v2(
                    document, expected_kind="active"
                )
                if contract["assignment_id"] in seen:
                    raise ValidationError("duplicate active assignment")
                seen.add(contract["assignment_id"])
                active_contracts.append((contract, document))
            declared = event.get("active_assignment_ids")
            if declared != sorted(seen):
                raise Conflict("promotion does not bind active assignments")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")

            def action():
                current = database.execute(
                    "SELECT * FROM channels WHERE channel=?", (channel,)
                ).fetchone()
                if not current:
                    raise NotFound("channel does not exist")
                if current["candidate_revision"] != candidate_revision:
                    raise Conflict("candidate changed")
                if current["active_revision"] != expected_active_revision:
                    raise Conflict("active revision changed")
                for enrollment in required_enrollments:
                    report = database.execute(
                        """
                        SELECT result FROM assignment_reports
                        WHERE enrollment_id=? AND channel=? AND revision_id=?
                          AND assignment_kind='candidate'
                        ORDER BY channel_generation DESC LIMIT 1
                        """,
                        (enrollment, channel, candidate_revision),
                    ).fetchone()
                    if report is None:
                        report = database.execute(
                            """
                            SELECT result FROM reports
                            WHERE enrollment_id=? AND channel=? AND revision_id=?
                            """,
                            (enrollment, channel, candidate_revision),
                        ).fetchone()
                    if not report or report["result"] != "success":
                        raise Conflict("required canary report is missing")
                generation = current["generation"] + 1
                if event.get("generation") != generation:
                    raise Conflict("promotion generation differs")
                if active_contracts is not None:
                    for contract, _document in active_contracts:
                        if (
                            contract["channel"] != channel
                            or contract["revision_id"] != candidate_revision
                            or contract["channel_generation"] != generation
                        ):
                            raise Conflict(
                                "active assignment differs from promotion"
                            )
                        enrolled = database.execute(
                            """
                            SELECT generation, channel, target_tags, revoked
                            FROM enrollments WHERE enrollment_id=?
                            """,
                            (contract["enrollment_id"],),
                        ).fetchone()
                        if (
                            enrolled is None
                            or enrolled["revoked"]
                            or enrolled["channel"] != channel
                            or enrolled["generation"]
                            != contract["enrollment_generation"]
                            or self._validate_target_tags(
                                json.loads(enrolled["target_tags"])
                            )
                            != contract["target_tags"]
                        ):
                            raise Conflict(
                                "active assignment enrollment is not eligible"
                            )
                database.execute(
                    """
                    UPDATE channels
                    SET active_revision=?, candidate_revision=NULL, generation=?
                    WHERE channel=?
                    """,
                    (candidate_revision, generation, channel),
                )
                database.execute(
                    "DELETE FROM assignments WHERE channel=?", (channel,)
                )
                if active_contracts is not None:
                    for contract, document in active_contracts:
                        database.execute(
                            """
                            INSERT INTO assignments (
                                enrollment_id, channel, revision_id,
                                assignment_kind, document
                            ) VALUES (?, ?, ?, 'active', ?)
                            """,
                            (
                                contract["enrollment_id"],
                                channel,
                                candidate_revision,
                                canonical_json(document).decode("utf-8"),
                            ),
                        )
                return {
                    "channel": channel,
                    "active_revision": candidate_revision,
                    "generation": generation,
                    **(
                        {
                            "active_assignment_ids": sorted(
                                contract["assignment_id"]
                                for contract, _document in active_contracts
                            )
                        }
                        if active_contracts is not None
                        else {}
                    ),
                }

            return self._idempotent(
                database, idempotency_key, "promote", action
            )

    def assignment(self, enrollment_id, channel, access_token=None):
        with self.connect() as database:
            if access_token is not None:
                enrollment = self._authenticate(
                    database, enrollment_id, access_token
                )
                if enrollment["channel"] != channel:
                    raise Unauthorized("channel mismatch")
            assigned = database.execute(
                """
                SELECT revision_id, assignment_kind, document FROM assignments
                WHERE enrollment_id=? AND channel=?
                """,
                (enrollment_id, channel),
            ).fetchone()
            if assigned:
                return {
                    "assignment_kind": assigned["assignment_kind"],
                    "document": json.loads(assigned["document"]),
                }
            current = database.execute(
                "SELECT active_revision FROM channels WHERE channel=?",
                (channel,),
            ).fetchone()
            if not current or current["active_revision"] is None:
                raise NotFound("channel has no active revision")
            response = {
                "revision_id": current["active_revision"],
                "assignment_kind": "active",
            }
            if access_token is not None:
                response["target_tags"] = self._validate_target_tags(
                    json.loads(enrollment["target_tags"])
                )
            return response
