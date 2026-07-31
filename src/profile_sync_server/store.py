"""Transactional SQLite state for immutable Kodi profile revisions."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
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
ROLES = {"read", "publish"}


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


def revision_identity(manifest):
    return {
        key: value
        for key, value in manifest.items()
        if key not in {"revision_id", "created_utc", "signature"}
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
                    token_sha256 TEXT NOT NULL,
                    target_tags TEXT NOT NULL DEFAULT '[]',
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_seen_at INTEGER,
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
        if integrity != "ok" or version != DATABASE_SCHEMA_VERSION:
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

    @classmethod
    def restore_backup(cls, source, destination):
        source = cls._validated_database(source)
        return cls._publish_database(
            source, destination, "restore target already exists"
        )

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
                        roles, key_id, public_key, token_sha256, target_tags,
                        revoked, created_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL)
                    """,
                    (
                        enrollment_id,
                        logical_device_id,
                        generation,
                        channel,
                        canonical_json(roles).decode("utf-8"),
                        key_id,
                        public_key,
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
            database.execute(
                "UPDATE enrollments SET last_seen_at=? WHERE enrollment_id=?",
                (int(time.time()), enrollment_id),
            )
        return {
            "enrollment_id": enrollment_id,
            "status": "ok",
            "revoked": False,
        }

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
                    "SELECT candidate_revision FROM channels WHERE channel=?",
                    (channel,),
                ).fetchone()
                if not row or row["candidate_revision"] != revision_id:
                    raise Conflict("assignment does not target current candidate")
                enrolled = database.execute(
                    """
                    SELECT channel, target_tags, revoked
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
                }

            return self._idempotent(
                database, idempotency_key, "assign_candidate", action
            )

    def bootstrap_active(self, channel, document, idempotency_key):
        """Create a signed client-compatible assignment for active state.

        The server never signs assignments.  This operation only accepts an
        offline-promoter-signed document and constrains it to the exact active
        revision and an existing eligible enrollment.  The stored assignment
        remains ``candidate`` for compatibility with released read-only
        clients, which already require and verify that signed assignment kind.
        """
        if not CHANNEL.fullmatch(str(channel)):
            raise ValidationError("invalid channel")
        if not self.verify_signed_document("assignment", document):
            raise ValidationError("invalid assignment signature")
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
                    "SELECT active_revision FROM channels WHERE channel=?",
                    (channel,),
                ).fetchone()
                if not current or current["active_revision"] != revision_id:
                    raise Conflict(
                        "bootstrap assignment does not target active revision"
                    )
                enrolled = database.execute(
                    """
                    SELECT channel, target_tags, revoked
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
                    "assignment_source": "active-bootstrap",
                    "target_tags": target_tags,
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
            if result not in {"success", "failure"}:
                raise ValidationError("invalid report result")

            def action():
                assignment = database.execute(
                    """
                    SELECT revision_id FROM assignments
                    WHERE enrollment_id=? AND channel=?
                    """,
                    (enrollment, channel),
                ).fetchone()
                if not assignment or assignment["revision_id"] != revision_id:
                    raise Conflict("report does not match assignment")
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
    ):
        if not self.verify_signed_document("promotion", event):
            raise ValidationError("invalid promotion signature")
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
                return {
                    "channel": channel,
                    "active_revision": candidate_revision,
                    "generation": generation,
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
