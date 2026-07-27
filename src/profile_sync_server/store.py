"""Transactional SQLite state for immutable Kodi profile revisions."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path


CHANNEL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
REVISION = re.compile(r"^sha256:[a-f0-9]{64}$")
ENROLLMENT = re.compile(r"^enr:[A-Za-z0-9._-]{8,128}$")


class ValidationError(ValueError):
    pass


class Conflict(RuntimeError):
    pass


class NotFound(RuntimeError):
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
    if not isinstance(manifest, dict) or manifest.get("schema") != 2:
        raise ValidationError("unsupported revision schema")
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
    def __init__(self, path, verify_signed_document):
        if verify_signed_document is None:
            raise ValueError("a signed-document verifier is required")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.verify_signed_document = verify_signed_document
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
                """
            )

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
                }

            return self._idempotent(
                database, idempotency_key, "assign_candidate", action
            )

    def record_report(self, document, idempotency_key):
        if not self.verify_signed_document("report", document):
            raise ValidationError("invalid report signature")
        enrollment = document.get("enrollment_id")
        channel = document.get("channel")
        revision_id = document.get("revision_id")
        result = document.get("result")
        if result not in {"success", "failure"}:
            raise ValidationError("invalid report result")
        with self.connect() as database:
            database.execute("BEGIN IMMEDIATE")

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

    def assignment(self, enrollment_id, channel):
        with self.connect() as database:
            assigned = database.execute(
                """
                SELECT revision_id, assignment_kind FROM assignments
                WHERE enrollment_id=? AND channel=?
                """,
                (enrollment_id, channel),
            ).fetchone()
            if assigned:
                return dict(assigned)
            current = database.execute(
                "SELECT active_revision FROM channels WHERE channel=?",
                (channel,),
            ).fetchone()
            if not current or current["active_revision"] is None:
                raise NotFound("channel has no active revision")
            return {
                "revision_id": current["active_revision"],
                "assignment_kind": "active",
            }
