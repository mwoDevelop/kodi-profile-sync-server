"""Loopback-only development HTTP API."""

from __future__ import annotations

import argparse
import json
import os
import stat
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .crypto import SignedDocumentVerifier
from .metadata import runtime_metadata
from .store import (
    Conflict,
    NotFound,
    ProfileStore,
    Unauthorized,
    ValidationError,
)


class Handler(BaseHTTPRequestHandler):
    store = None
    mode = "unconfigured"
    key_registry_path = None

    def _json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, status, document):
        payload = json.dumps(document, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _bearer(self):
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise Unauthorized("authentication failed")
        token = authorization[7:]
        if not token:
            raise Unauthorized("authentication failed")
        return token

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(
                200,
                {
                    "status": "ok",
                    "mode": self.mode,
                    **runtime_metadata(),
                },
            )
            return
        if parsed.path == "/ready":
            try:
                if not self.key_registry_path:
                    raise RuntimeError(
                        "verified key registry is not configured"
                    )
                registry = Path(self.key_registry_path)
                registry_stat = registry.stat()
                if (
                    not stat.S_ISREG(registry_stat.st_mode)
                    or not os.access(registry, os.R_OK)
                ):
                    raise RuntimeError("key registry is not a readable file")
                readiness = self.store.readiness()
            except (OSError, RuntimeError):
                self._send(
                    503,
                    {
                        "status": "not_ready",
                        "mode": self.mode,
                        **runtime_metadata(),
                    },
                )
                return
            self._send(
                200,
                {
                    "status": "ready",
                    "mode": self.mode,
                    "key_registry": "ready",
                    **runtime_metadata(),
                    **readiness,
                },
            )
            return
        parts = parsed.path.strip("/").split("/")
        if (
            len(parts) == 4
            and parts[:2] == ["v1", "enrollments"]
            and parts[3] == "assignment"
        ):
            query = parse_qs(parsed.query)
            channel = query.get("channel", [""])[0]
            self._dispatch(
                lambda: self.store.assignment(
                    parts[2], channel, self._bearer()
                )
            )
            return
        if (
            len(parts) == 5
            and parts[:2] == ["v1", "enrollments"]
            and parts[3] == "revisions"
        ):
            self._dispatch(
                lambda: self.store.revision(
                    parts[4], parts[2], self._bearer()
                )
            )
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self):
        parts = urlparse(self.path).path.strip("/").split("/")
        document = self._json()
        key = self.headers.get("Idempotency-Key", "")
        if parts == ["v1", "pair"]:
            self._dispatch(
                lambda: self.store.pair(
                    document["code"],
                    document["logical_device_id"],
                    document["channel"],
                    document["key_id"],
                    document["public_key"],
                )
            )
        elif parts == ["v1", "devices", "heartbeat"]:
            self._dispatch(
                lambda: self.store.heartbeat(document, self._bearer())
            )
        elif parts == ["v1", "revisions"]:
            self._dispatch(lambda: self.store.put_revision(document))
        elif len(parts) == 4 and parts[:2] == ["v1", "channels"]:
            channel = parts[2]
            action = parts[3]
            if action == "candidates":
                self._dispatch(
                    lambda: self.store.publish_candidate(
                        channel,
                        document["revision_id"],
                        document.get("base_revision"),
                        document.get("expected_candidate_head"),
                        key,
                    )
                )
            elif action == "assignments":
                self._dispatch(
                    lambda: self.store.assign_candidate(document, key)
                )
            elif action == "promote":
                self._dispatch(
                    lambda: self.store.promote(
                        channel,
                        document["candidate_revision"],
                        document.get("expected_active_revision"),
                        document["required_enrollments"],
                        document["event"],
                        key,
                    )
                )
            else:
                self._send(404, {"error": "not_found"})
        elif parts == ["v1", "reports"]:
            self._dispatch(lambda: self.store.record_report(document, key))
        else:
            self._send(404, {"error": "not_found"})

    def _dispatch(self, callback):
        try:
            self._send(200, callback())
        except ValidationError as error:
            self._send(400, {"error": str(error)})
        except Conflict as error:
            self._send(409, {"error": str(error)})
        except NotFound as error:
            self._send(404, {"error": str(error)})
        except Unauthorized as error:
            self._send(401, {"error": str(error)})
        except (KeyError, json.JSONDecodeError) as error:
            self._send(400, {"error": "invalid_request", "detail": str(error)})

    def log_message(self, _format, *_args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="allow a verified server to listen on a container interface",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--database", default="profile-sync-dev.sqlite")
    parser.add_argument(
        "--unsafe-accept-signatures",
        action="store_true",
        help="development only; never use for QNAP deployment",
    )
    parser.add_argument(
        "--key-registry",
        help="schema 1 JSON registry of trusted Ed25519 public keys",
    )
    args = parser.parse_args()
    if bool(args.unsafe_accept_signatures) == bool(args.key_registry):
        raise SystemExit(
            "choose exactly one of --key-registry or "
            "--unsafe-accept-signatures"
        )
    if args.listen not in {"127.0.0.1", "::1"} and (
        not args.allow_non_loopback or args.unsafe_accept_signatures
    ):
        raise SystemExit(
            "non-loopback requires --key-registry and "
            "--allow-non-loopback"
        )
    if args.key_registry:
        verifier = SignedDocumentVerifier.from_file(args.key_registry)
        Handler.mode = "verified-loopback"
        Handler.key_registry_path = str(Path(args.key_registry).resolve())
        bootstrap_keys = verifier.public_bundle(
            {"assignment", "promotion", "revision"}
        )
    else:
        verifier = lambda _kind, _document: True
        Handler.mode = "unsafe-loopback-dev"
        Handler.key_registry_path = None
        bootstrap_keys = {}
    Handler.store = ProfileStore(
        Path(args.database),
        verify_signed_document=verifier,
        bootstrap_keys=bootstrap_keys,
    )
    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
