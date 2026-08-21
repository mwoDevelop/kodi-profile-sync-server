"""Loopback-only development HTTP API."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import ssl
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .broker import BrokerUnavailable, SecretBrokerClient
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
    surface = "unconfigured"
    max_request_bytes = 1024 * 1024
    secret_broker = None

    def _json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValidationError("invalid content length") from error
        if length < 0 or length > self.max_request_bytes:
            raise ValidationError("request body is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def _send(self, status, document):
        payload = json.dumps(document, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, status, payload, media_type):
        self.send_response(status)
        self.send_header("Content-Type", media_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
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
            self.surface == "integration"
            and parts == ["v1", "integration", "fleet"]
        ):
            self._dispatch(self.store.integration_fleet_snapshot)
            return
        if (
            self.surface == "integration"
            and parts == ["v1", "integration", "rollouts"]
        ):
            self._dispatch(self.store.integration_rollout_snapshot)
            return
        if (
            self.surface == "consumer"
            and len(parts) == 5
            and parts[:2] == ["v1", "enrollments"]
            and parts[3:] == ["secrets", "youtube-session-v1"]
        ):
            if self.secret_broker is None:
                self._send(404, {"error": "secret_broker_not_configured"})
                return
            self._dispatch(
                lambda: self.secret_broker.envelope(
                    self.store.secret_envelope_request(
                        parts[2], self._bearer()
                    )
                )
            )
            return
        if (
            self.surface == "consumer"
            and
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
            self.surface == "consumer"
            and len(parts) == 5
            and parts[:2] == ["v1", "enrollments"]
            and parts[3] == "blobs"
        ):
            self._dispatch_bytes(
                lambda: self.store.blob(
                    parts[4], parts[2], self._bearer()
                )
            )
            return
        if (
            self.surface == "consumer"
            and
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
        if self.surface == "integration":
            self._send(405, {"error": "read_only"})
            return
        parts = urlparse(self.path).path.strip("/").split("/")
        try:
            document = self._json()
        except (ValidationError, json.JSONDecodeError) as error:
            self._send(400, {"error": str(error) or "invalid_request"})
            return
        key = self.headers.get("Idempotency-Key", "")
        if self.surface == "consumer" and parts == ["v1", "pair"]:
            self._dispatch(
                lambda: self.store.pair(
                    document["code"],
                    document["logical_device_id"],
                    document["channel"],
                    document["key_id"],
                    document["public_key"],
                    document.get("encryption_key_id"),
                    document.get("encryption_public_key"),
                )
            )
        elif self.surface == "consumer" and parts == ["v1", "devices", "heartbeat"]:
            self._dispatch(
                lambda: self.store.heartbeat(document, self._bearer())
            )
        elif self.surface == "admin" and parts == ["v1", "revisions"]:
            self._dispatch(
                lambda: self.store.put_revision(
                    self.store.authorize_admin_request(
                        document, "put_revision", key
                    )
                )
            )
        elif (
            self.surface == "admin"
            and len(parts) == 3
            and parts[:2] == ["v1", "blobs"]
        ):
            self._dispatch(
                lambda: self._put_blob(parts[2], document, key)
            )
        elif (
            self.surface == "admin"
            and len(parts) == 4
            and parts[:2] == ["v1", "channels"]
        ):
            channel = parts[2]
            action = parts[3]
            if action == "candidates":
                self._dispatch(
                    lambda: self._publish_candidate(
                        channel, document, key
                    )
                )
            elif action == "assignments":
                self._dispatch(
                    lambda: self.store.assign_candidate(
                        self.store.authorize_admin_request(
                            document, "assign_candidate", key
                        ),
                        key,
                    )
                )
            elif action == "bootstrap-assignments":
                self._dispatch(
                    lambda: self.store.bootstrap_active(
                        channel,
                        self.store.authorize_admin_request(
                            document, "bootstrap_active", key
                        ),
                        key,
                    )
                )
            elif action == "promote":
                self._dispatch(
                    lambda: self._promote(channel, document, key)
                )
            else:
                self._send(404, {"error": "not_found"})
        elif self.surface == "consumer" and parts == ["v1", "reports"]:
            self._dispatch(lambda: self.store.record_report(document, key))
        else:
            self._send(404, {"error": "not_found"})

    def _publish_candidate(self, channel, document, key):
        payload = self.store.authorize_admin_request(
            document, "publish_candidate", key
        )
        return self.store.publish_candidate(
            channel,
            payload["revision_id"],
            payload.get("base_revision"),
            payload.get("expected_candidate_head"),
            key,
        )

    def _put_blob(self, digest, document, key):
        payload = self.store.authorize_admin_request(
            document, "put_blob", key
        )
        encoded = payload.get("content_base64")
        if (
            not isinstance(encoded, str)
            or "=" in encoded
            or len(encoded) > 12 * 1024 * 1024
        ):
            raise ValidationError("invalid blob encoding")
        try:
            content = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (ValueError, binascii.Error) as error:
            raise ValidationError("invalid blob encoding") from error
        return self.store.put_blob(digest, content, payload.get("media_type"))

    def _promote(self, channel, document, key):
        payload = self.store.authorize_admin_request(
            document, "promote", key
        )
        return self.store.promote(
            channel,
            payload["candidate_revision"],
            payload.get("expected_active_revision"),
            payload["required_enrollments"],
            payload["event"],
            key,
            active_assignments=payload.get("active_assignments"),
        )

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
        except BrokerUnavailable:
            self._send(503, {"error": "secret_broker_unavailable"})
        except (KeyError, json.JSONDecodeError) as error:
            self._send(400, {"error": "invalid_request", "detail": str(error)})

    def _dispatch_bytes(self, callback):
        try:
            payload, media_type = callback()
            self._send_bytes(200, payload, media_type)
        except ValidationError as error:
            self._send(400, {"error": str(error)})
        except Conflict as error:
            self._send(409, {"error": str(error)})
        except NotFound as error:
            self._send(404, {"error": str(error)})
        except Unauthorized as error:
            self._send(401, {"error": str(error)})

    def log_message(self, _format, *_args):
        return


def transport_mode(
    *,
    listen,
    allow_non_loopback,
    unsafe_accept_signatures,
    key_registry,
    tls_cert,
    tls_key,
):
    if bool(unsafe_accept_signatures) == bool(key_registry):
        raise SystemExit(
            "choose exactly one of --key-registry or "
            "--unsafe-accept-signatures"
        )
    if bool(tls_cert) != bool(tls_key):
        raise SystemExit("provide TLS certificate and key together")
    non_loopback = listen not in {"127.0.0.1", "::1"}
    if non_loopback and (
        not allow_non_loopback or unsafe_accept_signatures
    ):
        raise SystemExit(
            "non-loopback requires --key-registry and "
            "--allow-non-loopback"
        )
    if non_loopback and not tls_cert:
        raise SystemExit("non-loopback requires TLS certificate and key")
    if tls_cert:
        return "verified-tls"
    if key_registry:
        return "verified-loopback"
    return "unsafe-loopback-dev"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="allow a verified server to listen on a container interface",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--admin-listen", default="127.0.0.1")
    parser.add_argument("--admin-port", type=int, default=8766)
    parser.add_argument("--integration-listen")
    parser.add_argument("--integration-port", type=int, default=8767)
    parser.add_argument("--integration-client-ca")
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
    parser.add_argument("--tls-cert", help="PEM TLS certificate chain")
    parser.add_argument("--tls-key", help="PEM TLS private key")
    parser.add_argument("--secret-broker-url")
    parser.add_argument("--secret-broker-ca")
    parser.add_argument("--secret-broker-cert")
    parser.add_argument("--secret-broker-key")
    args = parser.parse_args()
    mode = transport_mode(
        listen=args.listen,
        allow_non_loopback=args.allow_non_loopback,
        unsafe_accept_signatures=args.unsafe_accept_signatures,
        key_registry=args.key_registry,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
    )
    if args.key_registry:
        verifier = SignedDocumentVerifier.from_file(args.key_registry)
        Handler.mode = mode
        Handler.key_registry_path = str(Path(args.key_registry).resolve())
        bootstrap_keys = verifier.public_bundle(
            {"assignment", "promotion", "revision"}
        )
    else:
        verifier = lambda _kind, _document: True
        Handler.mode = mode
        Handler.key_registry_path = None
        bootstrap_keys = {}
    store = ProfileStore(
        Path(args.database),
        verify_signed_document=verifier,
        bootstrap_keys=bootstrap_keys,
    )
    broker_values = (
        args.secret_broker_url,
        args.secret_broker_ca,
        args.secret_broker_cert,
        args.secret_broker_key,
    )
    if any(broker_values) and not all(broker_values):
        raise SystemExit("provide all Secret Broker mTLS options together")
    secret_broker = (
        SecretBrokerClient(*broker_values) if all(broker_values) else None
    )
    if args.admin_listen not in {"127.0.0.1", "::1"}:
        raise SystemExit("admin listener must remain on loopback")

    class ConsumerHandler(Handler):
        pass

    class AdminHandler(Handler):
        pass

    class IntegrationHandler(Handler):
        pass

    for handler, surface, handler_mode in (
        (ConsumerHandler, "consumer", mode),
        (AdminHandler, "admin", "verified-loopback-admin"),
        (IntegrationHandler, "integration", "verified-mtls-integration"),
    ):
        handler.store = store
        handler.surface = surface
        handler.mode = handler_mode
        handler.key_registry_path = Handler.key_registry_path
        handler.secret_broker = secret_broker
        if surface == "admin":
            handler.max_request_bytes = 12 * 1024 * 1024

    server = ThreadingHTTPServer((args.listen, args.port), ConsumerHandler)
    admin_server = ThreadingHTTPServer(
        (args.admin_listen, args.admin_port), AdminHandler
    )
    integration_server = None
    if bool(args.integration_listen) != bool(args.integration_client_ca):
        raise SystemExit(
            "provide --integration-listen and --integration-client-ca together"
        )
    if args.integration_listen:
        if not args.tls_cert:
            raise SystemExit("integration listener requires TLS certificate and key")
        integration_server = ThreadingHTTPServer(
            (args.integration_listen, args.integration_port), IntegrationHandler
        )
        integration_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        integration_context.minimum_version = ssl.TLSVersion.TLSv1_2
        integration_context.load_cert_chain(args.tls_cert, args.tls_key)
        integration_context.load_verify_locations(args.integration_client_ca)
        integration_context.verify_mode = ssl.CERT_REQUIRED
        integration_server.socket = integration_context.wrap_socket(
            integration_server.socket, server_side=True
        )
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    admin_thread = threading.Thread(
        target=admin_server.serve_forever,
        name="profile-sync-admin",
        daemon=True,
    )
    admin_thread.start()
    integration_thread = None
    if integration_server is not None:
        integration_thread = threading.Thread(
            target=integration_server.serve_forever,
            name="profile-sync-integration",
            daemon=True,
        )
        integration_thread.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        admin_server.shutdown()
        admin_server.server_close()
        if integration_server is not None:
            integration_server.shutdown()
            integration_server.server_close()
        server.server_close()


if __name__ == "__main__":
    main()
