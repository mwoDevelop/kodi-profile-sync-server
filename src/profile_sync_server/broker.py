"""Strict mTLS client for the internal Secret Broker."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request


class BrokerUnavailable(RuntimeError):
    pass


class SecretBrokerClient:
    def __init__(self, base_url, ca, certificate, private_key, timeout=10):
        if not str(base_url).startswith("https://"):
            raise ValueError("Secret Broker URL must use HTTPS")
        context = ssl.create_default_context(cafile=ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        self.base_url = str(base_url).rstrip("/")
        self.timeout = timeout
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )

    def envelope(self, identity):
        payload = json.dumps(
            identity, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + "/v1/envelopes",
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except (OSError, urllib.error.URLError) as error:
            raise BrokerUnavailable("Secret Broker is unavailable") from error
        with response:
            body = response.read(128 * 1024 + 1)
        if len(body) > 128 * 1024:
            raise BrokerUnavailable("Secret Broker response is too large")
        try:
            document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise BrokerUnavailable("Secret Broker returned invalid JSON") from error
        if not isinstance(document, dict) or document.get("envelope_type") != (
            "secret-envelope-v1"
        ):
            raise BrokerUnavailable("Secret Broker returned invalid envelope")
        return document
