import pytest

from profile_sync_server.http import transport_mode


def test_non_loopback_verified_server_requires_tls_pair():
    with pytest.raises(SystemExit, match="non-loopback requires TLS"):
        transport_mode(
            listen="0.0.0.0",
            allow_non_loopback=True,
            unsafe_accept_signatures=False,
            key_registry="keys.json",
            tls_cert=None,
            tls_key=None,
        )

    with pytest.raises(SystemExit, match="certificate and key together"):
        transport_mode(
            listen="0.0.0.0",
            allow_non_loopback=True,
            unsafe_accept_signatures=False,
            key_registry="keys.json",
            tls_cert="server.crt",
            tls_key=None,
        )


def test_transport_mode_distinguishes_development_and_production():
    assert transport_mode(
        listen="127.0.0.1",
        allow_non_loopback=False,
        unsafe_accept_signatures=True,
        key_registry=None,
        tls_cert=None,
        tls_key=None,
    ) == "unsafe-loopback-dev"

    assert transport_mode(
        listen="0.0.0.0",
        allow_non_loopback=True,
        unsafe_accept_signatures=False,
        key_registry="keys.json",
        tls_cert="server.crt",
        tls_key="server.key",
    ) == "verified-tls"
