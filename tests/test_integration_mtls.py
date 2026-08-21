import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def certificates(root):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required for the mTLS integration test")
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Profile Sync Integration Test CA",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        cwd=root,
    )
    for name, common_name, extension in (
        ("server", "127.0.0.1", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
        ("client", "kodi-control-plane", "extendedKeyUsage=clientAuth\n"),
    ):
        run(
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-keyout",
            f"{name}.key",
            "-out",
            f"{name}.csr",
            cwd=root,
        )
        (root / f"{name}.ext").write_text(extension, encoding="utf-8")
        run(
            "openssl",
            "x509",
            "-req",
            "-in",
            f"{name}.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            f"{name}.ext",
            "-out",
            f"{name}.crt",
            cwd=root,
        )


def test_integration_surface_requires_mtls_and_is_read_only(tmp_path):
    certificates(tmp_path)
    consumer_port = free_port()
    admin_port = free_port()
    integration_port = free_port()
    repository = os.path.dirname(os.path.dirname(__file__))
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.path.join(repository, "src")
    process = subprocess.Popen(
        (
            sys.executable,
            "-m",
            "profile_sync_server.http",
            "--listen",
            "127.0.0.1",
            "--port",
            str(consumer_port),
            "--admin-port",
            str(admin_port),
            "--database",
            str(tmp_path / "state.sqlite"),
            "--unsafe-accept-signatures",
            "--tls-cert",
            str(tmp_path / "server.crt"),
            "--tls-key",
            str(tmp_path / "server.key"),
            "--integration-listen",
            "127.0.0.1",
            "--integration-port",
            str(integration_port),
            "--integration-client-ca",
            str(tmp_path / "ca.crt"),
        ),
        cwd=repository,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    endpoint = f"https://127.0.0.1:{integration_port}"
    client = ssl.create_default_context(cafile=tmp_path / "ca.crt")
    client.load_cert_chain(tmp_path / "client.crt", tmp_path / "client.key")
    try:
        fleet = None
        for _attempt in range(40):
            try:
                with urllib.request.urlopen(
                    endpoint + "/v1/integration/fleet",
                    context=client,
                    timeout=1,
                ) as response:
                    fleet = json.load(response)
                break
            except (OSError, urllib.error.URLError, ssl.SSLError):
                time.sleep(0.05)
        assert fleet == {
            "schema": 1,
            "generated_at": fleet["generated_at"],
            "database_schema": 5,
            "devices": [],
            "channels": [],
        }
        no_client = ssl.create_default_context(cafile=tmp_path / "ca.crt")
        with pytest.raises((urllib.error.URLError, ssl.SSLError)):
            urllib.request.urlopen(
                endpoint + "/v1/integration/fleet",
                context=no_client,
                timeout=1,
            )
        request = urllib.request.Request(
            endpoint + "/v1/integration/fleet", data=b"{}", method="POST"
        )
        with pytest.raises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(request, context=client, timeout=1)
        assert rejected.value.code == 405
        assert json.load(rejected.value)["error"] == "read_only"
        with urllib.request.urlopen(
            endpoint + "/v1/integration/rollouts",
            context=client,
            timeout=1,
        ) as response:
            rollouts = json.load(response)
        assert rollouts["schema"] == 1
        assert rollouts["assignments"] == []
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
