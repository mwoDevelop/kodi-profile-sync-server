from profile_sync_server.metadata import build_identifier, runtime_metadata
from profile_sync_server.store import ProfileStore


def test_runtime_metadata_redacts_invalid_build(monkeypatch):
    monkeypatch.setenv("PROFILE_SYNC_BUILD", "secret value with spaces")

    metadata = runtime_metadata()

    assert metadata["service"] == "kodi-profile-sync-server"
    assert metadata["api_version"] == "v1"
    assert metadata["database_schema"] == 5
    assert metadata["build"] == "invalid"


def test_build_identifier_accepts_commit_digest(monkeypatch):
    monkeypatch.setenv("PROFILE_SYNC_BUILD", "git:0123456789abcdef")

    assert build_identifier() == "git:0123456789abcdef"


def test_store_readiness_reports_migrated_schema(tmp_path):
    store = ProfileStore(
        tmp_path / "state.sqlite",
        verify_signed_document=lambda _kind, _document: True,
    )

    assert store.readiness() == {
        "database": "ready",
        "database_schema": 5,
    }
