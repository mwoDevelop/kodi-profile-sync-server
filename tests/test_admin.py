import json

from profile_sync_server.admin import main
from profile_sync_server.store import ProfileStore


def test_admin_backup_and_offline_restore(tmp_path, capsys):
    database = tmp_path / "state.sqlite"
    ProfileStore(database, lambda _kind, _document: True)
    backup = tmp_path / "backup.sqlite"

    assert main(
        ["--database", str(database), "backup", "--output", str(backup)]
    ) == 0
    backup_result = json.loads(capsys.readouterr().out)
    assert backup_result["bytes"] > 0

    database.unlink()
    assert main(
        ["--database", str(database), "restore", "--input", str(backup)]
    ) == 0
    restore_result = json.loads(capsys.readouterr().out)
    assert restore_result["bytes"] > 0
    assert ProfileStore(
        database, lambda _kind, _document: True
    ).readiness()["database"] == "ready"
