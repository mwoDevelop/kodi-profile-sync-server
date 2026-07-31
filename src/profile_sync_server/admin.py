"""Host-only administration for pairing and revocation."""

from __future__ import annotations

import argparse
import json

from .store import ProfileStore


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    pairing = commands.add_parser("create-pairing")
    pairing.add_argument("--logical-device-id", required=True)
    pairing.add_argument("--channel", required=True)
    pairing.add_argument("--role", action="append", default=["read"])
    pairing.add_argument("--target-tag", action="append", default=[])
    pairing.add_argument("--ttl-seconds", type=int, default=300)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("enrollment_id")
    backup = commands.add_parser("backup")
    backup.add_argument("--output", required=True)
    restore = commands.add_parser("restore")
    restore.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    if args.command == "restore":
        result = ProfileStore.restore_backup(args.input, args.database)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    store = ProfileStore(
        args.database,
        verify_signed_document=lambda _kind, _document: False,
    )
    if args.command == "create-pairing":
        result = store.create_pairing_code(
            args.logical_device_id,
            args.channel,
            roles=args.role,
            target_tags=args.target_tag,
            ttl_seconds=args.ttl_seconds,
        )
    elif args.command == "revoke":
        result = store.revoke_enrollment(args.enrollment_id)
    else:
        result = store.backup(args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
