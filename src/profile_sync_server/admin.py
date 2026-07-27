"""Host-only administration for pairing and revocation."""

from __future__ import annotations

import argparse
import json

from .store import ProfileStore


def main():
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
    args = parser.parse_args()
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
    else:
        result = store.revoke_enrollment(args.enrollment_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
