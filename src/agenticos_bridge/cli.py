"""Local operator interface; deliberately no HTTP key-management endpoints."""

import argparse
import json
import os
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from agenticos_bridge.access import AccessRegistry
from agenticos_bridge.errors import BridgeError
from agenticos_bridge.models import Provider


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage reviewed AgenticOS deployment access")
    parser.add_argument(
        "--registry",
        type=Path,
        default=Path(os.environ.get("BRIDGE_ACCESS_REGISTRY", "/data/access.sqlite3")),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize an empty, closed access registry")
    issue = commands.add_parser("issue", help="Issue an approved key once, to standard output")
    issue.add_argument("--origin", required=True)
    issue.add_argument("--contact", required=True, help="Operator incident contact")
    issue.add_argument(
        "--agreement-reference", required=True, help="Reference to reviewed terms/DPA"
    )
    issue.add_argument(
        "--provider", choices=["google", "microsoft", "slack"], action="append", required=True
    )
    issue.add_argument("--days", type=int, default=90)
    commands.add_parser("list", help="List enrollment metadata, never keys or hashes")
    revoke = commands.add_parser("revoke", help="Refuse subsequent bridge operations for a key")
    revoke.add_argument("id")
    args = parser.parse_args()
    registry = AccessRegistry(args.registry.resolve())
    try:
        if args.command == "init":
            registry.initialize()
        elif args.command == "issue":
            if not 1 <= args.days <= 365:
                parser.error("--days must be between 1 and 365")
            providers: list[Provider] = args.provider
            enrollment, key = registry.issue(
                origin=args.origin,
                contact=args.contact,
                agreement_reference=args.agreement_reference,
                providers=providers,
                expires_at=int((datetime.now(UTC) + timedelta(days=args.days)).timestamp()),
            )
            print(
                json.dumps(
                    {"enrollment": enrollment.model_dump(), "access_key": key.get_secret_value()}
                )
            )
        elif args.command == "list":
            print(json.dumps([item.model_dump() for item in registry.list_enrollments()]))
        elif args.command == "revoke":
            registry.revoke(args.id)
    except (BridgeError, ValueError, OSError, sqlite3.Error) as exc:
        print(
            exc.code if isinstance(exc, BridgeError) else "Invalid input or registry unavailable",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
