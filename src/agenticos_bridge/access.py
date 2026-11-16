"""Console-managed deployment access. Stores only hashes and enrollment metadata."""

import hashlib
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, SecretStr

from agenticos_bridge.errors import BridgeError
from agenticos_bridge.models import Provider, StartRequest


class Enrollment(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    origin: str
    contact: str
    agreement_reference: str
    providers: list[Provider]
    created_at: int
    expires_at: int
    revoked_at: int | None = None


def validate_origin(value: str) -> str:
    """Reuse the callback contract, rejecting wildcards and non-origin components."""
    url = urlsplit(value)
    if url.path or url.query or url.fragment or value != f"{url.scheme}://{url.netloc}":
        raise ValueError("Use an exact HTTPS origin without a trailing slash")
    StartRequest.validate_callback(value + "/api/me/mcp-connections/oauth/callback")
    if "*" in (url.hostname or ""):
        raise ValueError("Wildcards are not permitted")
    return value


class AccessRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(descriptor)
        self.path.chmod(0o600)
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS enrollments "
                "(id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, record TEXT NOT NULL)"
            )
        self.path.chmod(0o600)

    def issue(
        self,
        *,
        origin: str,
        contact: str,
        agreement_reference: str,
        providers: list[Provider],
        expires_at: int,
    ) -> tuple[Enrollment, SecretStr]:
        origin = validate_origin(origin)
        now = int(datetime.now(UTC).timestamp())
        if (
            expires_at <= now
            or not providers
            or not contact.strip()
            or not agreement_reference.strip()
        ):
            raise ValueError(
                "Contact, agreement reference, providers and a future expiry are required"
            )
        enrollment = Enrollment(
            id=secrets.token_hex(16),
            origin=origin,
            contact=contact,
            agreement_reference=agreement_reference,
            providers=sorted(set(providers)),
            created_at=now,
            expires_at=expires_at,
        )
        key = f"ab_{enrollment.id}.{secrets.token_urlsafe(32)}"
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute(
                "INSERT INTO enrollments VALUES (?, ?, ?)",
                (
                    enrollment.id,
                    hashlib.sha256(key.encode()).hexdigest(),
                    enrollment.model_dump_json(),
                ),
            )
        return enrollment, SecretStr(key)

    def _read(self, identifier: str) -> tuple[str, Enrollment]:
        try:
            with closing(
                sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=2)
            ) as db:
                row = db.execute(
                    "SELECT key_hash, record FROM enrollments WHERE id = ?", (identifier,)
                ).fetchone()
        except sqlite3.OperationalError:
            raise BridgeError("access_registry_unavailable") from None
        if row is None:
            raise BridgeError("access_denied")
        key_hash, record = row
        if not isinstance(key_hash, str) or not isinstance(record, str):
            raise RuntimeError("Invalid access registry record")
        return key_hash, Enrollment.model_validate_json(record)

    def require_active(self, identifier: str, provider: Provider) -> Enrollment:
        _, enrollment = self._read(identifier)
        if (
            enrollment.revoked_at is not None
            or enrollment.expires_at <= int(datetime.now(UTC).timestamp())
            or provider not in enrollment.providers
        ):
            raise BridgeError("access_denied")
        return enrollment

    def authenticate(
        self, key: str | None, provider: Provider, origin: str | None = None
    ) -> Enrollment:
        if not key or len(key) > 256 or not key.startswith("ab_"):
            raise BridgeError("access_denied")
        identifier = key[3:].split(".", 1)[0]
        key_hash, enrollment = self._read(identifier)
        if not secrets.compare_digest(key_hash, hashlib.sha256(key.encode()).hexdigest()):
            raise BridgeError("access_denied")
        enrollment = self.require_active(enrollment.id, provider)
        if origin is not None and origin != enrollment.origin:
            raise BridgeError("access_denied")
        return enrollment

    def list_enrollments(self) -> list[Enrollment]:
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            rows = db.execute("SELECT record FROM enrollments ORDER BY id").fetchall()
        return [Enrollment.model_validate_json(row[0]) for row in rows]

    def revoke(self, identifier: str) -> None:
        # The conditional SQL update preserves the original revocation time on retries.
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            cursor = db.execute(
                "UPDATE enrollments SET record = json_set(record, '$.revoked_at', ?) "
                "WHERE id = ? AND json_extract(record, '$.revoked_at') IS NULL",
                (int(datetime.now(UTC).timestamp()), identifier),
            )
            if not cursor.rowcount:
                self._read(identifier)
