from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class RevocationRecord:
    delegation_id: str
    revoked_at: int
    reason: str


class RevocationRegistry:
    """
    In-memory revocation registry used by the reference implementation.

    A production deployment may replace this class with a persistent or
    distributed revocation service without changing CoDA validation logic.
    """

    def __init__(self):
        self._records: Dict[str, RevocationRecord] = {}

    def revoke(
        self,
        delegation_id: str,
        revoked_at: int,
        reason: str,
    ) -> RevocationRecord:
        record = RevocationRecord(
            delegation_id=delegation_id,
            revoked_at=revoked_at,
            reason=reason,
        )

        self._records[delegation_id] = record
        return record

    def is_revoked(self, delegation_id: str) -> bool:
        return delegation_id in self._records

    def get(
        self,
        delegation_id: str,
    ) -> Optional[RevocationRecord]:
        return self._records.get(delegation_id)

    def clear(self) -> None:
        self._records.clear()
