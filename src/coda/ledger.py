from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from .capability import IssuedCapability
from .crypto import canonical_json_bytes, sha256_hex
from .models import DelegationCredential


@dataclass(frozen=True)
class LedgerRecord:
    commitment: str
    timestamp: int
    cod_digest: str
    capability_id: str


class MemoryCommitmentLedger:
    """
    In-memory append-only commitment ledger.

    This is deliberately NOT an IOTA implementation. It provides
    the ledger interface required by the reference implementation
    while keeping the cryptographic commitment semantics explicit.

    A production deployment can replace this component with an
    IOTA or other distributed-ledger adapter.
    """

    def __init__(self):
        self._records: List[LedgerRecord] = []

    def anchor_authorization(
        self,
        chain: Sequence[DelegationCredential],
        capability: IssuedCapability,
        timestamp: int,
    ) -> LedgerRecord:
        """
        Construct the post-authorization commitment

            C_del = H(CoD || Cap || t)

        using the canonical signed CoD, signed capability token,
        and authorization timestamp.
        """

        encoded_chain = canonical_json_bytes(
            [
                credential.to_dict()
                for credential in chain
            ]
        )

        commitment_material = (
            encoded_chain
            + b"\x00"
            + capability.token.encode("utf-8")
            + b"\x00"
            + str(timestamp).encode("ascii")
        )

        record = LedgerRecord(
            commitment=sha256_hex(
                commitment_material
            ),
            timestamp=timestamp,
            cod_digest=capability.cod_digest,
            capability_id=capability.capability_id,
        )

        self._records.append(record)

        return record

    def records(self) -> List[LedgerRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)
