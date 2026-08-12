from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class DelegationCredential:
    """
    CoDA delegation credential.

    A credential transfers a bounded subset of authority from issuer_did
    to subject_did.
    """

    delegation_id: str
    issuer_did: str
    subject_did: str
    scope: List[str]

    valid_from: int
    valid_until: int

    remaining_depth: int

    usage_constraints: Dict[str, int] = field(default_factory=dict)
    context_constraints: Dict[str, str] = field(default_factory=dict)

    signature: str = ""

    def signing_payload(self) -> Dict[str, Any]:
        """Return the fields covered by the issuer signature."""
        return {
            "delegation_id": self.delegation_id,
            "issuer_did": self.issuer_did,
            "subject_did": self.subject_did,
            "scope": sorted(self.scope),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "remaining_depth": self.remaining_depth,
            "usage_constraints": dict(sorted(self.usage_constraints.items())),
            "context_constraints": dict(
                sorted(self.context_constraints.items())
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        data = self.signing_payload()
        data["signature"] = self.signature
        return data


@dataclass
class AuthorizationRequest:
    requester_did: str
    relying_domain: str
    action: str
    resource: str
    request_time: int
    context: Dict[str, str] = field(default_factory=dict)


@dataclass
class ValidationResult:
    accepted: bool
    effective_scope: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @classmethod
    def allow(cls, scope: List[str]) -> "ValidationResult":
        return cls(
            accepted=True,
            effective_scope=scope,
            errors=[],
        )

    @classmethod
    def deny(cls, *errors: str) -> "ValidationResult":
        return cls(
            accepted=False,
            effective_scope=[],
            errors=list(errors),
        )
