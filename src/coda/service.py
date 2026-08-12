from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .authorization import AuthorizationService
from .models import (
    AuthorizationRequest,
    DelegationCredential,
)


class DelegationCredentialInput(BaseModel):
    delegation_id: str
    issuer_did: str
    subject_did: str
    scope: List[str]

    valid_from: int
    valid_until: int
    remaining_depth: int

    usage_constraints: Dict[str, int] = Field(
        default_factory=dict
    )
    context_constraints: Dict[str, str] = Field(
        default_factory=dict
    )

    signature: str

    def to_domain(self) -> DelegationCredential:
        return DelegationCredential(
            delegation_id=self.delegation_id,
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            scope=list(self.scope),
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            remaining_depth=self.remaining_depth,
            usage_constraints=dict(
                self.usage_constraints
            ),
            context_constraints=dict(
                self.context_constraints
            ),
            signature=self.signature,
        )


class AuthorizationInput(BaseModel):
    requester_did: str
    relying_domain: str
    action: str
    resource: str

    context: Dict[str, str] = Field(
        default_factory=dict
    )

    chain: List[DelegationCredentialInput]

    anchor_to_ledger: bool = True


def create_app(
    authorization_service: AuthorizationService,
    clock: Optional[Callable[[], int]] = None,
) -> FastAPI:
    """
    Create the CoDA relying-domain REST service.

    Security boundary:
      - clients may submit a signed Chain of Delegation;
      - clients may not add trusted DID keys;
      - clients may not change trusted root issuers;
      - clients may not change relying-domain policy;
      - authorization time is assigned by the server.

    DID trust configuration is therefore established outside
    the request path.
    """

    if clock is None:
        clock = lambda: int(time.time())

    app = FastAPI(
        title="CoDA Authorization Service",
        version="0.1.0",
        description=(
            "Bounded Chain-of-Delegation authorization "
            "for cross-domain Industrial Digital Twin agents."
        ),
    )

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "service": "coda-authorization",
            "relying_domain": (
                authorization_service.relying_domain
            ),
        }

    @app.post("/authorize")
    def authorize(payload: AuthorizationInput):
        chain = [
            credential.to_domain()
            for credential in payload.chain
        ]

        request = AuthorizationRequest(
            requester_did=payload.requester_did,
            relying_domain=payload.relying_domain,
            action=payload.action,
            resource=payload.resource,
            request_time=clock(),
            context=dict(payload.context),
        )

        outcome = authorization_service.authorize(
            request=request,
            chain=chain,
            anchor_to_ledger=payload.anchor_to_ledger,
        )

        response = {
            "accepted": outcome.accepted,
            "reason": outcome.reason,
            "effective_scope": (
                outcome.effective_scope
            ),
            "capability": None,
            "ledger": None,
        }

        if outcome.capability is not None:
            response["capability"] = {
                "token": outcome.capability.token,
                "capability_id": (
                    outcome.capability.capability_id
                ),
                "subject_did": (
                    outcome.capability.subject_did
                ),
                "scope": outcome.capability.scope,
                "issued_at": (
                    outcome.capability.issued_at
                ),
                "expires_at": (
                    outcome.capability.expires_at
                ),
                "nonce": outcome.capability.nonce,
                "h_cod": (
                    outcome.capability.cod_digest
                ),
            }

        if outcome.ledger_record is not None:
            response["ledger"] = {
                "commitment": (
                    outcome.ledger_record.commitment
                ),
                "timestamp": (
                    outcome.ledger_record.timestamp
                ),
                "h_cod": (
                    outcome.ledger_record.cod_digest
                ),
                "capability_id": (
                    outcome.ledger_record.capability_id
                ),
            }

        return response

    return app
