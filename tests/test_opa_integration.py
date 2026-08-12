from __future__ import annotations

import os

import httpx
import pytest

from coda.authorization import AuthorizationService
from coda.capability import CapabilityService
from coda.credentials import sign_credential
from coda.crypto import generate_ed25519_keypair
from coda.did import DIDRegistry
from coda.ledger import MemoryCommitmentLedger
from coda.models import (
    AuthorizationRequest,
    DelegationCredential,
)
from coda.policy import OPAPolicyEngine
from coda.revocation import RevocationRegistry
from coda.validator import CoDValidator


NOW = 1_750_000_000

DAM_A = "did:coda:factory-a:dam-a"
TWIN_AGENT = "did:coda:factory-a:twin-agent"
DAM_B = "did:coda:vendor-b:dam-b"
VENDOR_AGENT = "did:coda:vendor-b:vendor-agent"

OPA_URL = (
    "http://localhost:8181/"
    "v1/data/coda/authz/decision"
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_OPA_INTEGRATION") != "1",
    reason=(
        "set RUN_OPA_INTEGRATION=1 "
        "to test against a live OPA instance"
    ),
)


def opa_available() -> bool:
    try:
        response = httpx.get(
            "http://localhost:8181/health",
            timeout=1.0,
        )
        return response.status_code == 200
    except httpx.HTTPError:
        return False


def build_environment():
    if not opa_available():
        pytest.fail(
            "RUN_OPA_INTEGRATION=1 but OPA is not reachable"
        )

    identities = {}

    for did in [
        DAM_A,
        TWIN_AGENT,
        DAM_B,
        VENDOR_AGENT,
    ]:
        identities[did] = generate_ed25519_keypair()

    registry = DIDRegistry()

    for did, (_, public_key) in identities.items():
        registry.register(did, public_key)

    revocations = RevocationRegistry()

    d1 = DelegationCredential(
        delegation_id="opa-dc-001",
        issuer_did=DAM_A,
        subject_did=TWIN_AGENT,
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
        ],
        valid_from=NOW - 100,
        valid_until=NOW + 3600,
        remaining_depth=2,
        usage_constraints={
            "max_delegations": 2,
            "max_capabilities": 10,
        },
        context_constraints={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )
    sign_credential(d1, identities[DAM_A][0])

    d2 = DelegationCredential(
        delegation_id="opa-dc-002",
        issuer_did=TWIN_AGENT,
        subject_did=DAM_B,
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
        ],
        valid_from=NOW - 50,
        valid_until=NOW + 1800,
        remaining_depth=1,
        usage_constraints={
            "max_delegations": 1,
            "max_capabilities": 5,
        },
        context_constraints={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )
    sign_credential(d2, identities[TWIN_AGENT][0])

    d3 = DelegationCredential(
        delegation_id="opa-dc-003",
        issuer_did=DAM_B,
        subject_did=VENDOR_AGENT,
        scope=[
            "diagnostics:read",
        ],
        valid_from=NOW - 10,
        valid_until=NOW + 900,
        remaining_depth=0,
        usage_constraints={
            "max_delegations": 0,
            "max_capabilities": 1,
        },
        context_constraints={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )
    sign_credential(d3, identities[DAM_B][0])

    chain = [d1, d2, d3]

    validator = CoDValidator(
        did_registry=registry,
        revocations=revocations,
        max_depth=3,
        trusted_root_issuers={DAM_A},
    )

    policy = OPAPolicyEngine(
        url=OPA_URL,
        timeout=2.0,
    )

    capability_service = CapabilityService(
        issuer_did=DAM_B,
        private_key=identities[DAM_B][0],
        public_key=identities[DAM_B][1],
        revocations=revocations,
        default_lifetime=300,
    )

    ledger = MemoryCommitmentLedger()

    service = AuthorizationService(
        relying_domain="vendor-b",
        validator=validator,
        policy=policy,
        capability_service=capability_service,
        ledger=ledger,
    )

    return service, chain, ledger


def valid_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        requester_did=VENDOR_AGENT,
        relying_domain="vendor-b",
        action="read",
        resource="/assets/pump-17/diagnostics",
        request_time=NOW,
        context={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )


def test_live_opa_end_to_end_authorization():
    service, chain, ledger = build_environment()

    outcome = service.authorize(
        request=valid_request(),
        chain=chain,
        anchor_to_ledger=True,
    )

    assert outcome.accepted
    assert outcome.reason == "authorization granted"

    assert outcome.effective_scope == [
        "diagnostics:read"
    ]

    assert outcome.capability is not None
    assert outcome.capability.scope == [
        "diagnostics:read"
    ]

    assert outcome.ledger_record is not None
    assert len(ledger) == 1

    assert (
        outcome.capability.cod_digest
        == outcome.ledger_record.cod_digest
    )


def test_live_opa_denial_blocks_capability_and_ledger():
    service, chain, ledger = build_environment()

    request = valid_request()
    request.action = "delete"

    outcome = service.authorize(
        request=request,
        chain=chain,
        anchor_to_ledger=True,
    )

    assert not outcome.accepted
    assert outcome.capability is None
    assert outcome.ledger_record is None
    assert len(ledger) == 0
