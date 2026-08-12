from __future__ import annotations

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
from coda.policy import (
    LocalPolicyEngine,
    PolicyRule,
)
from coda.revocation import RevocationRegistry
from coda.validator import CoDValidator


NOW = 1_750_000_000

DAM_A = "did:coda:factory-a:dam-a"
TWIN_AGENT = "did:coda:factory-a:twin-agent"
DAM_B = "did:coda:vendor-b:dam-b"
VENDOR_AGENT = "did:coda:vendor-b:vendor-agent"


@pytest.fixture
def authorization_environment():
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
        delegation_id="dc-001",
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
        delegation_id="dc-002",
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
        delegation_id="dc-003",
        issuer_did=DAM_B,
        subject_did=VENDOR_AGENT,
        scope=["diagnostics:read"],
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

    policy = LocalPolicyEngine(
        rules=[
            PolicyRule(
                action="read",
                resource_pattern="/assets/*/diagnostics",
                required_permission="diagnostics:read",
            )
        ]
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


def valid_request():
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


def test_end_to_end_authorization_succeeds(
    authorization_environment,
):
    service, chain, ledger = authorization_environment

    outcome = service.authorize(
        valid_request(),
        chain,
    )

    assert outcome.accepted
    assert outcome.capability is not None
    assert outcome.ledger_record is not None

    assert outcome.effective_scope == [
        "diagnostics:read"
    ]

    assert outcome.capability.scope == [
        "diagnostics:read"
    ]

    assert len(ledger) == 1


def test_local_policy_denial_does_not_anchor(
    authorization_environment,
):
    service, chain, ledger = authorization_environment

    request = valid_request()
    request.action = "delete"

    outcome = service.authorize(
        request,
        chain,
    )

    assert not outcome.accepted
    assert outcome.capability is None
    assert outcome.ledger_record is None
    assert len(ledger) == 0


def test_requester_must_be_terminal_delegate(
    authorization_environment,
):
    service, chain, ledger = authorization_environment

    request = valid_request()
    request.requester_did = TWIN_AGENT

    outcome = service.authorize(
        request,
        chain,
    )

    assert not outcome.accepted
    assert "terminal delegate" in outcome.reason
    assert len(ledger) == 0


def test_runtime_context_is_enforced(
    authorization_environment,
):
    service, chain, ledger = authorization_environment

    request = valid_request()
    request.context["purpose"] = "general-access"

    outcome = service.authorize(
        request,
        chain,
    )

    assert not outcome.accepted
    assert "context" in outcome.reason
    assert len(ledger) == 0


def test_ledger_can_be_excluded_from_online_path(
    authorization_environment,
):
    service, chain, ledger = authorization_environment

    outcome = service.authorize(
        valid_request(),
        chain,
        anchor_to_ledger=False,
    )

    assert outcome.accepted
    assert outcome.capability is not None
    assert outcome.ledger_record is None
    assert len(ledger) == 0
