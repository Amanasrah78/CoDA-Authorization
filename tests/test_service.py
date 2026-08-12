from __future__ import annotations

from fastapi.testclient import TestClient

from coda.authorization import AuthorizationService
from coda.capability import CapabilityService
from coda.credentials import sign_credential
from coda.crypto import generate_ed25519_keypair
from coda.did import DIDRegistry
from coda.ledger import MemoryCommitmentLedger
from coda.models import DelegationCredential
from coda.policy import LocalPolicyEngine, PolicyRule
from coda.revocation import RevocationRegistry
from coda.service import create_app
from coda.validator import CoDValidator


NOW = 1_750_000_000

DAM_A = "did:coda:factory-a:dam-a"
TWIN_AGENT = "did:coda:factory-a:twin-agent"
DAM_B = "did:coda:vendor-b:dam-b"
VENDOR_AGENT = "did:coda:vendor-b:vendor-agent"


def build_client():
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
        registry.register(
            did,
            public_key,
        )

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
    sign_credential(
        d1,
        identities[DAM_A][0],
    )

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
    sign_credential(
        d2,
        identities[TWIN_AGENT][0],
    )

    d3 = DelegationCredential(
        delegation_id="dc-003",
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
    sign_credential(
        d3,
        identities[DAM_B][0],
    )

    chain = [d1, d2, d3]

    validator = CoDValidator(
        did_registry=registry,
        revocations=revocations,
        max_depth=3,
        trusted_root_issuers={
            DAM_A
        },
    )

    policy = LocalPolicyEngine(
        [
            PolicyRule(
                action="read",
                resource_pattern=(
                    "/assets/*/diagnostics"
                ),
                required_permission=(
                    "diagnostics:read"
                ),
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

    authorization_service = AuthorizationService(
        relying_domain="vendor-b",
        validator=validator,
        policy=policy,
        capability_service=(
            capability_service
        ),
        ledger=MemoryCommitmentLedger(),
    )

    app = create_app(
        authorization_service,
        clock=lambda: NOW,
    )

    return (
        TestClient(app),
        chain,
    )


def chain_to_json(chain):
    return [
        credential.to_dict()
        for credential in chain
    ]


def test_health_endpoint():
    client, _ = build_client()

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json()["status"] == "ok"


def test_authorize_endpoint_accepts_valid_cod():
    client, chain = build_client()

    response = client.post(
        "/authorize",
        json={
            "requester_did": VENDOR_AGENT,
            "relying_domain": "vendor-b",
            "action": "read",
            "resource": (
                "/assets/pump-17/diagnostics"
            ),
            "context": {
                "purpose": (
                    "predictive-maintenance"
                ),
                "plant": "factory-a",
            },
            "chain": chain_to_json(chain),
            "anchor_to_ledger": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["accepted"] is True

    assert body["effective_scope"] == [
        "diagnostics:read"
    ]

    assert body["capability"] is not None
    assert body["ledger"] is not None

    assert (
        body["capability"]["h_cod"]
        == body["ledger"]["h_cod"]
    )


def test_authorize_endpoint_rejects_bad_context():
    client, chain = build_client()

    response = client.post(
        "/authorize",
        json={
            "requester_did": VENDOR_AGENT,
            "relying_domain": "vendor-b",
            "action": "read",
            "resource": (
                "/assets/pump-17/diagnostics"
            ),
            "context": {
                "purpose": "unauthorized-purpose",
                "plant": "factory-a",
            },
            "chain": chain_to_json(chain),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["accepted"] is False
    assert body["capability"] is None
    assert body["ledger"] is None
