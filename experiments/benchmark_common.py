from __future__ import annotations

from typing import Dict, List, Tuple

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
    OPAPolicyEngine,
    PolicyRule,
)
from coda.revocation import RevocationRegistry
from coda.validator import CoDValidator


NOW = 1_750_000_000

ROOT_DID = "did:coda:factory-a:dam-a"


def build_chain(
    depth: int,
    now: int = NOW,
):
    if depth < 1:
        raise ValueError("depth must be at least 1")

    identities: Dict[str, Tuple] = {}

    root_private, root_public = generate_ed25519_keypair()
    identities[ROOT_DID] = (
        root_private,
        root_public,
    )

    delegate_dids = [
        f"did:coda:agent:{index}"
        for index in range(1, depth + 1)
    ]

    for did in delegate_dids:
        identities[did] = generate_ed25519_keypair()

    registry = DIDRegistry()

    for did, (_, public_key) in identities.items():
        registry.register(did, public_key)

    chain: List[DelegationCredential] = []

    issuer_did = ROOT_DID

    for index in range(depth):
        subject_did = delegate_dids[index]

        credential = DelegationCredential(
            delegation_id=(
                f"benchmark-d{depth}-{index + 1}"
            ),
            issuer_did=issuer_did,
            subject_did=subject_did,
            scope=["diagnostics:read"],
            valid_from=now - 60,
            valid_until=now + 3600,
            remaining_depth=depth - index - 1,
            usage_constraints={
                "max_delegations": (
                    depth - index - 1
                ),
                "max_capabilities": 1000000,
            },
            context_constraints={
                "purpose": "predictive-maintenance",
                "plant": "factory-a",
            },
        )

        sign_credential(
            credential,
            identities[issuer_did][0],
        )

        chain.append(credential)

        issuer_did = subject_did

    terminal_did = delegate_dids[-1]

    return (
        identities,
        registry,
        chain,
        terminal_did,
    )


def build_environment(
    depth: int,
    policy_mode: str = "local",
    opa_url: str = (
        "http://localhost:8181/"
        "v1/data/coda/authz/decision"
    ),
):
    (
        identities,
        registry,
        chain,
        terminal_did,
    ) = build_chain(depth)

    revocations = RevocationRegistry()

    validator = CoDValidator(
        did_registry=registry,
        revocations=revocations,
        max_depth=depth,
        trusted_root_issuers={ROOT_DID},
    )

    if policy_mode == "opa":
        policy = OPAPolicyEngine(
            url=opa_url,
            timeout=2.0,
        )
    elif policy_mode == "local":
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
    else:
        raise ValueError(
            "policy_mode must be 'local' or 'opa'"
        )

    # The relying domain owns a separate capability-signing key.
    relying_private, relying_public = (
        generate_ed25519_keypair()
    )

    capability_service = CapabilityService(
        issuer_did="did:coda:vendor-b:dam-b",
        private_key=relying_private,
        public_key=relying_public,
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

    request = AuthorizationRequest(
        requester_did=terminal_did,
        relying_domain="vendor-b",
        action="read",
        resource="/assets/pump-17/diagnostics",
        request_time=NOW,
        context={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )

    return {
        "identities": identities,
        "registry": registry,
        "revocations": revocations,
        "validator": validator,
        "policy": policy,
        "capability_service": capability_service,
        "ledger": ledger,
        "service": service,
        "chain": chain,
        "request": request,
    }
