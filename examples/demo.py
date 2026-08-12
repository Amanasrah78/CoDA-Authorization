from __future__ import annotations

from coda.capability import (
    CapabilityService,
    CapabilityValidationError,
)
from coda.credentials import sign_credential
from coda.crypto import generate_ed25519_keypair
from coda.did import DIDRegistry
from coda.models import DelegationCredential
from coda.revocation import RevocationRegistry
from coda.validator import CoDValidator


NOW = 1_750_000_000


def main():
    # ---------------------------------------------------------
    # Principals in the running CoDA example.
    # ---------------------------------------------------------
    DAM_A = "did:coda:factory-a:dam-a"
    TWIN_AGENT = "did:coda:factory-a:twin-agent"
    DAM_B = "did:coda:vendor-b:dam-b"
    VENDOR_AGENT = "did:coda:vendor-b:vendor-agent"

    # ---------------------------------------------------------
    # Generate Ed25519 identities.
    # ---------------------------------------------------------
    dam_a_private, dam_a_public = generate_ed25519_keypair()
    twin_private, twin_public = generate_ed25519_keypair()
    dam_b_private, dam_b_public = generate_ed25519_keypair()
    vendor_private, vendor_public = generate_ed25519_keypair()

    did_registry = DIDRegistry()

    did_registry.register(DAM_A, dam_a_public)
    did_registry.register(TWIN_AGENT, twin_public)
    did_registry.register(DAM_B, dam_b_public)
    did_registry.register(VENDOR_AGENT, vendor_public)

    revocations = RevocationRegistry()

    # ---------------------------------------------------------
    # d1:
    #
    # DAM_A -> TwinAgent
    # ---------------------------------------------------------
    d1 = DelegationCredential(
        delegation_id="dc-001",
        issuer_did=DAM_A,
        subject_did=TWIN_AGENT,
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
            "maintenance:request",
        ],
        valid_from=NOW - 60,
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

    sign_credential(d1, dam_a_private)

    # ---------------------------------------------------------
    # d2:
    #
    # TwinAgent -> DAM_B
    #
    # Authority becomes more restrictive.
    # ---------------------------------------------------------
    d2 = DelegationCredential(
        delegation_id="dc-002",
        issuer_did=TWIN_AGENT,
        subject_did=DAM_B,
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
        ],
        valid_from=NOW - 30,
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

    sign_credential(d2, twin_private)

    # ---------------------------------------------------------
    # d3:
    #
    # DAM_B -> VendorAgent
    # ---------------------------------------------------------
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

    sign_credential(d3, dam_b_private)

    chain = [d1, d2, d3]

    # ---------------------------------------------------------
    # Validate CoD.
    # ---------------------------------------------------------
    validator = CoDValidator(
        did_registry=did_registry,
        revocations=revocations,
        max_depth=3,
        trusted_root_issuers={DAM_A},
    )

    result = validator.validate(
        chain,
        evaluation_time=NOW,
    )

    print("CoD accepted:", result.accepted)
    print("Effective scope:", result.effective_scope)

    if not result.accepted:
        print("Errors:")
        for error in result.errors:
            print(" -", error)
        raise SystemExit(1)

    # ---------------------------------------------------------
    # Issue short-lived capability.
    # ---------------------------------------------------------
    capability_service = CapabilityService(
        issuer_did=DAM_B,
        private_key=dam_b_private,
        public_key=dam_b_public,
        revocations=revocations,
        default_lifetime=300,
    )

    capability = capability_service.issue(
        subject_did=VENDOR_AGENT,
        chain=chain,
        effective_scope=result.effective_scope,
        now=NOW,
    )

    print("Capability issued:", capability.capability_id)
    print("Capability scope:", capability.scope)
    print("CoD digest:", capability.cod_digest)

    # ---------------------------------------------------------
    # Verify runtime capability.
    # ---------------------------------------------------------
    claims = capability_service.verify(
        capability.token,
        required_scope=["diagnostics:read"],
        expected_subject=VENDOR_AGENT,
        expected_nonce=capability.nonce,
        now=NOW + 5,
    )

    print("Capability valid:", claims["jti"])

    # ---------------------------------------------------------
    # Revoke upstream delegation d2.
    #
    # The capability must immediately become invalid because
    # it is bound to the affected CoD.
    # ---------------------------------------------------------
    revocations.revoke(
        delegation_id="dc-002",
        revoked_at=NOW + 10,
        reason="maintenance task withdrawn",
    )

    try:
        capability_service.verify(
            capability.token,
            required_scope=["diagnostics:read"],
            expected_subject=VENDOR_AGENT,
            now=NOW + 11,
        )
    except CapabilityValidationError as exc:
        print("Capability invalid after revocation:", exc)
    else:
        raise RuntimeError(
            "revocation did not invalidate capability"
        )


if __name__ == "__main__":
    main()
