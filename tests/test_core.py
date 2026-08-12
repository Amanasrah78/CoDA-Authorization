from __future__ import annotations

from dataclasses import replace

import pytest

from coda.capability import (
    CapabilityError,
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

DAM_A = "did:coda:factory-a:dam-a"
TWIN_AGENT = "did:coda:factory-a:twin-agent"
DAM_B = "did:coda:vendor-b:dam-b"
VENDOR_AGENT = "did:coda:vendor-b:vendor-agent"
EXTRA_AGENT = "did:coda:vendor-b:extra-agent"


@pytest.fixture
def environment():
    identities = {}

    for did in [
        DAM_A,
        TWIN_AGENT,
        DAM_B,
        VENDOR_AGENT,
        EXTRA_AGENT,
    ]:
        private_key, public_key = generate_ed25519_keypair()
        identities[did] = (private_key, public_key)

    registry = DIDRegistry()

    for did, (_, public_key) in identities.items():
        registry.register(did, public_key)

    revocations = RevocationRegistry()

    return identities, registry, revocations


def build_valid_chain(identities):
    d1 = DelegationCredential(
        delegation_id="dc-001",
        issuer_did=DAM_A,
        subject_did=TWIN_AGENT,
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
            "maintenance:request",
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

    return [d1, d2, d3]


def make_validator(registry, revocations, max_depth=3):
    return CoDValidator(
        did_registry=registry,
        revocations=revocations,
        max_depth=max_depth,
        trusted_root_issuers={DAM_A},
    )


def test_valid_three_hop_cod_is_accepted(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert result.accepted
    assert result.errors == []
    assert result.effective_scope == [
        "diagnostics:read"
    ]


def test_scope_expansion_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    child = replace(
        chain[1],
        scope=[
            "diagnostics:read",
            "diagnostics:execute",
            "admin:write",
        ],
        signature="",
    )

    sign_credential(
        child,
        identities[TWIN_AGENT][0],
    )

    chain[1] = child

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "scope expansion" in error
        for error in result.errors
    )


def test_broken_continuity_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    child = replace(
        chain[1],
        issuer_did=EXTRA_AGENT,
        signature="",
    )

    sign_credential(
        child,
        identities[EXTRA_AGENT][0],
    )

    chain[1] = child

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "continuity violated" in error
        for error in result.errors
    )


def test_invalid_signature_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    chain[1].signature = chain[0].signature

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "invalid delegation signature" in error
        for error in result.errors
    )


def test_expired_credential_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    expired = replace(
        chain[1],
        valid_from=NOW - 1000,
        valid_until=NOW - 1,
        signature="",
    )

    sign_credential(
        expired,
        identities[TWIN_AGENT][0],
    )

    chain[1] = expired

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "outside its validity interval" in error
        for error in result.errors
    )


def test_revoked_delegation_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    revocations.revoke(
        "dc-002",
        NOW,
        "credential compromised",
    )

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "delegation is revoked" in error
        for error in result.errors
    )


def test_untrusted_root_issuer_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    root = replace(
        chain[0],
        issuer_did=EXTRA_AGENT,
        signature="",
    )

    sign_credential(
        root,
        identities[EXTRA_AGENT][0],
    )

    chain[0] = root

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "untrusted root issuer" in error
        for error in result.errors
    )


def test_depth_decrement_violation_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    child = replace(
        chain[1],
        remaining_depth=2,
        signature="",
    )

    sign_credential(
        child,
        identities[TWIN_AGENT][0],
    )

    chain[1] = child

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "remaining depth must be" in error
        for error in result.errors
    )


def test_maximum_chain_depth_is_enforced(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    # Reconfigure the existing chain so another valid child
    # delegation can be appended.
    d1 = replace(
        chain[0],
        remaining_depth=3,
        signature="",
    )
    sign_credential(d1, identities[DAM_A][0])

    d2 = replace(
        chain[1],
        remaining_depth=2,
        signature="",
    )
    sign_credential(d2, identities[TWIN_AGENT][0])

    d3 = replace(
        chain[2],
        remaining_depth=1,
        signature="",
    )
    sign_credential(d3, identities[DAM_B][0])

    d4 = DelegationCredential(
        delegation_id="dc-004",
        issuer_did=VENDOR_AGENT,
        subject_did=EXTRA_AGENT,
        scope=["diagnostics:read"],
        valid_from=NOW - 5,
        valid_until=NOW + 500,
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
        d4,
        identities[VENDOR_AGENT][0],
    )

    chain = [d1, d2, d3, d4]

    result = make_validator(
        registry,
        revocations,
        max_depth=3,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "delegation depth exceeded" in error
        for error in result.errors
    )


def test_usage_constraint_relaxation_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    child = replace(
        chain[1],
        usage_constraints={
            "max_delegations": 3,
            "max_capabilities": 50,
        },
        signature="",
    )

    sign_credential(
        child,
        identities[TWIN_AGENT][0],
    )

    chain[1] = child

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "usage constraint" in error
        for error in result.errors
    )


def test_context_constraint_change_is_rejected(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    child = replace(
        chain[1],
        context_constraints={
            "purpose": "unrelated-operation",
            "plant": "factory-a",
        },
        signature="",
    )

    sign_credential(
        child,
        identities[TWIN_AGENT][0],
    )

    chain[1] = child

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert not result.accepted
    assert any(
        "context constraint" in error
        for error in result.errors
    )


def test_capability_is_issued_and_verified(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    assert result.accepted

    service = CapabilityService(
        issuer_did=DAM_B,
        private_key=identities[DAM_B][0],
        public_key=identities[DAM_B][1],
        revocations=revocations,
        default_lifetime=300,
    )

    capability = service.issue(
        subject_did=VENDOR_AGENT,
        chain=chain,
        effective_scope=result.effective_scope,
        now=NOW,
    )

    claims = service.verify(
        capability.token,
        required_scope=["diagnostics:read"],
        expected_subject=VENDOR_AGENT,
        expected_nonce=capability.nonce,
        now=NOW + 1,
    )

    assert claims["sub"] == VENDOR_AGENT
    assert claims["scope"] == ["diagnostics:read"]
    assert claims["h_cod"] == capability.cod_digest


def test_capability_scope_cannot_expand_authority(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    service = CapabilityService(
        issuer_did=DAM_B,
        private_key=identities[DAM_B][0],
        public_key=identities[DAM_B][1],
        revocations=revocations,
    )

    with pytest.raises(CapabilityError):
        service.issue(
            subject_did=VENDOR_AGENT,
            chain=chain,
            effective_scope=result.effective_scope,
            capability_scope=[
                "diagnostics:read",
                "admin:write",
            ],
            now=NOW,
        )


def test_capability_expiration_is_enforced(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    service = CapabilityService(
        issuer_did=DAM_B,
        private_key=identities[DAM_B][0],
        public_key=identities[DAM_B][1],
        revocations=revocations,
        default_lifetime=10,
    )

    capability = service.issue(
        subject_did=VENDOR_AGENT,
        chain=chain,
        effective_scope=result.effective_scope,
        now=NOW,
    )

    with pytest.raises(
        CapabilityValidationError,
        match="expired",
    ):
        service.verify(
            capability.token,
            now=NOW + 10,
        )


def test_revocation_invalidates_derived_capability(environment):
    identities, registry, revocations = environment
    chain = build_valid_chain(identities)

    result = make_validator(
        registry,
        revocations,
    ).validate(chain, NOW)

    service = CapabilityService(
        issuer_did=DAM_B,
        private_key=identities[DAM_B][0],
        public_key=identities[DAM_B][1],
        revocations=revocations,
    )

    capability = service.issue(
        subject_did=VENDOR_AGENT,
        chain=chain,
        effective_scope=result.effective_scope,
        now=NOW,
    )

    revocations.revoke(
        "dc-001",
        NOW + 1,
        "upstream authority withdrawn",
    )

    with pytest.raises(
        CapabilityValidationError,
        match="revoked delegation",
    ):
        service.verify(
            capability.token,
            now=NOW + 2,
        )
