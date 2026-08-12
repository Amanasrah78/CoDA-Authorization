# Security Considerations

## Scope

This repository is a reconstructed reference implementation of CoDA for research, evaluation, and reproducibility. It has not undergone a production security audit.

## Trust Model

Each relying domain maintains its own trust base. The authorization API does not allow remote requesters to register trusted DID keys, add trusted root issuers, modify policy, or change maximum delegation depth.

## Validation and Confinement

A Chain of Delegation is accepted only after checking Ed25519 signatures, temporal validity, revocation, delegation continuity, bounded depth, per-hop depth decrement, monotonic scope reduction, inherited usage constraints, inherited context constraints, and trusted root authority.

    Sigma_(i+1) subseteq Sigma_i
    Sigma_eff = intersection(Sigma_1, ..., Sigma_n)
    Sigma_cap subseteq Sigma_eff

Capabilities are short-lived EdDSA-signed JWTs bound to the originating CoD through:

    h_CoD = SHA256(d1 || d2 || ... || dn)

## Revocation and DID Resolution

Revoked delegations invalidate subsequent CoD validation and associated tracked capabilities. The current revocation registry and DID-to-Ed25519-key registry are in-memory research abstractions; production deployments require persistent, synchronized revocation state and authenticated DID resolution.

## Policy Evaluation

CoDA supports a local policy engine and an Open Policy Agent (OPA) adapter. The OPA adapter fails closed if OPA is unavailable, the response is malformed, the request is denied, or the returned permission exceeds the effective delegated scope.

## Ledger Commitments

MemoryCommitmentLedger implements local cryptographic commitment semantics only. It is not a distributed ledger or an IOTA implementation. Its latency must not be interpreted as blockchain, distributed-ledger, or IOTA anchoring latency.

## Usage and Deployment Limits

The validator checks that usage constraints are preserved or tightened, but the current implementation does not provide a distributed persistent consumption counter across service instances.

Production deployments additionally require authenticated and encrypted transport, service authentication, secure key storage and rotation, persistent trust configuration, rate limiting, audit logging, secret management, and hardened hosts and containers.

## Research Artifact Status

The original prototype source used to generate the manuscript's reported measurements was not available when this repository was assembled. This repository is therefore a reconstructed reference implementation derived from the manuscript specification.

Performance values generated here are fresh measurements of this implementation and must not be represented as the original manuscript measurements.

## Reporting Security Issues

For security-sensitive findings, avoid publishing exploit details in a public GitHub issue before the repository maintainer has had an opportunity to assess the report.
