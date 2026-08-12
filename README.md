# CoDA Authorization

Reference implementation of **CoDA: Bounded Chain-of-Delegation Authorization for Cross-Domain Industrial Digital Twin Agents**.

CoDA provides bounded delegated authorization for cross-domain Industrial Digital Twin (IDT) agents. Delegated authority is represented as an explicit Chain of Delegation (CoD), validated before a relying domain issues a short-lived runtime capability.

## Research Artifact Status

> **Important:** The original prototype source used to produce the manuscript's reported measurements was not available when this repository was assembled.
>
> This repository is therefore a **reconstructed reference implementation derived from the manuscript specification**. It implements the CoDA authorization rules and provides executable functional and performance experiments, but it must not be represented as the byte-for-byte implementation that produced the manuscript's original latency measurements.

Benchmark scripts in this repository generate **fresh measurements on the machine where they are executed**. No manuscript latency values are hard-coded into the implementation.

## CoDA Authorization Model

For a Chain of Delegation:

```text
CoD = (d1, d2, ..., dn)
```

the relying domain validates:

- Ed25519 delegation signatures;
- credential temporal validity;
- revocation status;
- delegator-to-delegatee continuity;
- maximum CoD depth;
- per-hop remaining-depth decrement;
- monotonic scope reduction;
- inherited usage constraints;
- inherited contextual constraints;
- trusted root authority.

The effective delegated scope is:

```text
Sigma_eff = intersection(Sigma_1, ..., Sigma_n)
```

A relying-domain policy is then evaluated against the authorization request.

If authorization succeeds, CoDA issues a short-lived JWT capability satisfying:

```text
Sigma_cap subseteq Sigma_eff
```

The capability is cryptographically bound to the validated delegation chain through:

```text
h_CoD = SHA256(d1 || d2 || ... || dn)
```

Revocation of an upstream delegation invalidates capabilities derived from the affected CoD.

## Authorization Pipeline

```text
Signed Chain of Delegation
        |
        v
DID / Ed25519 verification
        |
        v
CoD constraint validation
        |
        v
Effective scope derivation
        |
        v
Relying-domain policy
        |
        v
Short-lived JWT capability
        |
        v
Post-authorization commitment
```

Ledger anchoring is deliberately separated from the online authorization predicate.

## Repository Structure

```text
src/coda/
    authorization.py   End-to-end authorization orchestration
    capability.py      JWT capability issuance and verification
    credentials.py     Delegation signing and CoD digest
    crypto.py          Ed25519 and SHA-256 utilities
    did.py             DID verification-key registry
    ledger.py          Commitment-ledger abstraction
    models.py          Core CoDA data structures
    policy.py          Local and OPA policy engines
    revocation.py      Delegation revocation registry
    service.py         FastAPI relying-domain interface
    validator.py       Chain-of-Delegation validation

policy/
    coda.rego          OPA relying-domain authorization policy

examples/
    demo.py            Three-hop CoDA demonstration

experiments/
    authorization_latency.py
    phase_breakdown.py
    benchmark_common.py

tests/
    Core, authorization, REST, OPA, and integration tests

docker-compose.yml     Local OPA deployment
```

## Requirements

- Python 3.9+
- Docker and Docker Compose for live OPA experiments

Python dependencies include:

- cryptography
- PyJWT
- FastAPI
- Uvicorn
- HTTPX
- pytest

## Installation

Clone the repository:

```bash
git clone https://github.com/Amanasrah78/CoDA-Authorization.git
cd CoDA-Authorization
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project:

```bash
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e ".[test]"
```

## Functional Validation

Run the complete test suite:

```bash
python -m pytest -v
```

The tests cover:

- valid three-hop delegation;
- scope-expansion attempts;
- broken delegation continuity;
- invalid signatures;
- expired credentials;
- revoked delegations;
- unauthorized root issuers;
- depth violations;
- usage-constraint relaxation;
- contextual-constraint violations;
- capability scope confinement;
- capability expiration;
- cascading capability invalidation;
- REST authorization;
- OPA policy decisions.

## Three-Hop Demonstration

Run:

```bash
python examples/demo.py
```

The demonstration constructs and validates a three-hop CoD, derives the effective scope, issues a capability, verifies it, and demonstrates capability invalidation following upstream delegation revocation.

## Open Policy Agent

Start OPA:

```bash
docker compose up -d
```

Check health:

```bash
curl http://localhost:8181/health
```

The CoDA policy decision endpoint is:

```text
http://localhost:8181/v1/data/coda/authz/decision
```

Run the live OPA integration tests:

```bash
RUN_OPA_INTEGRATION=1 \
python -m pytest tests/test_opa_integration.py -v
```

## Performance Experiments

### Online Authorization and Ledger-Inclusive Realization

Run:

```bash
python experiments/authorization_latency.py \
  --runs 100 \
  --warmup 10 \
  --depths 1 2 3 \
  --policy opa \
  --output results/authorization_latency_opa.csv
```

The benchmark distinguishes three quantities:

```text
online
    = authorization through capability issuance

ledger_anchoring
    = post-authorization commitment operation only

ledger_inclusive
    = online + ledger_anchoring
```

This distinction prevents online authorization latency from being conflated with ledger-inclusive execution time.

### Isolated CoDA Processing

To examine CoDA computational scaling without HTTP/OPA process overhead:

```bash
python experiments/authorization_latency.py \
  --runs 100 \
  --warmup 10 \
  --depths 1 2 3 \
  --policy local \
  --output results/authorization_latency_local.csv
```

### Phase Breakdown

For a three-hop CoD:

```bash
python experiments/phase_breakdown.py \
  --depth 3 \
  --runs 100 \
  --warmup 10 \
  --policy opa
```

This separately measures:

```text
CoD validation
Policy evaluation
Capability issuance
Ledger anchoring
```

## Ledger Note

`MemoryCommitmentLedger` implements the cryptographic commitment semantics needed by the reference implementation.

It is **not an IOTA implementation**.

Consequently, latency measured for `MemoryCommitmentLedger` must not be interpreted as distributed-ledger or IOTA anchoring latency.

The ledger interface is intentionally separated so that a production DLT adapter can replace the in-memory implementation.

## Interpreting Benchmark Results

OPA-backed measurements include HTTP communication and OPA/Rego policy-evaluation overhead. These components can dominate the comparatively small per-hop CoD validation cost.

The local-policy benchmark is therefore useful for examining delegation-depth computational scaling, while the OPA benchmark represents a more complete deployed authorization path.

Results depend on hardware, operating system, Python version, container runtime, OPA version, and system load.

## Security Boundary

The REST authorization interface accepts signed delegation credentials and authorization requests.

It deliberately does **not** expose endpoints allowing remote clients to:

```text
register trusted DID keys
add trusted root issuers
modify relying-domain policy
```

Trust configuration therefore remains outside the untrusted authorization request path.

## License

No software license has yet been assigned to this research artifact.

## Citation

Citation metadata will be provided through `CITATION.cff`.
