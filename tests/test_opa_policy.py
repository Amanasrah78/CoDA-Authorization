from __future__ import annotations

import httpx

from coda.models import AuthorizationRequest
from coda.policy import OPAPolicyEngine


NOW = 1_750_000_000


def request():
    return AuthorizationRequest(
        requester_did=(
            "did:coda:vendor-b:vendor-agent"
        ),
        relying_domain="vendor-b",
        action="read",
        resource="/assets/pump-17/diagnostics",
        request_time=NOW,
        context={
            "purpose": "predictive-maintenance",
            "plant": "factory-a",
        },
    )


def test_opa_policy_allows_valid_request():
    def handler(http_request):
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": True,
                    "required_permission": (
                        "diagnostics:read"
                    ),
                }
            },
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(
        transport=transport
    ) as client:
        policy = OPAPolicyEngine(
            client=client
        )

        decision = policy.evaluate(
            request(),
            ["diagnostics:read"],
        )

    assert decision.allowed
    assert (
        decision.required_permission
        == "diagnostics:read"
    )


def test_opa_policy_denial_is_enforced():
    def handler(http_request):
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": False,
                    "required_permission": "",
                }
            },
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(
        transport=transport
    ) as client:
        policy = OPAPolicyEngine(
            client=client
        )

        decision = policy.evaluate(
            request(),
            ["diagnostics:read"],
        )

    assert not decision.allowed


def test_opa_cannot_expand_cod_scope():
    def handler(http_request):
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": True,
                    "required_permission": "admin:write",
                }
            },
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(
        transport=transport
    ) as client:
        policy = OPAPolicyEngine(
            client=client
        )

        decision = policy.evaluate(
            request(),
            ["diagnostics:read"],
        )

    assert not decision.allowed
    assert "exceeds" in decision.reason


def test_opa_failure_is_fail_closed():
    def handler(http_request):
        raise httpx.ConnectError(
            "OPA unavailable"
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(
        transport=transport
    ) as client:
        policy = OPAPolicyEngine(
            client=client
        )

        decision = policy.evaluate(
            request(),
            ["diagnostics:read"],
        )

    assert not decision.allowed
    assert "failed" in decision.reason
