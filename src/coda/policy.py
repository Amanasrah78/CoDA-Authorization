from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Iterable, Optional, Protocol, Sequence

import httpx

from .models import AuthorizationRequest


class PolicyEngine(Protocol):
    def evaluate(
        self,
        request: AuthorizationRequest,
        effective_scope: Iterable[str],
    ) -> "PolicyDecision":
        ...


@dataclass(frozen=True)
class PolicyRule:
    action: str
    resource_pattern: str
    required_permission: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    required_permission: Optional[str]
    reason: str


class LocalPolicyEngine:
    """
    In-process relying-domain policy engine.

    This is useful for tests and deployments where OPA is not used.
    """

    def __init__(
        self,
        rules: Sequence[PolicyRule],
    ):
        self.rules = tuple(rules)

    def evaluate(
        self,
        request: AuthorizationRequest,
        effective_scope: Iterable[str],
    ) -> PolicyDecision:
        effective = set(effective_scope)

        for rule in self.rules:
            if request.action != rule.action:
                continue

            if not fnmatch.fnmatch(
                request.resource,
                rule.resource_pattern,
            ):
                continue

            if rule.required_permission not in effective:
                return PolicyDecision(
                    allowed=False,
                    required_permission=rule.required_permission,
                    reason=(
                        "required permission is not contained "
                        "in effective delegated scope"
                    ),
                )

            return PolicyDecision(
                allowed=True,
                required_permission=rule.required_permission,
                reason="relying-domain policy allowed request",
            )

        return PolicyDecision(
            allowed=False,
            required_permission=None,
            reason="no relying-domain policy rule allowed request",
        )


class OPAPolicyEngine:
    """
    Open Policy Agent adapter for CoDA.

    OPA receives the runtime authorization request together with
    Sigma_eff. The relying-domain policy returns both:

        allow
        required_permission

    The adapter fails closed if OPA is unavailable or returns an
    invalid decision.
    """

    def __init__(
        self,
        url: str = (
            "http://localhost:8181/"
            "v1/data/coda/authz/decision"
        ),
        timeout: float = 2.0,
        client: Optional[httpx.Client] = None,
    ):
        self.url = url
        self.timeout = timeout
        self.client = client

    def evaluate(
        self,
        request: AuthorizationRequest,
        effective_scope: Iterable[str],
    ) -> PolicyDecision:
        payload = {
            "input": {
                "requester_did": request.requester_did,
                "relying_domain": request.relying_domain,
                "action": request.action,
                "resource": request.resource,
                "request_time": request.request_time,
                "context": dict(request.context),
                "effective_scope": sorted(
                    set(effective_scope)
                ),
            }
        }

        try:
            if self.client is not None:
                response = self.client.post(
                    self.url,
                    json=payload,
                    timeout=self.timeout,
                )
            else:
                response = httpx.post(
                    self.url,
                    json=payload,
                    timeout=self.timeout,
                )

            response.raise_for_status()

        except httpx.HTTPError as exc:
            return PolicyDecision(
                allowed=False,
                required_permission=None,
                reason=f"OPA policy evaluation failed: {exc}",
            )

        try:
            body = response.json()
        except ValueError:
            return PolicyDecision(
                allowed=False,
                required_permission=None,
                reason="OPA returned invalid JSON",
            )

        result = body.get("result")

        if not isinstance(result, dict):
            return PolicyDecision(
                allowed=False,
                required_permission=None,
                reason="OPA returned no valid policy decision",
            )

        allowed = result.get("allow")

        if allowed is not True:
            return PolicyDecision(
                allowed=False,
                required_permission=None,
                reason="OPA relying-domain policy denied request",
            )

        required_permission = result.get(
            "required_permission"
        )

        if not isinstance(required_permission, str):
            return PolicyDecision(
                allowed=False,
                required_permission=None,
                reason=(
                    "OPA allowed request without a valid "
                    "required permission"
                ),
            )

        if required_permission not in set(
            effective_scope
        ):
            return PolicyDecision(
                allowed=False,
                required_permission=required_permission,
                reason=(
                    "OPA required permission exceeds "
                    "effective delegated scope"
                ),
            )

        return PolicyDecision(
            allowed=True,
            required_permission=required_permission,
            reason="OPA relying-domain policy allowed request",
        )
