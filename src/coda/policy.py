from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .models import AuthorizationRequest


@dataclass(frozen=True)
class PolicyRule:
    """
    Relying-domain authorization rule.

    resource_pattern uses shell-style matching so a rule such as

        /assets/*/diagnostics

    can match a family of protected resources.
    """

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
    Minimal relying-domain policy engine.

    This represents PolicyAllow(a, r, t) in the CoDA model.
    A later adapter can delegate the same decision to OPA.
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
