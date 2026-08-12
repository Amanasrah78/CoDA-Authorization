from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .capability import (
    CapabilityError,
    CapabilityService,
    IssuedCapability,
)
from .ledger import (
    LedgerRecord,
    MemoryCommitmentLedger,
)
from .models import (
    AuthorizationRequest,
    DelegationCredential,
)
from .policy import LocalPolicyEngine
from .validator import CoDValidator


@dataclass(frozen=True)
class AuthorizationOutcome:
    accepted: bool
    reason: str
    effective_scope: List[str]
    capability: Optional[IssuedCapability] = None
    ledger_record: Optional[LedgerRecord] = None


class AuthorizationService:
    """
    End-to-end CoDA authorization realization.

    Online authorization:

        Authz =
            Valid(CoD)
            AND request binding
            AND PolicyAllow(a, r, t)

    On success, a short-lived capability is issued.

    Ledger anchoring is performed only after authorization and
    therefore does not form part of the authorization predicate.
    """

    def __init__(
        self,
        relying_domain: str,
        validator: CoDValidator,
        policy: LocalPolicyEngine,
        capability_service: CapabilityService,
        ledger: MemoryCommitmentLedger,
    ):
        self.relying_domain = relying_domain
        self.validator = validator
        self.policy = policy
        self.capability_service = capability_service
        self.ledger = ledger

    def authorize(
        self,
        request: AuthorizationRequest,
        chain: Sequence[DelegationCredential],
        anchor_to_ledger: bool = True,
    ) -> AuthorizationOutcome:
        # -----------------------------------------------------
        # 1. Validate the Chain of Delegation.
        # -----------------------------------------------------
        validation = self.validator.validate(
            chain,
            evaluation_time=request.request_time,
        )

        if not validation.accepted:
            return AuthorizationOutcome(
                accepted=False,
                reason="; ".join(validation.errors),
                effective_scope=[],
            )

        # -----------------------------------------------------
        # 2. Bind request to this relying domain.
        # -----------------------------------------------------
        if request.relying_domain != self.relying_domain:
            return AuthorizationOutcome(
                accepted=False,
                reason="request targets a different relying domain",
                effective_scope=validation.effective_scope,
            )

        # -----------------------------------------------------
        # 3. The requester must be the terminal delegate.
        # -----------------------------------------------------
        terminal_delegate = chain[-1].subject_did

        if request.requester_did != terminal_delegate:
            return AuthorizationOutcome(
                accepted=False,
                reason=(
                    "requester is not the terminal "
                    "delegate of the validated CoD"
                ),
                effective_scope=validation.effective_scope,
            )

        # -----------------------------------------------------
        # 4. Enforce inherited contextual constraints against
        #    the actual runtime request.
        #
        # Parent constraints remain effective even if they are
        # omitted by later credentials.
        # -----------------------------------------------------
        inherited_context = {}

        for credential in chain:
            for key, value in (
                credential.context_constraints.items()
            ):
                inherited_context[key] = value

        for key, required_value in inherited_context.items():
            actual_value = request.context.get(key)

            if actual_value != required_value:
                return AuthorizationOutcome(
                    accepted=False,
                    reason=(
                        f"request context violates inherited "
                        f"constraint '{key}'"
                    ),
                    effective_scope=validation.effective_scope,
                )

        # -----------------------------------------------------
        # 5. Evaluate relying-domain policy.
        # -----------------------------------------------------
        policy_decision = self.policy.evaluate(
            request,
            validation.effective_scope,
        )

        if not policy_decision.allowed:
            return AuthorizationOutcome(
                accepted=False,
                reason=policy_decision.reason,
                effective_scope=validation.effective_scope,
            )

        required_permission = (
            policy_decision.required_permission
        )

        if required_permission is None:
            return AuthorizationOutcome(
                accepted=False,
                reason="policy returned no required permission",
                effective_scope=validation.effective_scope,
            )

        # -----------------------------------------------------
        # 6. Issue confined short-lived capability.
        #
        # Sigma_cap subseteq Sigma_eff
        # -----------------------------------------------------
        try:
            capability = self.capability_service.issue(
                subject_did=request.requester_did,
                chain=chain,
                effective_scope=validation.effective_scope,
                capability_scope=[
                    required_permission
                ],
                now=request.request_time,
            )
        except CapabilityError as exc:
            return AuthorizationOutcome(
                accepted=False,
                reason=str(exc),
                effective_scope=validation.effective_scope,
            )

        # -----------------------------------------------------
        # 7. Accountability anchoring occurs AFTER successful
        #    authorization/capability realization.
        # -----------------------------------------------------
        ledger_record = None

        if anchor_to_ledger:
            ledger_record = self.ledger.anchor_authorization(
                chain=chain,
                capability=capability,
                timestamp=request.request_time,
            )

        return AuthorizationOutcome(
            accepted=True,
            reason="authorization granted",
            effective_scope=validation.effective_scope,
            capability=capability,
            ledger_record=ledger_record,
        )
