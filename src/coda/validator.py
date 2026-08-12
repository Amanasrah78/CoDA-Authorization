from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Set

from .credentials import verify_credential_signature
from .did import DIDRegistry, DIDResolutionError
from .models import DelegationCredential, ValidationResult
from .revocation import RevocationRegistry


class CoDValidator:
    """
    Validator for a bounded Chain of Delegation (CoD).

    The implementation follows the principal CoDA conditions:

      1. credential cryptographic validity;
      2. temporal validity;
      3. non-revocation;
      4. delegation continuity;
      5. bounded chain depth;
      6. monotonic scope reduction;
      7. inherited usage-constraint preservation;
      8. inherited context-constraint preservation;
      9. remaining-depth decrement.

    Scope entries are modeled as discrete permissions. Therefore,
    child scope must be a mathematical subset of parent scope.
    """

    def __init__(
        self,
        did_registry: DIDRegistry,
        revocations: RevocationRegistry,
        max_depth: int,
        trusted_root_issuers: Optional[Iterable[str]] = None,
    ):
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")

        self.did_registry = did_registry
        self.revocations = revocations
        self.max_depth = max_depth

        self.trusted_root_issuers: Set[str] = set(
            trusted_root_issuers or []
        )

    def validate(
        self,
        chain: Sequence[DelegationCredential],
        evaluation_time: int,
    ) -> ValidationResult:
        errors: List[str] = []

        if not chain:
            return ValidationResult.deny(
                "Chain of Delegation is empty"
            )

        # ---------------------------------------------------------
        # Bounded propagation:
        #
        # |CoD| <= Depth_max
        # ---------------------------------------------------------
        if len(chain) > self.max_depth:
            errors.append(
                f"delegation depth exceeded: "
                f"{len(chain)} > {self.max_depth}"
            )

        # ---------------------------------------------------------
        # Optional root-of-authority check.
        #
        # This rejects a syntactically valid chain that originates
        # from an issuer the relying domain does not trust.
        # ---------------------------------------------------------
        if self.trusted_root_issuers:
            root_issuer = chain[0].issuer_did

            if root_issuer not in self.trusted_root_issuers:
                errors.append(
                    f"untrusted root issuer: {root_issuer}"
                )

        # Reusing the same delegation identifier in one chain is
        # considered malformed.
        delegation_ids = [
            credential.delegation_id
            for credential in chain
        ]

        if len(delegation_ids) != len(set(delegation_ids)):
            errors.append(
                "duplicate delegation identifier in chain"
            )

        # ---------------------------------------------------------
        # Per-credential checks:
        #
        #   Valid(d_i)
        #   AND
        #   NOT Revoked(d_i)
        # ---------------------------------------------------------
        for index, credential in enumerate(chain):
            label = f"d{index + 1}"

            if credential.remaining_depth < 0:
                errors.append(
                    f"{label}: remaining depth is negative"
                )

            if credential.valid_until < credential.valid_from:
                errors.append(
                    f"{label}: invalid validity interval"
                )

            if not (
                credential.valid_from
                <= evaluation_time
                <= credential.valid_until
            ):
                errors.append(
                    f"{label}: credential is outside "
                    f"its validity interval"
                )

            if self.revocations.is_revoked(
                credential.delegation_id
            ):
                errors.append(
                    f"{label}: delegation is revoked"
                )

            try:
                issuer_key = self.did_registry.resolve(
                    credential.issuer_did
                )
            except DIDResolutionError:
                errors.append(
                    f"{label}: issuer DID cannot be resolved: "
                    f"{credential.issuer_did}"
                )
                continue

            if not verify_credential_signature(
                credential,
                issuer_key,
            ):
                errors.append(
                    f"{label}: invalid delegation signature"
                )

        # ---------------------------------------------------------
        # Pairwise delegation checks.
        #
        # For each adjacent pair d_i and d_(i+1):
        #
        #   DID_to(d_i) = DID_from(d_(i+1))
        #
        #   Sigma_(i+1) subseteq Sigma_i
        #
        #   Depth_(i+1) = Depth_i - 1
        #
        # Usage and contextual constraints may be preserved or
        # tightened, but not relaxed.
        # ---------------------------------------------------------
        for index in range(len(chain) - 1):
            parent = chain[index]
            child = chain[index + 1]

            parent_label = f"d{index + 1}"
            child_label = f"d{index + 2}"

            # Delegation continuity.
            if parent.subject_did != child.issuer_did:
                errors.append(
                    f"{parent_label}->{child_label}: "
                    f"delegation continuity violated"
                )

            # Monotonic authority reduction.
            parent_scope = set(parent.scope)
            child_scope = set(child.scope)

            if not child_scope.issubset(parent_scope):
                errors.append(
                    f"{parent_label}->{child_label}: "
                    f"scope expansion detected"
                )

            # Remaining delegation depth must decrease exactly
            # one level at every delegation step.
            expected_depth = parent.remaining_depth - 1

            if child.remaining_depth != expected_depth:
                errors.append(
                    f"{parent_label}->{child_label}: "
                    f"remaining depth must be "
                    f"{expected_depth}, got "
                    f"{child.remaining_depth}"
                )

            # -------------------------------------------------
            # Usage constraints:
            #
            # A child may:
            #   - omit a parent value, meaning that the parent's
            #     restriction remains inherited;
            #   - repeat the same value;
            #   - specify a smaller numeric limit.
            #
            # It may not specify a larger limit.
            # -------------------------------------------------
            for key, parent_value in (
                parent.usage_constraints.items()
            ):
                if key not in child.usage_constraints:
                    continue

                child_value = child.usage_constraints[key]

                if child_value > parent_value:
                    errors.append(
                        f"{parent_label}->{child_label}: "
                        f"usage constraint '{key}' relaxed "
                        f"from {parent_value} to {child_value}"
                    )

            # -------------------------------------------------
            # Context constraints:
            #
            # For this reference implementation, parent context
            # attributes remain inherited unless the child adds
            # new attributes. Replacing an inherited attribute
            # with a different value is rejected because its
            # semantics could relax the upstream restriction.
            # -------------------------------------------------
            for key, parent_value in (
                parent.context_constraints.items()
            ):
                if key not in child.context_constraints:
                    continue

                child_value = child.context_constraints[key]

                if child_value != parent_value:
                    errors.append(
                        f"{parent_label}->{child_label}: "
                        f"context constraint '{key}' changed "
                        f"from '{parent_value}' to "
                        f"'{child_value}'"
                    )

        if errors:
            return ValidationResult.deny(*errors)

        effective_scope = self._effective_scope(chain)

        return ValidationResult.allow(effective_scope)

    @staticmethod
    def _effective_scope(
        chain: Sequence[DelegationCredential],
    ) -> List[str]:
        """
        Sigma_eff = intersection_i Sigma_i
        """
        if not chain:
            return []

        effective = set(chain[0].scope)

        for credential in chain[1:]:
            effective.intersection_update(
                credential.scope
            )

        return sorted(effective)
