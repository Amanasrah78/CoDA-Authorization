from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .credentials import chain_digest
from .models import DelegationCredential
from .revocation import RevocationRegistry


class CapabilityError(ValueError):
    """Raised when capability issuance cannot be completed."""


class CapabilityValidationError(ValueError):
    """Raised when a capability is invalid."""


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    capability_id: str
    subject_did: str
    scope: List[str]
    issued_at: int
    expires_at: int
    nonce: str
    cod_digest: str


class CapabilityService:
    """
    Issues and validates short-lived CoDA capabilities.

    A capability is issued only after successful CoD validation.
    The capability scope must remain within Sigma_eff.

    The JWT is cryptographically bound to the originating CoD
    through h_CoD.
    """

    def __init__(
        self,
        issuer_did: str,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
        revocations: RevocationRegistry,
        default_lifetime: int = 300,
    ):
        if default_lifetime <= 0:
            raise ValueError(
                "default_lifetime must be positive"
            )

        self.issuer_did = issuer_did
        self.private_key = private_key
        self.public_key = public_key
        self.revocations = revocations
        self.default_lifetime = default_lifetime

        # Maps h_CoD to the delegation identifiers contained
        # in the validated chain.
        #
        # This allows capability verification to determine
        # whether an upstream delegation has subsequently
        # been revoked without embedding the whole CoD in
        # the capability itself.
        self._chain_bindings: Dict[
            str,
            Tuple[str, ...],
        ] = {}

    def issue(
        self,
        subject_did: str,
        chain: Sequence[DelegationCredential],
        effective_scope: Iterable[str],
        capability_scope: Optional[Iterable[str]] = None,
        lifetime_seconds: Optional[int] = None,
        now: Optional[int] = None,
    ) -> IssuedCapability:
        if not chain:
            raise CapabilityError(
                "cannot issue a capability for an empty CoD"
            )

        issued_at = int(
            time.time() if now is None else now
        )

        lifetime = (
            self.default_lifetime
            if lifetime_seconds is None
            else lifetime_seconds
        )

        if lifetime <= 0:
            raise CapabilityError(
                "capability lifetime must be positive"
            )

        effective = set(effective_scope)

        if not effective:
            raise CapabilityError(
                "effective scope is empty"
            )

        if capability_scope is None:
            requested_scope = set(effective)
        else:
            requested_scope = set(capability_scope)

        if not requested_scope:
            raise CapabilityError(
                "capability scope is empty"
            )

        # -----------------------------------------------------
        # Capability confinement:
        #
        # Sigma_cap subseteq Sigma_eff
        # -----------------------------------------------------
        if not requested_scope.issubset(effective):
            raise CapabilityError(
                "capability scope exceeds effective CoD scope"
            )

        cod_hash = chain_digest(chain)

        delegation_ids = tuple(
            credential.delegation_id
            for credential in chain
        )

        # Do not issue a capability from a chain that is
        # already revoked.
        for delegation_id in delegation_ids:
            if self.revocations.is_revoked(
                delegation_id
            ):
                raise CapabilityError(
                    "cannot issue capability from "
                    "a revoked delegation chain"
                )

        self._chain_bindings[cod_hash] = delegation_ids

        capability_id = str(uuid.uuid4())
        nonce = secrets.token_urlsafe(16)
        expires_at = issued_at + lifetime

        payload = {
            "jti": capability_id,
            "iss": self.issuer_did,
            "sub": subject_did,
            "scope": sorted(requested_scope),
            "iat": issued_at,
            "exp": expires_at,
            "nonce": nonce,
            "h_cod": cod_hash,
        }

        token = jwt.encode(
            payload,
            self.private_key,
            algorithm="EdDSA",
        )

        return IssuedCapability(
            token=token,
            capability_id=capability_id,
            subject_did=subject_did,
            scope=sorted(requested_scope),
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            cod_digest=cod_hash,
        )

    def verify(
        self,
        token: str,
        required_scope: Optional[Iterable[str]] = None,
        expected_subject: Optional[str] = None,
        expected_nonce: Optional[str] = None,
        now: Optional[int] = None,
    ) -> Dict:
        """
        Verify a capability.

        Valid(Cap) depends on:
          - valid Ed25519 JWT signature;
          - expected issuer;
          - expiration;
          - originating CoD binding;
          - non-revocation of every delegation in that CoD;
          - optional subject, nonce, and requested-scope checks.
        """
        evaluation_time = int(
            time.time() if now is None else now
        )

        try:
            claims = jwt.decode(
                token,
                self.public_key,
                algorithms=["EdDSA"],
                issuer=self.issuer_did,
                options={
                    # Expiration is checked explicitly below so
                    # experiments can supply a deterministic time.
                    "verify_exp": False,
                    "require": [
                        "jti",
                        "iss",
                        "sub",
                        "scope",
                        "iat",
                        "exp",
                        "nonce",
                        "h_cod",
                    ],
                },
            )
        except jwt.PyJWTError as exc:
            raise CapabilityValidationError(
                f"invalid capability signature or claims: {exc}"
            ) from exc

        expires_at = claims.get("exp")

        if not isinstance(expires_at, int):
            raise CapabilityValidationError(
                "invalid capability expiration"
            )

        # Manuscript condition:
        #
        # t < T_cap
        if evaluation_time >= expires_at:
            raise CapabilityValidationError(
                "capability has expired"
            )

        if expected_subject is not None:
            if claims.get("sub") != expected_subject:
                raise CapabilityValidationError(
                    "capability subject mismatch"
                )

        if expected_nonce is not None:
            if claims.get("nonce") != expected_nonce:
                raise CapabilityValidationError(
                    "capability nonce mismatch"
                )

        capability_scope = set(
            claims.get("scope", [])
        )

        if required_scope is not None:
            required = set(required_scope)

            if not required.issubset(
                capability_scope
            ):
                raise CapabilityValidationError(
                    "requested operation exceeds "
                    "capability scope"
                )

        cod_hash = claims.get("h_cod")

        delegation_ids = self._chain_bindings.get(
            cod_hash
        )

        if delegation_ids is None:
            raise CapabilityValidationError(
                "unknown originating Chain of Delegation"
            )

        # -----------------------------------------------------
        # Cascading invalidation:
        #
        # Revoked(d_i) => not Valid(Cap)
        # -----------------------------------------------------
        for delegation_id in delegation_ids:
            if self.revocations.is_revoked(
                delegation_id
            ):
                raise CapabilityValidationError(
                    "capability invalidated by "
                    f"revoked delegation {delegation_id}"
                )

        return claims

    def chain_binding(
        self,
        cod_hash: str,
    ) -> Optional[Tuple[str, ...]]:
        return self._chain_bindings.get(cod_hash)
