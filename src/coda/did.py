from __future__ import annotations

from typing import Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .crypto import (
    public_key_from_b64,
    public_key_to_b64,
)


class DIDResolutionError(KeyError):
    pass


class DIDRegistry:
    """
    Minimal DID-resolution abstraction for the reference implementation.

    The registry stores DID -> Ed25519 verification-key bindings.
    Production deployments can replace this class with a real DID resolver
    without changing CoDA validation logic.
    """

    def __init__(self):
        self._verification_keys: Dict[str, str] = {}

    def register(
        self,
        did: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        if not did.startswith("did:"):
            raise ValueError("DID must begin with 'did:'")

        self._verification_keys[did] = public_key_to_b64(
            public_key
        )

    def resolve(
        self,
        did: str,
    ) -> Ed25519PublicKey:
        encoded = self._verification_keys.get(did)

        if encoded is None:
            raise DIDResolutionError(
                f"Unable to resolve DID: {did}"
            )

        return public_key_from_b64(encoded)

    def contains(self, did: str) -> bool:
        return did in self._verification_keys
