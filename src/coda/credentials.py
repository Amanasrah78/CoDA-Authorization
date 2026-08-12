from __future__ import annotations

from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto import (
    canonical_json_bytes,
    sha256_hex,
    sign_bytes,
    verify_bytes,
)
from .models import DelegationCredential


def sign_credential(
    credential: DelegationCredential,
    private_key: Ed25519PrivateKey,
) -> DelegationCredential:
    """
    Sign all security-relevant delegation fields.
    """
    payload = canonical_json_bytes(
        credential.signing_payload()
    )

    credential.signature = sign_bytes(
        private_key,
        payload,
    )

    return credential


def verify_credential_signature(
    credential: DelegationCredential,
    public_key: Ed25519PublicKey,
) -> bool:
    if not credential.signature:
        return False

    payload = canonical_json_bytes(
        credential.signing_payload()
    )

    return verify_bytes(
        public_key,
        payload,
        credential.signature,
    )


def credential_digest(
    credential: DelegationCredential,
) -> str:
    """
    Digest of the complete signed credential.
    """
    return sha256_hex(
        canonical_json_bytes(
            credential.to_dict()
        )
    )


def chain_digest(
    credentials: Iterable[DelegationCredential],
) -> str:
    """
    h_CoD = H(d1 || ... || dn)

    Canonical signed credential representations are concatenated
    before hashing.
    """
    encoded = b"".join(
        canonical_json_bytes(credential.to_dict())
        for credential in credentials
    )

    return sha256_hex(encoded)
