from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical_json_bytes(value: Any) -> bytes:
    """
    Deterministic JSON encoding used for credential signatures
    and cryptographic digests.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def generate_ed25519_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_bytes(
    private_key: Ed25519PrivateKey,
    data: bytes,
) -> str:
    signature = private_key.sign(data)
    return base64.urlsafe_b64encode(signature).decode("ascii")


def verify_bytes(
    public_key: Ed25519PublicKey,
    data: bytes,
    signature_b64: str,
) -> bool:
    try:
        signature = base64.urlsafe_b64decode(
            signature_b64.encode("ascii")
        )
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def public_key_to_b64(
    public_key: Ed25519PublicKey,
) -> str:
    raw = public_key.public_bytes_raw()
    return base64.urlsafe_b64encode(raw).decode("ascii")


def public_key_from_b64(
    value: str,
) -> Ed25519PublicKey:
    raw = base64.urlsafe_b64decode(value.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
