"""Server side of the browser encryption (docs/protocol.md 4).

ECDH P-256 (server key per request, private key kept in memory only) -> shared x coordinate
-> HKDF-SHA256(salt = sid raw 32 bytes, info = HKDF_INFO, length 32) -> AES-256-GCM
(iv 12 bytes, tag appended to ciphertext, AAD = request_id UTF-8).
"""

from __future__ import annotations

import base64
import re
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import HKDF_INFO

_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class CryptoFormatError(ValueError):
    """Malformed encoding or wrong length (maps to ``invalid_payload``)."""


class DecryptError(ValueError):
    """Key agreement or authentication failed (maps to ``decrypt_failed``)."""


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text, length: Optional[int] = None) -> bytes:
    if not isinstance(text, str) or not _B64U_RE.fullmatch(text) or len(text) % 4 == 1:
        raise CryptoFormatError("not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:  # binascii.Error subclasses ValueError; regex guards most
        raise CryptoFormatError("not unpadded base64url") from exc
    if b64u_encode(raw) != text:
        raise CryptoFormatError("non-canonical base64url")
    if length is not None and len(raw) != length:
        raise CryptoFormatError("wrong length")
    return raw


class ServerKey:
    """A fresh P-256 key pair for one request."""

    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())
        raw = self._priv.public_key().public_bytes(serialization.Encoding.X962,
                                                   serialization.PublicFormat.UncompressedPoint)
        self.public_b64 = b64u_encode(raw)

    def __repr__(self) -> str:  # never print key material
        return "ServerKey(<redacted>)"

    def decrypt(self, client_public: bytes, sid: bytes, iv: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public)
            shared = self._priv.exchange(ec.ECDH(), peer)
        except (ValueError, TypeError) as exc:
            raise DecryptError("key agreement failed") from None
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=sid, info=HKDF_INFO).derive(shared)
        try:
            return AESGCM(key).decrypt(iv, ciphertext, aad)
        except (InvalidTag, ValueError):
            raise DecryptError("authentication failed") from None
