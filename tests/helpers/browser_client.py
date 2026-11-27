"""Python stand-in for the browser side of the protocol (docs/protocol.md 5.4).

Written independently from ``secure_input.crypto`` so the round-trip tests check the
contract, not the server's own helper. Mirrors WebCrypto: ECDH P-256 -> shared x (32 bytes)
-> HKDF-SHA256(salt=sid raw, info=HKDF_INFO, 32) -> AES-256-GCM(iv 12, aad=request_id).
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"hermes-secure-input/v1/submit"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encrypt_submission(open_resp: dict, plaintext: dict | bytes) -> dict:
    server_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb64u(open_resp["server_public_key"]))
    client_priv = ec.generate_private_key(ec.SECP256R1())
    shared = client_priv.exchange(ec.ECDH(), server_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=unb64u(open_resp["sid"]), info=INFO).derive(shared)
    iv = os.urandom(12)
    data = plaintext if isinstance(plaintext, bytes) else json.dumps(plaintext).encode("utf-8")
    ct = AESGCM(key).encrypt(iv, data, open_resp["request_id"].encode("utf-8"))
    client_pub = client_priv.public_key().public_bytes(serialization.Encoding.X962,
                                                       serialization.PublicFormat.UncompressedPoint)
    return {"v": 2, "sid": open_resp["sid"], "client_public_key": b64u(client_pub), "iv": b64u(iv),
            "ciphertext": b64u(ct)}


def selected_stores(open_resp: dict) -> list[str]:
    """The store names the page would send unchanged: the rows of the open answer that are preselected (A.6)."""
    return [r["store"] for r in (open_resp.get("target") or {}).get("stores") or [] if r.get("selected")]


class BrowserClient:
    """Talks to ``<base_url>`` (which ends with ``/<token>/``) like the UI would."""

    def __init__(self, base_url: str, origin: Optional[str] = "auto", client: Optional[httpx.Client] = None,
                 timeout: float = 30.0, identity: Optional[str] = None):
        """``identity``: send ``Tailscale-User-Login: <identity>`` on every API call, as Tailscale Serve
        does for the account that opened the link (only needed when talking to 127.0.0.1 directly)."""
        if not base_url.endswith("/"):
            raise ValueError("base_url must end with /")
        self.base_url = base_url
        self.identity = identity
        if origin == "auto":
            u = httpx.URL(base_url)
            default_port = {"http": 80, "https": 443}[u.scheme]
            origin = f"{u.scheme}://{u.host}" + ("" if u.port in (None, default_port) else f":{u.port}")
        self.origin = origin
        self.http = client or httpx.Client(timeout=timeout)
        self.opened: Optional[dict] = None

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.origin:
            h["Origin"] = self.origin
        return h

    def get(self, rel: str = "") -> httpx.Response:
        return self.http.get(self.base_url + rel)

    def post(self, rel: str, body: Any, headers: Optional[dict] = None) -> httpx.Response:
        content = body if isinstance(body, (bytes, str)) else json.dumps(body)
        hdrs = dict(headers or self._headers())
        if self.identity is not None and not any(k.lower() == "tailscale-user-login" for k in hdrs):
            hdrs["Tailscale-User-Login"] = self.identity
        return self.http.post(self.base_url + rel, content=content, headers=hdrs)

    def open(self) -> httpx.Response:
        r = self.post("api/open", {})
        if r.status_code == 200:
            self.opened = r.json()
        return r

    def build_submit(self, plaintext: dict | bytes, auto_stores: bool = True) -> dict:
        """Protocol 2 (A.7): a dict without ``stores`` gets the open answer's preselected store names, as the page
        sends them when the user changes nothing (``otp_code`` has no ``stores``). ``auto_stores=False`` sends the
        dict as given."""
        assert self.opened is not None, "open() first"
        if (auto_stores and isinstance(plaintext, dict) and "stores" not in plaintext
                and plaintext.get("kind") != "otp_code"):
            plaintext = dict(plaintext, stores=selected_stores(self.opened))
        return encrypt_submission(self.opened, plaintext)

    def submit(self, plaintext: dict | bytes, auto_stores: bool = True) -> httpx.Response:
        return self.post("api/submit", self.build_submit(plaintext, auto_stores))

    def cancel(self) -> httpx.Response:
        sid = self.opened["sid"] if self.opened else ""
        return self.post("api/cancel", {"sid": sid})
