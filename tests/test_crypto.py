import os

import pytest

from helpers.browser_client import encrypt_submission, unb64u
from secure_input.crypto import CryptoFormatError, DecryptError, ServerKey, b64u_decode, b64u_encode


def test_b64url_has_no_padding_and_roundtrips():
    for n in range(0, 40):
        data = os.urandom(n)
        enc = b64u_encode(data)
        assert "=" not in enc and "+" not in enc and "/" not in enc
        assert b64u_decode(enc) == data


@pytest.mark.parametrize("bad", ["a=", "ab+c", "a", "!!!!", 5, None])
def test_b64url_rejects_bad_input(bad):
    with pytest.raises(CryptoFormatError):
        b64u_decode(bad)


def test_b64url_length_check():
    with pytest.raises(CryptoFormatError):
        b64u_decode(b64u_encode(b"x" * 11), length=12)


def test_server_public_key_is_raw_uncompressed_p256():
    raw = unb64u(ServerKey().public_b64)
    assert len(raw) == 65 and raw[0] == 4


def test_each_server_key_is_new():
    assert ServerKey().public_b64 != ServerKey().public_b64


def _open_resp(key: ServerKey, sid: bytes, request_id: str) -> dict:
    return {"server_public_key": key.public_b64, "sid": b64u_encode(sid), "request_id": request_id}


def test_browser_ciphertext_decrypts():
    key, sid, rid = ServerKey(), os.urandom(32), os.urandom(16).hex()
    body = encrypt_submission(_open_resp(key, sid, rid), {"kind": "otp_code", "code": "123456"})
    plain = key.decrypt(unb64u(body["client_public_key"]), sid, unb64u(body["iv"]), unb64u(body["ciphertext"]),
                        rid.encode())
    assert plain == b'{"kind": "otp_code", "code": "123456"}'


@pytest.mark.parametrize("tamper", ["ciphertext", "aad", "sid", "iv"])
def test_tampering_fails_decrypt(tamper):
    key, sid, rid = ServerKey(), os.urandom(32), "r" * 32
    body = encrypt_submission(_open_resp(key, sid, rid), {"x": 1})
    cpub, iv, ct, aad = unb64u(body["client_public_key"]), unb64u(body["iv"]), bytearray(unb64u(body["ciphertext"])), rid.encode()
    if tamper == "ciphertext":
        ct[0] ^= 1
    elif tamper == "aad":
        aad = b"other"
    elif tamper == "sid":
        sid = os.urandom(32)
    elif tamper == "iv":
        iv = os.urandom(12)
    with pytest.raises(DecryptError):
        key.decrypt(cpub, sid, iv, bytes(ct), aad)


def test_invalid_client_point_fails_decrypt():
    key = ServerKey()
    with pytest.raises(DecryptError):
        key.decrypt(b"\x04" + b"\x01" * 64, os.urandom(32), os.urandom(12), os.urandom(32), b"a")
