"""Contract constants shared with the UI and integration cards (docs/protocol.md, plan appendix A.1)."""

import re

OPEN_TTL_S = 60
SUBMIT_TTL_S = 300
MAX_SUBMIT_ATTEMPTS = 5
MAX_ACTIVE_REQUESTS = 3
PROTOCOL_VERSION = 2
HKDF_INFO = b"hermes-secure-input/v1/submit"

# Implementation limits (not part of the shared contract text, but documented).
MAX_BODY_BYTES = 64 * 1024
SHUTDOWN_GRACE_S = 2.0
READY_TIMEOUT_S = 20.0

KINDS = ("api_key", "login", "otp_code", "secret")
LOGIN_IDENTIFIER_TYPES = ("email", "phone", "username")

# Storage targets (plan appendix A.1). STORE_NAMES is the order of the page's rows and of the writes.
STORE_NAMES = ("env", "hermes_vault", "keychain")
KIND_STORES = {"api_key": ("env", "keychain"), "login": ("hermes_vault",), "secret": ("keychain",), "otp_code": ()}
KIND_DEFAULT_STORES = {"api_key": ("env",), "login": ("hermes_vault",), "secret": ("keychain",), "otp_code": ()}
STORE_TIMEOUT_S = {"env": 10.0, "hermes_vault": 30.0, "keychain": 20.0}
PREFLIGHT_AT_CREATE_TIMEOUT_S = 10.0
WAIT_MARGIN_S = 10.0
CANCEL_MARGIN_S = 5.0
# Checked with re.fullmatch (re.match with "$" lets a trailing newline through).
KEYCHAIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
KEYCHAIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
# Security review 3 N-4: the allow list goes into every model call's tool description; at most this many items
# (each about 300 characters at most, so about 6,000 characters).
MAX_KEYCHAIN_ITEMS = 20

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'"
    ),
}
