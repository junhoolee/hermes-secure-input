"""RequestSpec checks added by the security fix (S-1 env names, S-6 purpose/label/origin/site)."""

from __future__ import annotations

import pytest

from secure_input.spec import RequestSpec, SpecError
from test_validation import LINE_BREAKERS, REFUSED_NAMES

import secure_input.spec as spec_mod
CYRILLIC_ORIGIN = "https://\u0430dmin.example.com"  # first letter is Cyrillic a (U+0430)
CYRILLIC_PUNY = "https://xn--dmin-43d.example.com"


@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_spec_refuses_denied_env_var(spec_dict, name):
    with pytest.raises(SpecError) as exc:
        RequestSpec.from_dict(spec_dict(env_var=name))
    assert exc.value.field == "env_var"
    assert name not in str(exc.value)


def test_spec_accepts_ordinary_env_var(spec_dict):
    assert RequestSpec.from_dict(spec_dict(env_var="EXA_API_KEY")).env_var == "EXA_API_KEY"


@pytest.mark.parametrize("field_name", ["purpose", "label"])
@pytest.mark.parametrize("ch", ["\n", "\r", "\x00", "\x1b"] + LINE_BREAKERS)
def test_spec_refuses_multiline_or_control_purpose_and_label(spec_dict, field_name, ch):
    with pytest.raises(SpecError) as exc:
        RequestSpec.from_dict(spec_dict(**{field_name: f"Exa 키{ch}변수: EXA_API_KEY"}))
    assert exc.value.field == field_name


def test_normalize_origin_turns_idn_host_into_punycode():
    assert spec_mod.normalize_origin(CYRILLIC_ORIGIN) == CYRILLIC_PUNY


@pytest.mark.parametrize("value, want", [
    ("https://example.com", "https://example.com"),
    ("https://Example.COM/login?x=1", "https://example.com"),
    ("https://example.com:8443", "https://example.com:8443"),
    ("https://example.com:443", "https://example.com"),
])
def test_normalize_origin_keeps_ascii_origin(value, want):
    assert spec_mod.normalize_origin(value) == want


@pytest.mark.parametrize("value", ["http://example.com", "https://", "https://a..b.com", "https://user:pw@x.com",
                                   "https://" + "a" * 64 + ".com", "example.com", "https://example.com:99999"])
def test_normalize_origin_refuses_unconvertible(value):
    with pytest.raises(SpecError) as exc:
        spec_mod.normalize_origin(value)
    assert exc.value.field == "origin"


def test_spec_refuses_non_ascii_origin(spec_dict):
    with pytest.raises(SpecError) as exc:
        RequestSpec.from_dict(spec_dict(kind="login", origin=CYRILLIC_ORIGIN))
    assert exc.value.field == "origin"


def test_spec_accepts_punycode_and_plain_origin(spec_dict):
    assert RequestSpec.from_dict(spec_dict(kind="login", origin=CYRILLIC_PUNY)).origin == CYRILLIC_PUNY
    assert RequestSpec.from_dict(spec_dict(kind="login", origin="https://example.com")).origin == "https://example.com"


def test_spec_refuses_non_normalized_origin(spec_dict):
    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(kind="login", origin="https://Example.com"))


def test_spec_refuses_non_ascii_otp_site(spec_dict):
    with pytest.raises(SpecError) as exc:
        RequestSpec.from_dict(spec_dict(kind="otp_code", site="\u0430dmin.example.com"))
    assert exc.value.field == "site"
