from pathlib import Path

import pytest

from secure_input import config
from secure_input.profiles import ProfileError, list_profiles, resolve_profile_home
from secure_input.spec import RequestSpec, SpecError


def test_constants_match_contract():
    assert config.OPEN_TTL_S == 60
    assert config.SUBMIT_TTL_S == 300
    assert config.MAX_SUBMIT_ATTEMPTS == 5
    assert config.MAX_ACTIVE_REQUESTS == 3
    assert config.PROTOCOL_VERSION == 2
    assert config.HKDF_INFO == b"hermes-secure-input/v1/submit"


def test_default_profile_resolves_to_root(hermes_root):
    assert resolve_profile_home("default", str(hermes_root)) == hermes_root


def test_named_profile_resolves_under_profiles(hermes_root):
    assert resolve_profile_home("worker", str(hermes_root)) == hermes_root / "profiles" / "worker"


@pytest.mark.parametrize("name", ["missing", "../x", "Worker", "a/b", "", "-x", "x" * 65])
def test_bad_or_missing_profile_is_rejected(hermes_root, name):
    with pytest.raises(ProfileError):
        resolve_profile_home(name, str(hermes_root))


def test_relative_root_is_rejected(hermes_root):
    with pytest.raises(ProfileError):
        resolve_profile_home("default", "relative/path")


def test_list_profiles_reads_root(hermes_root):
    (hermes_root / "profiles" / "Bad Name").mkdir()
    (hermes_root / "profiles" / "alpha").mkdir()
    (hermes_root / "profiles" / "file.txt").write_text("")
    assert list_profiles(str(hermes_root)) == ["default", "alpha", "worker"]


def test_valid_api_key_spec(spec_dict):
    spec = RequestSpec.from_dict(spec_dict())
    assert spec.kind == "api_key" and spec.env_var == "EXA_API_KEY"
    assert RequestSpec.from_dict(spec.to_dict()) == spec


def test_valid_login_and_otp_specs(spec_dict):
    assert RequestSpec.from_dict(spec_dict(kind="login")).origin == "https://example.com"
    otp = RequestSpec.from_dict(spec_dict(kind="otp_code"))
    assert otp.site == "example.com" and otp.profile_editable is False


@pytest.mark.parametrize("over,field", [
    ({"kind": "password"}, "kind"),
    ({"purpose": ""}, "purpose"),
    ({"purpose": "x" * 201}, "purpose"),
    ({"label": ""}, "label"),
    ({"label": "x" * 81}, "label"),
    ({"env_var": "lower_case"}, "env_var"),
    ({"env_var": None}, "env_var"),
    ({"origin": "https://example.com"}, "origin"),
    ({"requester": {"type": "robot", "profile": "default", "platform": "x", "session_key": "", "user_id": ""}},
     "requester"),
    ({"hermes_root": "relative"}, "hermes_root"),
    ({"profile_editable": "yes"}, "profile_editable"),
    ({"target_profile": "../etc"}, "target_profile"),
])
def test_invalid_api_key_specs(spec_dict, over, field):
    with pytest.raises(SpecError) as ei:
        RequestSpec.from_dict(spec_dict(**over))
    assert ei.value.field == field


@pytest.mark.parametrize("over,field", [
    ({"origin": "http://example.com"}, "origin"),
    ({"origin": "https://example.com/path"}, "origin"),
    ({"origin": None}, "origin"),
    ({"env_var": "X"}, "env_var"),
])
def test_invalid_login_specs(spec_dict, over, field):
    with pytest.raises(SpecError) as ei:
        RequestSpec.from_dict(spec_dict(kind="login", **over))
    assert ei.value.field == field


@pytest.mark.parametrize("over,field", [
    ({"profile_editable": True}, "profile_editable"),
    ({"site": "https://example.com"}, "site"),
    ({"site": None}, "site"),
])
def test_invalid_otp_specs(spec_dict, over, field):
    with pytest.raises(SpecError) as ei:
        RequestSpec.from_dict(spec_dict(kind="otp_code", **over))
    assert ei.value.field == field


def test_spec_error_does_not_echo_values(spec_dict):
    secretish = "SECRET-CANARY-specvalue"
    with pytest.raises(SpecError) as ei:
        RequestSpec.from_dict(spec_dict(env_var=secretish))
    assert secretish not in str(ei.value)
