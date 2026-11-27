"""`/secure-input` argument parsing (card 5.2)."""

import pytest

from secure_input.command import CommandError, parse_command, USAGE


def test_key_with_defaults():
    c = parse_command("key EXA_API_KEY")
    assert c.action == "key"
    assert c.kind == "api_key" and c.env_var == "EXA_API_KEY" and c.origin is None
    assert c.profile is None
    assert c.purpose == "EXA_API_KEY 값을 직접 등록합니다"
    assert c.label == "EXA_API_KEY"


def test_key_with_all_options_quoted():
    c = parse_command('key EXA_API_KEY --profile worker --purpose "검색 도구 키 교체" --label "Exa 키"')
    assert (c.profile, c.purpose, c.label) == ("worker", "검색 도구 키 교체", "Exa 키")


def test_login_defaults_use_host():
    c = parse_command("login https://admin.example.com")
    assert c.kind == "login" and c.origin == "https://admin.example.com"
    assert c.label == "admin.example.com"
    assert c.purpose == "https://admin.example.com 로그인 정보를 직접 등록합니다"


def test_login_url_with_path_is_reduced_to_origin():
    c = parse_command("login https://admin.example.com:8443/login?next=/ --label 관리자")
    assert c.origin == "https://admin.example.com:8443"
    assert c.label == "관리자"


def test_help_and_empty_return_usage():
    assert parse_command("help").action == "help"
    assert parse_command("").action == "help"


@pytest.mark.parametrize("raw", [
    "key", "key lower_case", "key 1ABC", "login", "login http://plain.example.com", "login notaurl",
    "key A --profile", "key A --bogus x", "key A extra", "frobnicate", 'key A --purpose "unterminated',
    "key A --purpose " + "가" * 201, "key A --label " + "x" * 81, "key A --profile Bad!Name",
])
def test_bad_arguments_raise_with_korean_usage(raw):
    with pytest.raises(CommandError) as ei:
        parse_command(raw)
    assert "사용법" in str(ei.value)
    assert USAGE in ei.value.usage_text()


def test_usage_mentions_all_forms():
    for form in ("key <ENV_VAR>", "login <https://", "help", "--profile", "--purpose", "--label"):
        assert form in USAGE


# --- card 3: /secure-input secret <keychain_item> (plan 7.1) ------------------------------------------------------

def test_secret_with_defaults():
    c = parse_command("secret test-item")
    assert c.action == "secret" and c.kind == "secret" and c.keychain_item == "test-item"
    assert c.env_var is None and c.origin is None and c.profile is None
    assert c.label == "test-item"
    assert c.purpose == "Mac 키체인 항목 test-item 의 값을 직접 등록합니다"


def test_secret_with_all_options():
    c = parse_command('secret example-cred --label "예시 비밀번호" --profile worker --purpose "잠금 해제용"')
    assert (c.keychain_item, c.label, c.profile, c.purpose) == ("example-cred", "예시 비밀번호", "worker", "잠금 해제용")


def test_secret_name_shape_is_left_to_the_tool_rules():
    # plan 3.2 rules 3-8 run in the plugin, the same as for the tool argument
    assert parse_command("secret Example-Service").keychain_item == "Example-Service"


@pytest.mark.parametrize("raw", ["secret", "secret a b", "secret a --store keychain", "secret a --stores env"])
def test_secret_bad_arguments(raw):
    with pytest.raises(CommandError):
        parse_command(raw)


def test_usage_mentions_secret_and_no_store_option():
    assert "/secure-input secret <keychain_item>" in USAGE
    assert "--store" not in USAGE
