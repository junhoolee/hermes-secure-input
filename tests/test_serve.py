import subprocess

import pytest

from secure_input import serve as serve_mod
from secure_input.serve import ServeError, ServeManager, find_tailscale_bin


class FakeRunner:
    def __init__(self, dns="box.tailnet.ts.net.", rc=0):
        self.calls = []
        self.dns, self.rc = dns, rc

    def __call__(self, argv):
        self.calls.append(argv[1:])
        if argv[1:3] == ["status", "--json"]:
            out = '{"Self": {"DNSName": "%s"}}' % self.dns
        else:
            out = ""
        return subprocess.CompletedProcess(argv, self.rc, out, "")


def test_bin_lookup_order(tmp_path, monkeypatch):
    env_bin = tmp_path / "ts-env"
    env_bin.write_text("")
    env_bin.chmod(0o755)
    monkeypatch.setenv("SECURE_INPUT_TAILSCALE_BIN", str(env_bin))
    assert find_tailscale_bin() == str(env_bin)

    monkeypatch.delenv("SECURE_INPUT_TAILSCALE_BIN")
    app = tmp_path / "Tailscale"
    app.write_text("")
    app.chmod(0o755)
    monkeypatch.setattr(serve_mod, "MACOS_APP_BIN", str(app))
    assert find_tailscale_bin() == str(app)

    monkeypatch.setattr(serve_mod, "MACOS_APP_BIN", str(tmp_path / "missing"))
    path_dir = tmp_path / "bin"
    path_dir.mkdir()
    (path_dir / "tailscale").write_text("")
    (path_dir / "tailscale").chmod(0o755)
    monkeypatch.setenv("PATH", str(path_dir))
    assert find_tailscale_bin() == str(path_dir / "tailscale")

    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert find_tailscale_bin() is None


def test_dns_name_from_status_json():
    r = FakeRunner(dns="box.tailnet.ts.net.")
    assert ServeManager(bin="/x/tailscale", runner=r).dns_name() == "box.tailnet.ts.net"
    assert r.calls == [["status", "--json"]]


def test_add_and_remove_commands():
    r = FakeRunner()
    sm = ServeManager(bin="/x/tailscale", runner=r)
    sm.add("TOKEN123", 4567)
    sm.remove("TOKEN123")
    assert r.calls == [
        ["serve", "--bg", "--https=443", "--set-path", "/TOKEN123", "http://127.0.0.1:4567/TOKEN123"],
        ["serve", "--https=443", "--set-path", "/TOKEN123", "off"],
    ]


def test_add_failure_raises_without_token():
    sm = ServeManager(bin="/x/tailscale", runner=FakeRunner(rc=1))
    with pytest.raises(ServeError) as ei:
        sm.add("TOKEN123", 1)
    assert "TOKEN123" not in str(ei.value)


def test_remove_failure_returns_false():
    assert ServeManager(bin="/x/tailscale", runner=FakeRunner(rc=1)).remove("TOKEN123") is False


@pytest.mark.parametrize("bad", ["", "a/b", "a b", "../x"])
def test_bad_token_rejected(bad):
    with pytest.raises(ServeError):
        ServeManager(bin="/x/tailscale", runner=FakeRunner()).add(bad, 1)


def test_source_never_uses_funnel_or_reset():
    import inspect
    src = inspect.getsource(serve_mod)
    assert "funnel" not in src.lower()
    assert '"reset"' not in src
