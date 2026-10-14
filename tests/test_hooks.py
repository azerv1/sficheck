from __future__ import annotations

import io
import re
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from sficheck import cli, hooks
from sficheck.classify import Classifier
from sficheck.sources.base import Context
from sficheck.sources.system import Dpkg, Pacman, Rpm
from tests.conftest import FakeRun, StubFetcher

COMMAND = ["/home/me/.local/bin/sficheck"]


def test_pacman_hook_runs_before_installs_with_the_targets() -> None:
    text = hooks.hook_text("pacman", COMMAND)
    assert "Operation = Install\n" in text and "Target = *\n" in text
    assert "When = PreTransaction\n" in text and "NeedsTargets\n" in text
    assert "Exec = /home/me/.local/bin/sficheck --check-targets pacman\n" in text
    assert "AbortOnFail" not in text  # it only warns


def test_apt_hook_asks_for_protocol_version_2() -> None:
    text = hooks.hook_text("apt", COMMAND)
    assert 'DPkg::Pre-Install-Pkgs { "/home/me/.local/bin/sficheck --check-targets dpkg || cat > /dev/null"; };' in text
    assert 'DPkg::Tools::Options::/home/me/.local/bin/sficheck::Version "2";' in text


def test_dnf_hook_escapes_spaces_and_skips_all_but_new_installs() -> None:
    line = hooks.hook_text("dnf", COMMAND).splitlines()[-1]
    callback, pattern, direction, options, command = line.split(":", 4)
    assert (callback, pattern, direction, options) == ("pre_transaction", "*", "in", "")
    escaped, positional = re.split(r"(?<!\\) ", command.removeprefix("/bin/sh -c "), maxsplit=1)
    assert positional == "sh ${pkg.action} ${pkg.name} ${pkg.license}"
    script = escaped.replace("\\ ", " ")  # every space is escaped, so sh -c gets one script
    assert script.startswith('[ "$1" = I ] || exit 0; exec /home/me/.local/bin/sficheck')
    assert script.endswith('--check-targets rpm "$2" "$3" >&2')  # dnf5 only shows an action's stderr


def _dnf5_argv(command: str, values: dict[str, str]) -> list[str]:
    """What dnf5's actions plugin executes: split on unescaped spaces, substitute each argument, unescape."""
    args = re.split(r"(?<!\\) +", command)
    for key, value in values.items():
        args = [arg.replace("${" + key + "}", value) for arg in args]
    return [re.sub(r"\\(.)", r"\1", arg) for arg in args]


def test_dnf_hook_keeps_package_values_out_of_the_script() -> None:
    command = hooks.hook_text("dnf", COMMAND).splitlines()[-1].split(":", 4)[4]
    evil = "MIT' ; touch /tmp/pwned ; '"
    argv = _dnf5_argv(command, {"pkg.action": "I", "pkg.name": "zoom", "pkg.license": evil})
    assert argv[:2] == ["/bin/sh", "-c"]
    assert "pwned" not in argv[2]
    assert argv[3:] == ["sh", "I", "zoom", evil]


def test_install_refuses_files_a_user_could_change(monkeypatch: pytest.MonkeyPatch) -> None:
    def stat(owner: int, mode: int) -> Callable[[Path], SimpleNamespace]:
        return lambda self: SimpleNamespace(st_uid=owner, st_mode=mode)

    monkeypatch.setattr(Path, "stat", stat(0, 0o40755))
    hooks._check_root_owned(COMMAND)  # root-owned and not group or world writable
    monkeypatch.setattr(Path, "stat", stat(1000, 0o40755))
    with pytest.raises(OSError, match="can be changed by a user other than root"):
        hooks._check_root_owned(COMMAND)
    monkeypatch.setattr(Path, "stat", stat(0, 0o40777))
    with pytest.raises(OSError, match="system-wide"):
        hooks._check_root_owned(COMMAND)


def test_python_dash_m_runs_through_the_interpreter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["/src/sficheck/__main__.py"])
    assert hooks.sficheck_command() == [sys.executable, "-m", "sficheck"]


@pytest.fixture
def hook_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(hooks, "HOOK_FILES", {m: tmp_path / m / "sficheck.hook" for m in hooks.HOOK_FILES})
    monkeypatch.setattr(hooks, "DNF_ACTIONS_CONF", tmp_path / "missing.conf")
    monkeypatch.setattr(hooks, "_is_linux", lambda: True)
    monkeypatch.setattr(hooks, "_is_root", lambda: True)
    monkeypatch.setattr(hooks, "_check_root_owned", lambda command: None)
    monkeypatch.setattr(cli, "config_path", lambda: tmp_path / "config.json")
    return tmp_path


def test_install_and_remove(hook_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--install-hook", "pacman"]) == 0
    assert (hook_dir / "pacman" / "sficheck.hook").read_text(encoding="utf-8").startswith("# Written by sficheck")
    assert "Installed" in capsys.readouterr().out
    assert "libdnf5-plugin-actions" in hooks.install("dnf")
    assert cli.main(["--remove-hook", "pacman"]) == 0
    assert not (hook_dir / "pacman" / "sficheck.hook").exists()
    assert hooks.remove("pacman").startswith("No sficheck hook")


def test_install_needs_root_and_linux(hook_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hooks, "_is_root", lambda: False)
    with pytest.raises(OSError, match="run it with sudo"):
        hooks.install("apt")
    monkeypatch.setattr(hooks, "_is_linux", lambda: False)
    with pytest.raises(OSError, match="only supported on Linux"):
        hooks.install("apt")
    assert cli.main(["-q", "--install-hook", "apt"]) == 2


APT_STDIN = """VERSION 2
APT::Architecture=amd64
Dir::Cache::archives=/var/cache/apt/archives/

unrar - < 1:7.0.7-1 /var/cache/apt/archives/unrar_7.0.7-1_amd64.deb
bash 5.2.15-2 < 5.2.21-2 /var/cache/apt/archives/bash_5.2.21-2_amd64.deb
nano - < 7.2-1 /var/cache/apt/archives/nano_7.2-1_amd64.deb
oldlib 1.0 < - **REMOVE**
"""


def test_apt_targets_are_only_new_installs(fake_run: FakeRun, ctx: Context) -> None:
    fake_run({"dpkg-deb -f /var/cache/apt/archives/unrar": "non-free/utils\n", "dpkg-deb -f": "editors\n"})
    found = hooks.targets(Dpkg(ctx), io.StringIO(APT_STDIN), [])
    assert [(p.name, p.version, p.extra["section"]) for p in found] == [
        ("unrar", "1:7.0.7-1", "non-free/utils"),
        ("nano", "7.2-1", "editors"),
    ]
    assert hooks.targets(Dpkg(ctx), io.StringIO("unrar\n"), []) == []  # version 1 input isn't understood


def test_check_warns_only_about_proprietary_targets(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fetcher.bodies["/blacklist.txt"] = "unrar:unar:::[nonfree] proprietary license\n"
    pacman = Pacman(ctx)
    packages = hooks.targets(pacman, io.StringIO("unrar\nbash\n\n"), [])
    warnings = hooks.check(pacman, packages, Classifier(fetcher=fetcher))
    assert warnings == ["sficheck: unrar is nonfree (proprietary license); free alternatives: unar"]
    rpm = Rpm(ctx)
    assert hooks.check(rpm, hooks.targets(rpm, [], ["zoom", "Proprietary"]), Classifier(fetcher=fetcher))
    assert hooks.check(rpm, hooks.targets(rpm, [], ["bash", "GPL-3.0-or-later"]), Classifier(fetcher=fetcher)) == []


def test_check_targets_never_fails_the_install(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(hooks, "targets", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    assert cli.main(["--offline", "--check-targets", "rpm", "zoom", "Proprietary"]) == 0
    assert cli.main(["-q", "zoom"]) == 2  # stray arguments outside a hook are an error
