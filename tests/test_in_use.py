from __future__ import annotations

from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import psutil
import pytest

from sficheck import running
from sficheck.models import Package
from sficheck.sources.base import Context
from sficheck.sources.firmware import Firmware
from sficheck.sources.hypervisors import UNDERNEATH, Hypervisors
from sficheck.sources.python import Pip
from sficheck.sources.system import Brew, Dpkg, Flatpak, Pacman, Rpm, Snap
from sficheck.sources.windows import Scoop, WindowsRegistry, _install_folder
from tests.conftest import FakeRun

RUNNING = {Path("/usr/bin/bash"), Path("/opt/app/bin/app")}


def test_running_paths_fall_back_to_an_absolute_command_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bash, sshd = tmp_path / "bash", tmp_path / "sshd"  # absolute on every OS
    processes = [
        {"exe": str(bash), "cmdline": ["bash"]},
        {"exe": None, "cmdline": [str(sshd), "-D"]},  # another user's process hides its exe
        {"exe": None, "cmdline": ["kworker"]},  # relative: can't be placed
        {"exe": None, "cmdline": None},  # kernel thread
    ]
    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: [SimpleNamespace(info=p) for p in processes])
    assert running.running_paths() == {bash, sshd}


@pytest.mark.parametrize(
    ("path", "folder", "inside"),
    [
        (r"C:\Program Files\Mozilla Firefox\firefox.exe", r"c:\program files\mozilla firefox", True),
        (r"C:\Program Files\Mozilla Firefox\firefox.exe", "C:\\Program Files\\Mozilla Firefox\\", True),
        (r"C:\Program Files\Mozilla Firefox2\x.exe", r"C:\Program Files\Mozilla Firefox", False),
        (r"C:\anything.exe", "", False),
    ],
)
def test_under_ignores_case_and_needs_a_whole_folder(path: str, folder: str, inside: bool) -> None:
    assert running.under(Path(path), folder) is inside


def test_pacman_dpkg_and_rpm_ask_who_owns_the_paths(fake_run: FakeRun, ctx: Context) -> None:
    fake_run(
        {
            "pacman -Qqo": "bash\napp\n",
            "dpkg -S": "bash: /usr/bin/bash\nlibfoo1:amd64, libfoo-dev: /opt/app/bin/app\n",
            "rpm -qf": "bash\nfile /opt/app/bin/app is not owned by any package\n",
        }
    )
    assert Pacman(ctx).in_use([], RUNNING) == {"bash", "app"}
    assert Dpkg(ctx).in_use([], RUNNING) == {"bash", "libfoo1", "libfoo-dev"}
    assert Rpm(ctx).in_use([], RUNNING) == {"bash"}


def test_flatpak_snap_and_brew(fake_run: FakeRun, ctx: Context) -> None:
    fake_run({"flatpak ps": "org.mozilla.firefox\norg.gimp.GIMP\n"})
    assert Flatpak(ctx).in_use([], set()) == {"org.mozilla.firefox", "org.gimp.GIMP"}
    paths = {Path("/snap/firefox/4848/usr/lib/firefox/firefox"), Path("/snap/bin/firefox"), Path("/usr/bin/x")}
    assert Snap(ctx).in_use([], paths) == {"firefox"}
    cellar = {Path("/opt/homebrew/Cellar/wget/1.24.5/bin/wget"), Path("/Applications/Zoom.app/Contents/MacOS/zoom")}
    assert Brew(ctx).in_use([], cellar) == {"wget"}


def test_windows_programs_match_by_install_folder(ctx: Context) -> None:
    packages = [
        Package("Mozilla Firefox", "windows", extra={"folder": r"C:\Program Files\Mozilla Firefox"}),
        Package("Zoom", "windows", extra={"folder": r"C:\Users\me\AppData\Roaming\Zoom\bin"}),
        Package("No folder", "windows", extra={"folder": ""}),
    ]
    now = {Path(r"C:\Program Files\Mozilla Firefox\firefox.exe"), Path(r"C:\Windows\explorer.exe")}
    assert WindowsRegistry(ctx).in_use(packages, now) == {"Mozilla Firefox"}


@pytest.mark.parametrize(
    ("values", "folder"),
    [
        ({"InstallLocation": '"C:\\Program Files\\Git\\"'}, "C:\\Program Files\\Git\\"),
        ({"InstallLocation": "C:\\Program Files"}, ""),  # a shared parent would match everything
        ({"DisplayIcon": '"C:\\Apps\\Zoom\\Zoom.exe",0'}, str(PureWindowsPath("C:\\Apps\\Zoom"))),
        ({"DisplayIcon": "C:\\Windows\\Installer\\{GUID}\\app.exe"}, ""),
        ({"DisplayIcon": "C:\\Apps\\Zoom\\zoom.ico"}, ""),
    ],
)
def test_install_folder(values: dict[str, object], folder: str) -> None:
    assert _install_folder(values) == folder


def test_scoop_apps_run_from_their_apps_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ctx: Context) -> None:
    monkeypatch.setenv("SCOOP", str(tmp_path))
    monkeypatch.delenv("SCOOP_GLOBAL", raising=False)
    packages = [Package("7zip", "scoop"), Package("git", "scoop")]
    now = {tmp_path / "apps" / "7zip" / "current" / "7zFM.exe"}
    assert Scoop(ctx).in_use(packages, now) == {"7zip"}


def test_layers_and_sources_that_cant_tell(ctx: Context) -> None:
    hypervisors = [Package("hyper-v", "hypervisors", extra={"role": UNDERNEATH}), Package("vmware", "hypervisors")]
    assert Hypervisors(ctx).in_use(hypervisors, set()) == {"hyper-v"}  # an installed one may sit idle
    assert Firmware(ctx).in_use([Package("intel-me", "firmware")], set()) == {"intel-me"}
    assert Pip(ctx).in_use([Package("requests", "pip")], RUNNING) is None
