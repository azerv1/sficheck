from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest

from sficheck.blacklist import Blacklist
from sficheck.classify import Classifier
from sficheck.models import Entry, Finding, Package, Ring, Status
from sficheck.sources import ALL_SOURCES, BY_NAME, _registry, firmware, hardware, hypervisors, kernel
from sficheck.sources.base import Context, Source
from sficheck.sources.compiled import Cargo, Go
from sficheck.sources.firmware import Firmware
from sficheck.sources.hardware import Hardware
from sficheck.sources.hypervisors import Hypervisors
from sficheck.sources.javascript import Npm
from sficheck.sources.jvm import Maven, Sdkman
from sficheck.sources.kernel import Kernel
from sficheck.sources.python import Pip
from sficheck.sources.scripting import CranR, Gem, GhcPkg
from sficheck.sources.system import Brew, Dpkg, Nix, Pacman, Snap
from sficheck.sources.windows import Chocolatey, Scoop
from tests.conftest import FakeRun, StubFetcher

FIXTURES = Path(__file__).parent / "fixtures"


def scan(source: Source, fetcher: StubFetcher, **kwargs: bool) -> dict[str, Finding]:
    classifier = Classifier(fetcher=fetcher, **kwargs)  # type: ignore[arg-type]
    return {f.package.name: f for f in classifier.run(source, list(source.packages()))}


def test_registry_names_are_unique() -> None:
    assert len(BY_NAME) == len(ALL_SOURCES)


def test_pacman_uses_parabola_and_treats_the_rest_as_free(fake_run: FakeRun, fetcher: StubFetcher) -> None:
    fetcher.bodies["plain/blacklist.txt"] = (FIXTURES / "blacklist_sample.txt").read_text(encoding="utf-8")
    fetcher.bodies["aur-blacklist.txt"] = "acroread::::\n"
    fake_run({"pacman -Qqm": "acroread\n", "pacman -Q": "unrar 1:7.0-1\nbash 5.2-1\nacroread 9.5-1\n"})
    found = scan(Pacman(Context(fetcher=fetcher)), fetcher)
    assert found["unrar"].status is Status.NONFREE
    assert found["unrar"].reason == "parabola:blacklist"
    assert found["acroread"].status is Status.NONFREE
    assert found["bash"].status is Status.FREE
    assert found["unrar"].package.version == "1:7.0-1"


def test_dpkg_sections(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fake_run(
        {
            "dpkg-query": "ii \tunrar\t1:7.0\tnon-free/utils\n"
            "ii \tfirmware-iwlwifi\t1\tnon-free-firmware/kernel\n"
            "ii \tsteam-installer\t1\tcontrib/games\n"
            "ii \tcoreutils\t9.1\tutils\n"
            "rc \tremoved\t1\tnon-free/utils\n"
            "ii \tgoogle-chrome-stable\t130\tweb\n"
            "ii \tnvidia-driver\t1\trestricted/misc\n"
        }
    )
    found = scan(Dpkg(ctx), fetcher)
    assert "removed" not in found
    assert found["unrar"].status is Status.NONFREE
    assert found["firmware-iwlwifi"].status is Status.NONFREE
    assert found["steam-installer"].status is Status.USES_NONFREE  # section wins over the curated list
    assert found["coreutils"].status is Status.FREE
    assert found["google-chrome-stable"].status is Status.NONFREE  # curated list
    assert found["nvidia-driver"].status is Status.NONFREE  # Ubuntu component


def test_nix_meta(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    env = {
        "a": {"pname": "hello", "version": "2.12", "meta": {"license": {"spdxId": "GPL-3.0-or-later", "free": True}}},
        "b": {
            "pname": "unrar",
            "version": "7",
            "meta": {"unfree": True, "license": {"shortName": "unfreeRedistributable", "free": False}},
        },
        "c": {
            "pname": "mixed",
            "version": "1",
            "meta": {"license": [{"spdxId": "MIT", "free": True}, {"shortName": "unfree", "free": False}]},
        },
        "d": {"pname": "mystery", "version": "1", "meta": {}},
    }
    fake_run({"nix-env": json.dumps(env)})
    found = scan(Nix(ctx), fetcher)
    assert found["hello"].status is Status.FREE
    assert found["unrar"].status is Status.NONFREE
    assert found["mixed"].status is Status.SEMIFREE
    assert found["mystery"].status is Status.UNKNOWN


def test_snap(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fake_run(
        {
            "snap list": "Name  Version  Rev  Tracking  Publisher  Notes\nspotify 1.2 80 latest/stable spotify -\nhtop 3.3 4000 latest/stable maxiberta -\n",
            "snap info htop": "name: htop\nlicense: GPL-2.0\n",
            "snap info spotify": "name: spotify\nlicense: unset\n",
        }
    )
    found = scan(Snap(ctx), fetcher)
    assert found["htop"].status is Status.FREE
    assert found["spotify"].status is Status.NONFREE  # curated


def test_brew(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    data = {
        "formulae": [{"name": "wget", "license": "GPL-3.0-or-later", "installed": [{"version": "1.24"}]}],
        "casks": [{"token": "google-chrome", "version": "130", "installed": "130"}],
    }
    fake_run({"brew info": json.dumps(data)})
    found = scan(Brew(ctx), fetcher)
    assert found["wget"].status is Status.FREE
    assert found["google-chrome"].status is Status.NONFREE


def test_cargo_reads_registry_manifest(
    fake_run: FakeRun, fetcher: StubFetcher, ctx: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    crate = tmp_path / "registry" / "src" / "index.crates.io-xyz" / "ripgrep-14.1.0"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text('[package]\nname = "ripgrep"\nlicense = "Unlicense OR MIT"\n')
    monkeypatch.setenv("CARGO_HOME", str(tmp_path))
    fake_run({"cargo install --list": "ripgrep v14.1.0:\n    rg\nlocal v0.1.0 (/src/local):\n    local\n"})
    found = scan(Cargo(ctx), fetcher)
    assert found["ripgrep"].status is Status.FREE
    assert found["local"].status is Status.UNKNOWN


def test_go_module_cache_license(
    fake_run: FakeRun, fetcher: StubFetcher, ctx: Context, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir, modcache = tmp_path / "bin", tmp_path / "mod"
    bin_dir.mkdir()
    (bin_dir / "gopls").write_bytes(b"")
    mod = modcache / "golang.org" / "x" / "tools" / "!gopls@v0.16.0"
    mod.mkdir(parents=True)
    (mod / "LICENSE").write_text("Redistribution and use in source and binary forms, with or without modification")
    fake_run(
        {
            "go env": f"{bin_dir}\n{tmp_path}\n{modcache}\n",
            "go version": f"{bin_dir}/gopls: go1.23\n\tpath\tgolang.org/x/tools/gopls\n\tmod\tgolang.org/x/tools/Gopls\tv0.16.0\th1:x\n",
        }
    )
    found = scan(Go(ctx), fetcher)
    assert found["golang.org/x/tools/Gopls"].status is Status.FREE


def test_npm_node_modules(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context, tmp_path: Path) -> None:
    root = tmp_path / "node_modules"
    for name, lic in [
        ("typescript", "Apache-2.0"),
        ("@anthropic-ai/claude-code", "SEE LICENSE IN README.md"),
        ("weird", None),
    ]:
        pkg = root / name
        pkg.mkdir(parents=True)
        data: dict[str, object] = {"name": name, "version": "1.0.0"}
        if lic:
            data["license"] = lic
        (pkg / "package.json").write_text(json.dumps(data))
    (root / "weird" / "LICENSE").write_text("Permission is hereby granted, free of charge, to any person")
    fake_run({"npm root -g": f"{root}\n"})
    found = scan(Npm(ctx), fetcher)
    assert found["typescript"].status is Status.FREE
    assert found["@anthropic-ai/claude-code"].status is Status.NONFREE  # curated beats "SEE LICENSE"
    assert found["weird"].status is Status.FREE  # sniffed LICENSE file


def test_pip_dist_info_prefers_classifiable_field(
    fake_run: FakeRun, fetcher: StubFetcher, ctx: Context, tmp_path: Path
) -> None:
    site = tmp_path / "site-packages"
    dist = site / "python_dateutil-2.9.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: python-dateutil\nVersion: 2.9\nLicense: Dual License\n"
        "Classifier: License :: OSI Approved :: BSD License\nClassifier: License :: OSI Approved :: Apache Software License\n"
    )
    nf = site / "nvidia_cublas_cu12-12.4.dist-info"
    nf.mkdir()
    (nf / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: nvidia-cublas-cu12\nVersion: 12.4\nLicense: NVIDIA Proprietary Software\n"
    )
    fake_run({"py": json.dumps([str(site)]), "python3": json.dumps([str(site)])})
    found = scan(Pip(ctx), fetcher)
    assert found["python-dateutil"].status is Status.FREE
    assert found["nvidia-cublas-cu12"].status is Status.NONFREE


def test_gem_r_ghc(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fake_run(
        {
            "ruby": json.dumps(
                [{"name": "rake", "version": "13", "licenses": ["MIT"]}, {"name": "x", "version": "1", "licenses": []}]
            ),
            "Rscript": "ggplot2\t3.5\tMIT + file LICENSE\nrlang\t1.1\tGPL-2 | GPL-3\n",
            "ghc-pkg": "name: base\nversion: 4.19\nlicense: BSD-3-Clause\nname: secret\nversion: 1\nlicense: AllRightsReserved\n",
        }
    )
    gems = scan(Gem(ctx), fetcher)
    assert gems["rake"].status is Status.FREE and gems["x"].status is Status.UNKNOWN
    r = scan(CranR(ctx), fetcher)
    assert r["ggplot2"].status is Status.FREE and r["rlang"].status is Status.FREE
    hs = scan(GhcPkg(ctx), fetcher)
    assert hs["base"].status is Status.FREE and hs["secret"].status is Status.UNKNOWN


def test_maven_pom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    version_dir = tmp_path / ".m2" / "repository" / "org" / "slf4j" / "slf4j-api" / "2.0.9"
    version_dir.mkdir(parents=True)
    (version_dir / "slf4j-api-2.0.9.pom").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><licenses><license><name>MIT License</name></license></licenses></project>'
    )
    found = scan(Maven(ctx), fetcher)
    assert found["org.slf4j:slf4j-api"].status is Status.FREE
    assert not Maven.default_enabled


def test_sdkman_java_vendors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    monkeypatch.setenv("SDKMAN_DIR", str(tmp_path))
    for d in ["java/21.0.2-oracle", "java/21.0.2-tem", "java/current", "gradle/8.5"]:
        (tmp_path / "candidates" / d).mkdir(parents=True)
    found = {
        (f.package.name, f.package.version): f
        for f in Classifier(fetcher=fetcher).run(Sdkman(ctx), list(Sdkman(ctx).packages()))
    }
    assert found[("java", "21.0.2-oracle")].status is Status.NONFREE
    assert found[("java", "21.0.2-tem")].status is Status.FREE
    assert ("java", "current") not in found
    assert found[("gradle", "8.5")].status is Status.UNKNOWN


def test_scoop_and_choco(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context) -> None:
    app = tmp_path / "scoop" / "apps" / "ripgrep" / "current"
    app.mkdir(parents=True)
    (app / "manifest.json").write_text(json.dumps({"version": "14.1", "license": {"identifier": "MIT"}}))
    monkeypatch.setenv("SCOOP", str(tmp_path / "scoop"))
    assert scan(Scoop(ctx), fetcher)["ripgrep"].status is Status.FREE

    lib = tmp_path / "choco" / "lib"
    for pkg_id, extra in [("KB2919355", ""), ("jq", "<licenseUrl>https://opensource.org/licenses/MIT</licenseUrl>")]:
        (lib / pkg_id).mkdir(parents=True)
        (lib / pkg_id / f"{pkg_id}.nuspec").write_text(
            f'<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd"><metadata>'
            f"<id>{pkg_id}</id><version>1.0</version>{extra}</metadata></package>"
        )
    monkeypatch.setenv("CHOCOLATEYINSTALL", str(tmp_path / "choco"))
    found = scan(Chocolatey(ctx), fetcher)
    assert found["KB2919355"].status is Status.NONFREE
    assert found["jq"].status is Status.FREE


def test_ignore_user_list_and_online(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fake_run(
        {
            "ruby": json.dumps(
                [{"name": "a", "version": "1", "licenses": []}, {"name": "b", "version": "1", "licenses": []}]
            )
        }
    )
    fetcher.bodies["RUBYGEMS/packages/a/versions/1"] = json.dumps({"licenses": ["MIT"]})
    from sficheck.blacklist import Blacklist
    from sficheck.models import Entry

    user = Blacklist()
    user.add(Entry("b", Status.NONFREE, origin="user:mine"))
    classifier = Classifier(fetcher=fetcher, user=user, online=True, ignore=frozenset())
    found = {f.package.name: f for f in classifier.run(Gem(ctx), list(Gem(ctx).packages()))}
    assert found["a"].status is Status.FREE and found["a"].reason == "online:rubygems"
    assert found["b"].status is Status.NONFREE and found["b"].reason == "user:mine"
    ignored = Classifier(fetcher=fetcher, ignore=frozenset({"a"})).run(Gem(ctx), list(Gem(ctx).packages()))
    assert [f.package.name for f in ignored] == ["b"]


def test_dpkg_unavailable_without_tool(fake_run: FakeRun, ctx: Context) -> None:
    fake_run({})
    assert not Dpkg(ctx).available()
    assert not Pacman(ctx).available()


class _Platform(Source):
    name = "platform-test"
    default_ring = Ring.HYPERVISOR

    def available(self) -> bool:
        return True

    def packages(self) -> Iterable[Package]:
        return [self.pkg("blob", license="Proprietary"), self.pkg("calendar"), self.pkg("bash", license="GPL-3.0")]


def test_ring_comes_from_entry_else_source_default(fetcher: StubFetcher, ctx: Context) -> None:
    user = Blacklist()
    user.add(Entry("calendar", Status.NONFREE, ring=Ring.USER))
    source = _Platform(ctx)
    found = {f.package.name: f for f in Classifier(fetcher=fetcher, user=user).run(source, source.packages())}
    assert found["blob"].ring is Ring.HYPERVISOR
    assert found["calendar"].ring is Ring.USER
    assert found["bash"].ring is None  # free software gets no severity


def test_kernel_modules_use_the_taint_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    proc_modules = tmp_path / "modules"
    proc_modules.write_text(
        "nvidia 54001664 0 - Live 0x0 (POE)\nwl 6365184 0 - Live 0x0 (POE)\next4 1081344 1 - Live 0x0\n"
    )
    for name, taint, version in [("nvidia", "POE", "550.78"), ("wl", "POE", ""), ("ext4", "", "")]:
        (tmp_path / "sys" / name).mkdir(parents=True)
        (tmp_path / "sys" / name / "taint").write_text(taint + "\n")
        if version:
            (tmp_path / "sys" / name / "version").write_text(version + "\n")
    monkeypatch.setattr(kernel, "IS_WINDOWS", False)
    monkeypatch.setattr(kernel, "PROC_MODULES", proc_modules)
    monkeypatch.setattr(kernel, "SYS_MODULE", tmp_path / "sys")
    found = scan(Kernel(ctx), fetcher)
    assert found["nvidia"].status is Status.NONFREE and found["nvidia"].alternatives  # curated: nouveau
    assert found["nvidia"].package.version == "550.78" and found["nvidia"].ring is Ring.KERNEL
    assert found["wl"].status is Status.NONFREE and found["wl"].reason == "kernel taint P"
    assert found["ext4"].status is Status.FREE and found["ext4"].ring is None


def test_windows_drivers_keep_third_party_ones_in_use(
    monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    services = [
        ("vgk", "", 1, 0),  # loads at system start
        ("mystery", r"\??\C:\Program Files\Game\ac.sys", 3, 0),  # on demand, outside Windows
        ("igfxn", "", 3, 1),  # bound to a device
        ("megasas", "", 0, 0),  # inbox boot driver, no such controller here
        ("disk", "", 0, 1),  # Microsoft's
        ("gone", r"\??\C:\Games\gone.sys", 3, 0),  # registry leftover, file deleted
        ("NDKPerf", "", 3, 1),  # inbox file without version info
    ]
    infos = {
        r"C:\Windows\System32\drivers\vgk.sys": {"CompanyName": "Riot Games, Inc.", "FileVersion": "1.17"},
        r"C:\Program Files\Game\ac.sys": {},
        r"C:\Windows\System32\drivers\igfxn.sys": {
            "CompanyName": "Intel Corporation",
            "ProductName": "Intel HD Graphics",
        },
        r"C:\Windows\System32\drivers\megasas.sys": {"CompanyName": "Avago Technologies"},
        r"C:\Windows\System32\drivers\disk.sys": {"CompanyName": "Microsoft Corporation"},
        r"C:\Windows\System32\drivers\NDKPerf.sys": {},
    }
    monkeypatch.setattr(kernel, "IS_WINDOWS", True)
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setattr(kernel, "_windows_driver_services", lambda: iter(services))
    monkeypatch.setattr(kernel, "_file_info", infos.get)
    found = scan(Kernel(ctx), fetcher)
    assert sorted(found) == ["igfxn", "mystery", "vgk"]
    assert found["igfxn"].status is Status.NONFREE and found["igfxn"].ring is Ring.KERNEL
    assert found["igfxn"].description == "Intel HD Graphics (Intel Corporation)"
    assert found["vgk"].package.version == "1.17"
    assert found["mystery"].description == "Driver from an unnamed vendor"
    assert found["vgk"].description.startswith("Riot Vanguard")  # curated entry wins over the fallback


def test_image_paths_resolve_to_files() -> None:
    root = r"C:\Windows"
    assert kernel._image_path("vgk", "", root) == r"C:\Windows\System32\drivers\vgk.sys"
    assert kernel._image_path("x", r"\??\D:\x.sys", root) == r"D:\x.sys"
    assert kernel._image_path("x", r"\SystemRoot\System32\x.sys", root) == r"C:\Windows\System32\x.sys"
    assert kernel._image_path("x", r"System32\drivers\x.sys", root) == r"C:\Windows\System32\drivers\x.sys"


def test_linux_guest_names_its_hypervisor_and_installed_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    (tmp_path / "cpuinfo").write_text("processor\t: 0\nflags\t\t: fpu vme hypervisor lahf_lm\n")
    (tmp_path / "dmi").mkdir()
    (tmp_path / "dmi" / "sys_vendor").write_text("Microsoft Corporation\n")
    (tmp_path / "dmi" / "product_name").write_text("Virtual Machine\n")
    (tmp_path / "modules").write_text("kvm_intel 1 0 - Live 0x0\nkvm 2 1 kvm_intel, Live 0x0\nvmmon 3 0 - Live 0x0\n")
    monkeypatch.setattr(hypervisors, "IS_WINDOWS", False)
    monkeypatch.setattr(hypervisors, "CPUINFO", tmp_path / "cpuinfo")
    monkeypatch.setattr(hypervisors, "DMI", tmp_path / "dmi")
    monkeypatch.setattr(hypervisors, "XEN", tmp_path / "missing")
    monkeypatch.setattr(hypervisors, "OSRELEASE", tmp_path / "missing")
    monkeypatch.setattr(hypervisors, "PROC_MODULES", tmp_path / "modules")
    found = scan(Hypervisors(ctx), fetcher)
    assert sorted(found) == ["hyper-v", "kvm", "vmware"]
    assert found["hyper-v"].status is Status.NONFREE and found["hyper-v"].ring is Ring.HYPERVISOR
    assert found["hyper-v"].package.extra["role"] == "running underneath this OS"
    assert found["kvm"].status is Status.FREE and found["vmware"].package.extra["role"] == "installed"


def test_windows_on_bare_metal_with_a_hypervisor_runs_on_hyper_v(
    monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    machine = {"SystemManufacturer": "HP", "SystemProductName": "HP Pavilion Laptop"}
    monkeypatch.setattr(hypervisors, "IS_WINDOWS", True)
    monkeypatch.setattr(hypervisors, "_windows_hypervisor_present", lambda: True)
    monkeypatch.setattr(_registry, "value", lambda key, name: machine.get(name, ""))
    monkeypatch.setattr(hypervisors, "_windows_services", lambda: {"VBoxSup"})
    found = scan(Hypervisors(ctx), fetcher)
    assert sorted(found) == ["hyper-v", "virtualbox"]
    assert found["hyper-v"].status is Status.NONFREE
    machine["SystemManufacturer"] = "VMware, Inc."  # Windows as a guest
    assert "vmware" in scan(Hypervisors(ctx), fetcher)
    monkeypatch.setattr(hypervisors, "_windows_hypervisor_present", lambda: False)
    assert sorted(scan(Hypervisors(ctx), fetcher)) == ["virtualbox"]


def test_linux_firmware_reads_dmi_cpuinfo_and_the_me(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    (tmp_path / "cpuinfo").write_text(
        "processor\t: 0\nvendor_id\t: GenuineIntel\nmicrocode\t: 0xf4\n\nprocessor\t: 1\nvendor_id\t: x\n"
    )
    (tmp_path / "dmi").mkdir()
    (tmp_path / "dmi" / "bios_vendor").write_text("American Megatrends Inc.\n")
    (tmp_path / "dmi" / "bios_version").write_text("1.20\n")
    (tmp_path / "fw_ver").write_text("0:16.1.25.1885\n0:16.1.25.1885\n")
    monkeypatch.setattr(firmware, "IS_WINDOWS", False)
    monkeypatch.setattr(firmware, "CPUINFO", tmp_path / "cpuinfo")
    monkeypatch.setattr(firmware, "DMI", tmp_path / "dmi")
    monkeypatch.setattr(firmware, "MEI_FW_VER", tmp_path / "fw_ver")
    found = scan(Firmware(ctx), fetcher)
    assert sorted(found) == ["American Megatrends Inc.", "intel-me", "intel-microcode"]
    bios = found["American Megatrends Inc."]
    assert bios.status is Status.NONFREE and bios.ring is Ring.FIRMWARE and bios.package.version == "1.20"
    assert found["intel-me"].ring is Ring.ME and found["intel-me"].package.version == "16.1.25.1885"
    assert found["intel-microcode"].package.version == "0xf4"


def test_windows_firmware_reads_the_registry(
    monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    keys: dict[str, dict[str, object]] = {
        firmware.BIOS_KEY: {"BIOSVendor": "coreboot", "BIOSVersion": "4.22"},
        firmware.CPU_KEY: {"VendorIdentifier": "AuthenticAMD", "Update Revision": b"\0\0\0\0\x15\x01\x20\x0a"},
    }
    monkeypatch.setattr(firmware, "IS_WINDOWS", True)
    monkeypatch.setattr(_registry, "values", lambda key: keys[key])
    found = scan(Firmware(ctx), fetcher)
    assert found["coreboot"].status is Status.USES_NONFREE  # curated: free, but with blobs
    assert found["amd-psp"].status is Status.NONFREE and found["amd-psp"].ring is Ring.ME
    assert found["amd-microcode"].package.version == "0xa200115"
    assert firmware._revision(b"\xac\0\0\0") == "0xac" and firmware._revision(b"\0" * 8) == ""


def test_linux_hardware_judges_devices_by_driver_and_firmware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_run: FakeRun, fetcher: StubFetcher, ctx: Context
) -> None:
    devices = [
        ("NVIDIA Corporation AD104 [GeForce RTX 4070]", "nvidia"),
        ("Intel Corporation Wi-Fi 6 AX201", "iwlwifi"),
        ("Realtek Semiconductor Co., Ltd. RTL8111/8168 PCI Express Gigabit Ethernet", "r8169"),
        ("Realtek 802.11n", "wl"),
    ]
    (tmp_path / "module" / "wl").mkdir(parents=True)
    (tmp_path / "module" / "wl" / "taint").write_text("POE\n")
    (tmp_path / "firmware").mkdir()
    for blob in ("iwlwifi-so-a0-gf-a0-72.ucode.zst", "iwlwifi-so-a0-gf-a0.pnvm", "rtl_nic/rtl8168h-2.fw"):
        (tmp_path / "firmware" / blob).parent.mkdir(exist_ok=True)
        (tmp_path / "firmware" / blob).write_bytes(b"\0")
    fake_run(
        {
            "modinfo -F firmware iwlwifi": "iwlwifi-so-a0-gf-a0-72.ucode\niwlwifi-so-a0-gf-a0.pnvm\niwlwifi-ty-a0.ucode\n",
            "modinfo -F firmware r8169": "",
        }
    )
    monkeypatch.setattr(hardware, "IS_WINDOWS", False)
    monkeypatch.setattr(hardware, "_linux_devices", lambda: devices)
    monkeypatch.setattr(hardware, "SYS_MODULE", tmp_path / "module")
    monkeypatch.setattr(hardware, "FIRMWARE_DIR", tmp_path / "firmware")
    found = scan(Hardware(ctx), fetcher)
    gpu, wifi = found["NVIDIA Corporation AD104 [GeForce RTX 4070]"], found["Intel Corporation Wi-Fi 6 AX201"]
    assert gpu.status is Status.NONFREE and gpu.ring is Ring.KERNEL and gpu.alternatives  # curated nvidia entry
    assert wifi.status is Status.USES_NONFREE
    assert wifi.description == "iwlwifi loads iwlwifi-so-a0-gf-a0-72.ucode, iwlwifi-so-a0-gf-a0.pnvm"
    assert found["Realtek 802.11n"].status is Status.NONFREE and found["Realtek 802.11n"].reason == "kernel taint P"
    assert found[devices[2][0]].status is Status.FREE


@pytest.mark.skipif(hardware._udev() is None, reason="needs Linux with libudev")
def test_udev_lists_real_devices() -> None:
    devices = hardware._linux_devices()
    assert all(name and driver for name, driver in devices)
    assert hardware._udev_name(type("D", (), {"properties": {}})(), "1414:008E") == "device 1414:008E"


def test_windows_hardware_flags_devices_on_third_party_drivers(
    monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    devices = [
        ("Intel(R) Wi-Fi 6 AX201 160MHz", "Netwtw10"),
        ("USB xHCI Compliant Host Controller", "USBXHCI"),  # Microsoft's inbox driver
        ("WireGuard Tunnel", "wireguard"),
        ("ASIX USB to Gigabit Ethernet", "AX88179A"),
        ("ASIX USB to Gigabit Ethernet", "AX88179A"),  # a second instance
    ]
    drivers = [
        ("Netwtw10", {"CompanyName": "Intel Corporation"}),
        ("WireGuard", {"CompanyName": "WireGuard LLC"}),
        ("AX88179A", {}),
    ]
    monkeypatch.setattr(hardware, "IS_WINDOWS", True)
    monkeypatch.setattr(hardware, "_windows_devices", lambda: iter(devices))
    monkeypatch.setattr(hardware, "_windows_drivers", lambda jobs: iter(drivers))
    found = scan(Hardware(ctx), fetcher)
    assert sorted(found) == ["ASIX USB to Gigabit Ethernet", "Intel(R) Wi-Fi 6 AX201 160MHz", "WireGuard Tunnel"]
    wifi = found["Intel(R) Wi-Fi 6 AX201 160MHz"]
    assert wifi.status is Status.NONFREE and wifi.ring is Ring.KERNEL
    assert wifi.description == "Needs Netwtw10 from Intel Corporation"
    assert found["ASIX USB to Gigabit Ethernet"].description == "Needs AX88179A from an unnamed vendor"
    assert found["WireGuard Tunnel"].status is Status.FREE  # curated in kernel.json


@pytest.mark.skipif(sys.platform != "win32", reason="reads a Windows executable")
def test_file_info_reads_the_version_resource(tmp_path: Path) -> None:
    python = Path(sys.base_prefix) / "python.exe"
    assert kernel._file_info(str(python))["CompanyName"] == "Python Software Foundation"  # type: ignore[index]
    (tmp_path / "notes.txt").write_text("not a PE file")
    assert kernel._file_info(str(tmp_path / "notes.txt")) == {}
    assert kernel._file_info(str(tmp_path / "missing.sys")) is None


def test_wsl_runs_on_hyper_v(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    (tmp_path / "cpuinfo").write_text("flags\t\t: fpu hypervisor\n")
    (tmp_path / "osrelease").write_text("6.18.40.1-microsoft-standard-WSL2\n")
    monkeypatch.setattr(hypervisors, "IS_WINDOWS", False)
    monkeypatch.setattr(hypervisors, "CPUINFO", tmp_path / "cpuinfo")
    monkeypatch.setattr(hypervisors, "DMI", tmp_path / "no-dmi")  # WSL has no DMI
    monkeypatch.setattr(hypervisors, "XEN", tmp_path / "missing")
    monkeypatch.setattr(hypervisors, "OSRELEASE", tmp_path / "osrelease")
    monkeypatch.setattr(hypervisors, "PROC_MODULES", tmp_path / "missing")
    assert list(scan(Hypervisors(ctx), fetcher)) == ["hyper-v"]


def test_vm_microcode_placeholder_is_not_a_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fetcher: StubFetcher, ctx: Context
) -> None:
    (tmp_path / "cpuinfo").write_text("vendor_id\t: GenuineIntel\nmicrocode\t: 0xffffffff\n")
    monkeypatch.setattr(firmware, "IS_WINDOWS", False)
    monkeypatch.setattr(firmware, "CPUINFO", tmp_path / "cpuinfo")
    monkeypatch.setattr(firmware, "DMI", tmp_path / "no-dmi")
    monkeypatch.setattr(firmware, "MEI_FW_VER", tmp_path / "missing")
    assert scan(Firmware(ctx), fetcher)["intel-microcode"].package.version == ""
