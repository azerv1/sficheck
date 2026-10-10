from __future__ import annotations

import json
from pathlib import Path

import pytest

from absolutely_proprietary.classify import Classifier
from absolutely_proprietary.models import Finding, Status
from absolutely_proprietary.sources import ALL_SOURCES, BY_NAME
from absolutely_proprietary.sources.base import Context, Source
from absolutely_proprietary.sources.compiled import Cargo, Go
from absolutely_proprietary.sources.containers import Docker
from absolutely_proprietary.sources.javascript import Npm
from absolutely_proprietary.sources.jvm import Maven, Sdkman
from absolutely_proprietary.sources.python import Pip
from absolutely_proprietary.sources.scripting import CranR, Gem, GhcPkg
from absolutely_proprietary.sources.system import Brew, Dpkg, Nix, Pacman, Snap
from absolutely_proprietary.sources.windows import Chocolatey, Scoop
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


def test_docker_labels_and_curated(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    images = [
        {"Repository": "mongo", "Tag": "7", "ID": "aaa111"},
        {"Repository": "ghcr.io/acme/tool", "Tag": "1", "ID": "bbb222"},
        {"Repository": "<none>", "Tag": "<none>", "ID": "ccc333"},
    ]
    inspect = [
        {"Id": "sha256:aaa111ffff", "Config": {"Labels": None}},
        {"Id": "sha256:bbb222ffff", "Config": {"Labels": {"org.opencontainers.image.licenses": "Apache-2.0"}}},
    ]
    fake_run({"docker image ls": "\n".join(json.dumps(i) for i in images), "docker image inspect": json.dumps(inspect)})
    found = scan(Docker(ctx), fetcher)
    assert found["mongo"].status is Status.NONFREE
    assert found["ghcr.io/acme/tool"].status is Status.FREE
    assert "<none>" not in found


def test_docker_daemon_down_raises(fake_run: FakeRun, ctx: Context) -> None:
    fake_run({"docker image ls": None})
    with pytest.raises(RuntimeError, match="daemon"):
        list(Docker(ctx).packages())


def test_ignore_user_list_and_online(fake_run: FakeRun, fetcher: StubFetcher, ctx: Context) -> None:
    fake_run(
        {
            "ruby": json.dumps(
                [{"name": "a", "version": "1", "licenses": []}, {"name": "b", "version": "1", "licenses": []}]
            )
        }
    )
    fetcher.bodies["RUBYGEMS/packages/a/versions/1"] = json.dumps({"licenses": ["MIT"]})
    from absolutely_proprietary.blacklist import Blacklist
    from absolutely_proprietary.models import Entry

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
