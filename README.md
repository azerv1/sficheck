# Absolutely Proprietary

Proprietary software detector. It audits everything installed through your system package manager, your language package managers and your container engine, then prints your Stallman Freedom Index (free / classified).

It runs on GNU/Linux (Arch, Debian, Ubuntu, NixOS and anything with flatpak/snap/brew), Windows and macOS. Python 3.10+, no dependencies.

## Install

```sh
pipx install git+https://github.com/vmavromatis/absolutely-proprietary   # or: uv tool install ...
absolutely-proprietary
```

You can also run it from a clone without installing: `python3 -m absolutely_proprietary` (`py -m absolutely_proprietary` on Windows).

Arch users can use the [AUR package](https://aur.archlinux.org/packages/absolutely-proprietary/) or the `PKGBUILD` in this repo.

## Sources

`absolutely-proprietary --list-sources` shows which of these are available on your machine. Every available source is scanned unless you pass `--sources` or `--skip`.

**System**
- `pacman` — Arch and derivatives, checked against Parabola's [blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/blacklist.txt) and [aur-blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/aur-blacklist.txt) (`--include-privacy` adds `your-privacy-blacklist.txt`). Packages that aren't blacklisted count as free, as before.
- `dpkg` — Debian, Ubuntu, Mint… Archive area decides: `non-free`, `non-free-firmware`, `restricted`, `multiverse` → nonfree; `contrib` → uses-nonfree. Third-party repo packages (Chrome, VS Code, Teams…) come from the curated list.
- `nix` — `nix-env`, `nix profile` and NixOS `systemPackages`, using nixpkgs `meta.license.free`.
- `flatpak` — license from the local appstream catalogue.
- `snap`, `brew` — license from `snap info` / `brew info`; brew casks via the curated list.
- `windows` — programs in the registry's Uninstall keys, plus Windows itself.
- `winget`, `scoop`, `choco` — license from `winget show` (cached), scoop manifests, Chocolatey nuspecs.

**Languages** (global installs, not project dependencies)
- Python: `pip` (default interpreter), `uv` tools, `pipx`
- JavaScript/TypeScript: `npm`, `pnpm`, `yarn`, `bun`, `deno`
- Rust `cargo` · Go `go` · Ruby `gem` · PHP `composer` · Perl `cpan` · Lua `luarocks` · R `r` · Julia `julia` · Haskell `ghc-pkg` · Elixir `mix` · Dart/Flutter `pub` · Swift `mint`
- JVM: `sdkman` (Oracle JDK/GraalVM builds are nonfree), `coursier`, and the opt-in caches `maven`, `gradle`
- .NET: `dotnet` global tools, opt-in `nuget` cache
- C/C++: `vcpkg`, `conan`

**Containers**
- `docker`, `podman` — `org.opencontainers.image.licenses` label plus the curated list (mongo, mssql, hashicorp/*, …).

Opt-in sources only run when named, e.g. `--sources maven,gradle`.

## How a package is classified

Each package goes through a fixed chain, and the first step with an answer wins. Your own `--blacklist` files come first, so you can always overrule the tool. Next comes the ecosystem's own authority, when it has one: Parabola's blacklist for pacman, the archive area for dpkg, `meta.unfree` for nix. Then the bundled curated lists in `absolutely_proprietary/data/lists/`. They come before declared licenses because a license field can be technically true and still misleading. 7-Zip is LGPL but bundles nonfree unRAR code, and VS Code's source is MIT but the Microsoft build is not.

After that the declared license is parsed as an SPDX expression or free text. `MIT OR Proprietary` is free, because you may choose the free branch. `MIT AND Proprietary` is semifree. `BUSL-1.1`, `SSPL`, `Elastic-2.0`, `Freeware` and npm's `UNLICENSED` are nonfree. With `--online-licenses`, packages with no usable license are looked up on deps.dev, Packagist, pub.dev, hex.pm, MetaCPAN or GitHub. Anything still unresolved is `unknown`, except under pacman and dpkg, whose vetted archives default to free.

Unknown packages are left out of the index by default. `--unknown-as-nonfree` counts them against you instead. Sources can overlap (the `windows` registry also lists programs winget installed), so the overall index is a rough figure. The per-source rows are the precise ones.

Statuses:
- *nonfree* — blatantly nonfree software.
- *semifree* — mostly free, but contains some nonfree software.
- *uses-nonfree* — free, but depends on, recommends or integrates with nonfree software or services.
- *unknown* — no license information could be found.

## Options

```
--sources A,B / --skip A,B / --kind system|lang|container    what to scan
--status S (repeatable) / -f, --full / --all / --show-unknown  what to show (default: nonfree)
--sort source|name|status|alternatives  (-s, -a shortcuts)  -r   ordering
--format table|markdown|json|csv  -o FILE                     output
--blacklist PATH|URL (repeatable)  --ignore PKG  --no-bundled list control
--online-licenses  --offline  --refresh  --cache-ttl HOURS    network and cache
--unknown-as-nonfree  --exit-code  --jobs N  --color  -q  -v
```

`--exit-code` makes the command exit 1 when anything proprietary is found, so it can be used in CI. Progress goes to stderr, so `--format json | jq` works.

Defaults for any option can live in `~/.config/absolutely-proprietary/config.json` (`%APPDATA%\absolutely-proprietary\config.json` on Windows), using the option names with underscores:

```json
{ "full": true, "ignore": ["steam"], "blacklist": ["~/my-blacklist.txt"], "skip": ["gradle"] }
```

User blacklists use either Parabola's text format (`name:replacement:ref:id:[status] description`) or the bundled JSON format.

Downloads (Parabola lists, registry lookups, `winget show` output) are cached for 24h in `~/.cache/absolutely-proprietary` (`%LOCALAPPDATA%` on Windows). If the network fails, a stale cache is used.

## Output

```
=============================================
5 ABSOLUTELY PROPRIETARY PACKAGES INSTALLED
=============================================

Your system is infected with 5 proprietary packages out of 1311 found (8 unknown) across 11 sources.
Your Stallman Freedom Index is 99.62

+--------+----------+-------------+---------+---------------+
| Source | Packages | Proprietary | Unknown | Freedom index |
+--------+----------+-------------+---------+---------------+
| dpkg   | 1081     | 5           | 0       | 99.54         |
| pip    | 131      | 0           | 4       | 100.00        |
| gem    | 95       | 0           | 2       | 100.00        |
...
+--------+-------+------------+---------+--------------------+--------------------------------------------+
| Source | Name  | Version    | Status  | Libre alternatives | Description                                |
+--------+-------+------------+---------+--------------------+--------------------------------------------+
| dpkg   | nikto | 1:2.1.5-3  | nonfree |                    | in Debian's non-free archive area          |
+--------+-------+------------+---------+--------------------+--------------------------------------------+
```

## Contributing to the lists

Curated entries live in `absolutely_proprietary/data/lists/*.json`, one object per entry:

```json
{"name": "zoom", "status": "nonfree", "alternatives": ["jitsi-meet-desktop"], "description": "Proprietary video conferencing"}
```

Add `"pattern"` (a case-insensitive regex) instead of an exact name for fuzzy matches, such as Windows display names. In pattern lists the first match in file order wins.

**Lists**
- `common.json` — cross-platform apps by package name (pacman/deb/flatpak/snap/brew/winget ids)
- `debian.json` — third-party `.deb` packages
- `windows.json` — registry DisplayName regexes
- `windows-packages.json` — winget/scoop/choco id regexes
- `lang.json` — language packages with missing or misleading metadata
- `containers.json` — image repository regexes

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
pytest && ruff check . && ruff format --check . && mypy absolutely_proprietary tests
```
