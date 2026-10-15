# sficheck

sficheck (SFI-check) finds proprietary software at every level, kernel drivers, the hypervisor, the BIOS/UEFI and devices that need nonfree drivers or firmware.

## Origins

sficheck is a fork of [absolutely-proprietary](https://github.com/vmavromatis/absolutely-proprietary) by Vasilis Mavromatis and contributors. The original was a single script for Arch-based distros: it checked pacman packages against Parabola's blacklists and printed your Stallman Freedom Index. This fork adds:

- system package managers beyond pacman (dpkg, rpm, nix, flatpak, snap, brew) and 28 language package managers
- the kernel, hypervisor, firmware and hardware scans (rings 0 to -3), each selectable on its own
- opt-in browser and Android scans, anti-feature tags, and `--in-use`
- install-time warnings for pacman, apt and dnf
- the classification chain: user blacklists, ecosystem authorities, curated lists, SPDX parsing and online license lookups
- JSON output, a config file, caching, and a test suite with Hypothesis property tests

## Install

```sh
uv tool install sficheck   # or: pipx install sficheck
sficheck
```

Python 3.11 or newer. Dependencies: [msgspec](https://jcristharif.com/msgspec/) (list files), [license-expression](https://github.com/aboutcode-org/license-expression) (licenses), [httpx2](https://pypi.org/project/httpx2/) (online lookups), [psutil](https://github.com/giampaolo/psutil) (`--in-use`), and on Linux [pyudev](https://pyudev.readthedocs.io/) (devices; needs libudev).

- **From a clone**, `python -m sficheck`.
- **On Arch**, build the `PKGBUILD` in this repo with `makepkg -si`.

## Usage

```sh
sficheck                          # scan every layer, list what's nonfree
sficheck --full                   # also list semifree and uses-nonfree findings
sficheck --firmware               # scan one layer only
sficheck --in-use                 # only what is running right now
sficheck --sort ring              # deepest findings first
sficheck --browser                # add browser extensions and DRM (opt-in)
sficheck --android                # rate a phone connected over adb (opt-in)
sficheck --format json | jq       # machine-readable report
sficheck --list-sources           # what sficheck can scan on this machine
```

## Output

```
=============================================
5 ABSOLUTELY PROPRIETARY PACKAGES INSTALLED
=============================================

Your system is infected with 5 proprietary packages out of 1311 found (8 unknown) across 11 sources.
Your Stallman Freedom Index is 99.62
By protection ring: 3 user: 5

+--------+----------+-------------+---------+---------------+
| Source | Packages | Proprietary | Unknown | Freedom index |
+--------+----------+-------------+---------+---------------+
| dpkg   | 1081     | 5           | 0       | 99.54         |
| pip    | 131      | 0           | 4       | 100.00        |
| gem    | 95       | 0           | 2       | 100.00        |
...
+--------+-------+------------+---------+--------+--------------------+--------------------------------------------+
| Source | Name  | Version    | Status  | Ring   | Libre alternatives | Description                                |
+--------+-------+------------+---------+--------+--------------------+--------------------------------------------+
| dpkg   | nikto | 1:2.1.5-3  | nonfree | 3 user |                    | in Debian's non-free archive area          |
+--------+-------+------------+---------+--------+--------------------+--------------------------------------------+
```

Other formats: `--format markdown`, `csv` or `json`, and `-o FILE` writes to a file.

### System & Language package managers (`--software`)

- **`pacman`** — Arch and derivatives, checked against Parabola's [blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/blacklist.txt) and [aur-blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/aur-blacklist.txt). `--include-privacy` adds `your-privacy-blacklist.txt`. Packages that aren't blacklisted count as free.
- **`dpkg`** — Debian, Ubuntu, Mint… The archive area decides: `non-free`, `non-free-firmware`, `restricted` and `multiverse` are nonfree, `contrib` is uses-nonfree. Third-party packages (Chrome, VS Code, Teams…) come from the curated list.
- **`rpm`** — Fedora, RHEL, openSUSE, Mageia… The License tag from the rpm database, as SPDX on current Fedora or as older Callaway names like `GPLv2+` and `ASL 2.0`. Firmware tagged `LicenseRef-Fedora-Firmware` or `Redistributable, no modification permitted` is nonfree.
- **`nix`** — `nix-env`, `nix profile` and NixOS `systemPackages`, using nixpkgs `meta.license.free`.
- **`Python`** — `pip` (default interpreter), `uv` tools, `pipx`
- **`JavaScript/TypeScript`** — `npm`, `pnpm`, `yarn`, `bun`, `deno`
- **`JVM`** — `sdkman` (Oracle JDK and GraalVM builds are nonfree), `coursier`, and the opt-in caches `maven` and `gradle`
- **.`NET`** — `dotnet` global tools, and the opt-in `nuget` cache
- **`C/C`++** — `vcpkg`, `conan`
- **`Others`** — Rust `cargo` · Go `go` · Ruby `gem` · PHP `composer` · Perl `cpan` · Lua `luarocks` · R `r` · Julia `julia` · Haskell `ghc-pkg` · Elixir `mix` · Dart/Flutter `pub` · Swift `mint`

Opt-in sources only run when named, e.g. `--sources maven,gradle`.

### Browser (`--browser`, opt-in)

- **`browser`** — extensions you installed in Firefox and Chromium-based browsers (Chrome, Chromium, Brave, Edge, Vivaldi), and the Widevine DRM module those browsers download to play protected video. Widevine is nonfree and tagged `drm`.
- It reads only these local files, never history, cookies or passwords:
  - Firefox: `extensions.json` and the `gmp-widevinecdm` folder in each profile, under `~/.mozilla/firefox` (plus its flatpak and snap locations).
  - Chromium-based: each extension's `manifest.json` (and its `_locales` folder for the display name) under `<profile>/Extensions`, and the `WidevineCdm` folder, under `~/.config/<browser>`.
- Firefox's built-in add-ons, themes, dictionaries and language packs are skipped.
- With `--online-licenses`, Firefox extensions are looked up on addons.mozilla.org, which publishes the license each developer declares; a custom license stays unknown. Chrome Web Store doesn't publish licenses, so Chromium extensions rely on the curated `browser.json` and are unknown otherwise.

## How a package is classified

- **nonfree** — blatantly nonfree software.
- **semifree** — mostly free, but contains some nonfree software.
- **uses-nonfree** — free, but depends on, recommends or integrates with nonfree software or services.
- **free** — free software.
- **unknown** — no license information could be found.

### Protection rings

Proprietary findings also carry the CPU protection ring the software runs in. A proprietary calendar can only see what you give it. A kernel anticheat sees everything the OS does, and the Intel ME keeps running while the machine is off.

| Ring          | Runs as                                                                | Examples                                                                    |
| ------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| -3 ME         | a coprocessor (ME = Management Engine) or the CPU itself, below the OS | Intel ME, AMD PSP, CPU microcode                                            |
| -2 firmware   | system firmware                                                        | BIOS/UEFI                                                                   |
| -1 hypervisor | underneath every OS on the machine                                     | Hyper-V, VMware, Parallels, the VirtualBox Extension Pack                   |
| 0 kernel      | the kernel                                                             | Riot Vanguard, Easy Anti-Cheat, BattlEye, FACEIT AC, nvidia                 |
| 3 user        | an ordinary program                                                    | everything else                                                             |

## Only what runs now: `--in-use`

`--in-use` keeps only what is in use right now

- Running programs come from the process list (psutil).
- Kernel drivers, firmware and devices always count as in use.

## Warnings at install time

`sudo sficheck --install-hook pacman` (or `apt`, or `dnf`) adds a hook that warns before the package manager installs something proprietary:

```
sficheck: unrar is nonfree (proprietary license); free alternatives: unar
```

The hook only warns. It never blocks an install, even when sficheck itself is broken or has been uninstalled. It checks new installs only, never upgrades,

The package manager runs the hook as root, so sficheck must be installed where only root can change it: your distro's package, the `PKGBUILD`, or `sudo pipx install --global`. `--install-hook` refuses a copy under your home directory, since anyone who could edit it could then run code as root. The hook runs sficheck by the absolute path it was installed from, so reinstall the hook if you move sficheck.

| Package manager | File written                                          | How it's called                                                                                                                         |
| --------------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| pacman          | `/etc/pacman.d/hooks/sficheck.hook`                   | a `PreTransaction` hook for `Operation = Install`, given the package names                                                              |
| apt             | `/etc/apt/apt.conf.d/50sficheck`                      | `DPkg::Pre-Install-Pkgs` with protocol version 2, which tells new installs from upgrades; each `.deb`'s section is read with `dpkg-deb` |
| dnf5            | `/etc/dnf/libdnf5-plugins/actions.d/sficheck.actions` | a `pre_transaction` action, run per new package with its name and License tag; needs `libdnf5-plugin-actions`                           |

## Options

```
what to scan (every layer except the opt-in ones by default)
  --software                 system and language package managers (ring 3)
  --kernel                   kernel modules and third-party drivers (ring 0)
  --hypervisors              the hypervisor this OS runs on, and installed ones (ring -1)
  --firmware                 BIOS/UEFI (ring -2), Intel ME / AMD PSP and microcode (ring -3)
  --hardware                 devices that need a nonfree driver or firmware blobs
  --browser                  browser extensions and DRM modules (opt-in)
  --android                  a phone's apps over adb (opt-in; scored separately)
  --kind system|lang         package managers of this kind only (repeatable)
  --sources A,B / --skip A,B name sources / skip sources
  --list-sources             show every source and whether it's available, then exit

what to show
  --status S                 nonfree|semifree|uses-nonfree|free|unknown|all (repeatable; default: nonfree)
  -f, --full                 nonfree, semifree and uses-nonfree
  --all                      every package, free ones too
  --show-unknown             also packages that couldn't be classified
  --unknown-as-nonfree       count unknown packages against the index
  --in-use                   only what is in use now
  --max-ring N               only ring N or deeper (-3 … 3)
  --sort source|name|status|ring|alternatives   -s (status)  -a (alternatives)  -r (reverse)

output
  --format table|markdown|json|csv   -o, --output FILE   --color auto|always|never
  -q, --quiet   -v, --verbose   --exit-code (exit 1 if anything proprietary is found)

lists and lookups
  --blacklist PATH|https-URL (repeatable)   --ignore PKG (repeatable)   --no-bundled   --include-privacy
  --online-licenses   --offline   --refresh   --cache-ttl HOURS (default 24)   --jobs N (default 8)

install-time hooks (Linux, root)
  --install-hook pacman|apt|dnf   --remove-hook pacman|apt|dnf
```

## Configuration and cache

Defaults for any option can live in `~/.config/sficheck/config.json`

```json
{
  "full": true,
  "ignore": ["steam"],
  "blacklist": ["~/my-blacklist.txt"],
  "skip": ["gradle"]
}
```

User blacklists use either Parabola's text format (`name:replacement:ref:id:[status] description`) or the bundled JSON format. They're read from a local path or an `https://` URL.

Downloads (Parabola lists, registry lookups) are cached for 24 hours in `~/.cache/sficheck`. If the network fails, a stale cache is used. `--offline` never touches the network.

## Development

With [uv](https://docs.astral.sh/uv/) and make:

```sh
make sync      # dev environment from uv.lock
make format    # sort imports, reformat
make lint      # ruff, mypy, complexipy, vulture, deptry, zizmor
make test      # pytest, including Hypothesis property tests
make audit     # pip-audit the locked dependencies
make install   # install the command for your user (uv tool install)
make schema    # regenerate the JSON Schemas in docs/
make clean     # caches and build output
uv run tox -p  # the tests on every supported Python
uv run python scripts/check_lists.py --online   # after editing the lists
```

## License

GPL-3.0-or-later, the same as upstream. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
