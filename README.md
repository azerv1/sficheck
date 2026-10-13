# sficheck

Check your Stallman Freedom Index (SFI).

sficheck is a proprietary software detector. It audits everything installed through your system package manager and your language package managers, then prints your Stallman Freedom Index (free / classified).

It runs on GNU/Linux (Arch, Debian, Ubuntu, Fedora, RHEL, openSUSE, NixOS and anything with flatpak/snap/brew), Windows and macOS. Python 3.11+. Dependencies: [msgspec](https://jcristharif.com/msgspec/) (list files), [license-expression](https://github.com/aboutcode-org/license-expression) (licenses), [httpx2](https://pypi.org/project/httpx2/) (online lookups), and on Linux [pyudev](https://pyudev.readthedocs.io/) (devices, needs libudev).

## Install

```sh
pipx install git+https://github.com/azerv1/sficheck   # or: uv tool install git+https://github.com/azerv1/sficheck
sficheck
```

You can also run it from a clone without installing: `python3 -m sficheck` (`py -m sficheck` on Windows).

Arch users can build the `PKGBUILD` in this repo with `makepkg -si`.

sficheck started as a fork of absolutely-proprietary. See [Origins](#origins) below.

## Sources

`sficheck --list-sources` shows which of these are available on your machine. By default every layer is scanned: the package managers (`--software`) and the kernel, hypervisor, firmware and hardware layers below them. Name one or more layers to scan only those, so `sficheck --firmware` checks just the firmware and `sficheck --software --kernel` skips the rest. `--kind system|lang` narrows the package managers, `--sources` names exact sources, and `--skip` drops sources from any selection.

**System** (`--software`)
- `pacman` — Arch and derivatives, checked against Parabola's [blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/blacklist.txt) and [aur-blacklist](https://git.parabola.nu/abslibre/blacklist.git/plain/aur-blacklist.txt) (`--include-privacy` adds `your-privacy-blacklist.txt`). Packages that aren't blacklisted count as free, as before.
- `dpkg` — Debian, Ubuntu, Mint… Archive area decides: `non-free`, `non-free-firmware`, `restricted`, `multiverse` → nonfree; `contrib` → uses-nonfree. Third-party repo packages (Chrome, VS Code, Teams…) come from the curated list.
- `rpm` — Fedora, RHEL, openSUSE, Mageia… License tag from the rpm database (SPDX on current Fedora, older Callaway names like `GPLv2+` and `ASL 2.0` too). Firmware tagged `LicenseRef-Fedora-Firmware` or `Redistributable, no modification permitted` is nonfree.
- `nix` — `nix-env`, `nix profile` and NixOS `systemPackages`, using nixpkgs `meta.license.free`.
- `flatpak` — license from the local appstream catalogue.
- `snap`, `brew` — license from `snap info` / `brew info`; brew casks via the curated list.
- `windows` — programs in the registry's Uninstall keys, plus Windows itself.
- `winget`, `scoop`, `choco` — license from `winget show` (cached), scoop manifests, Chocolatey nuspecs.

**Below userspace**
- `kernel` (`--kernel`) — what runs in ring 0.
  - Linux: loaded modules from `/proc/modules`. A module the kernel taints with `P` (license not GPL-compatible) is nonfree, the rest free.
  - Windows: third-party kernel drivers from the registry's service keys, counting only those in use: bound to a device, loaded at system or auto start, or installed outside `C:\Windows`. Microsoft's own drivers are skipped (Windows itself is already reported), as are leftover entries whose file is gone. Vendor and version come from the driver file. A driver not in `kernel.json` counts as nonfree, since free drivers are listed there.
- `hypervisors` (`--hypervisors`) — what runs in ring -1.
  - The hypervisor this OS runs on. Linux reads the CPU's `hypervisor` flag, `/sys/hypervisor/type`, the DMI vendor and the kernel release (WSL 2). Windows asks the kernel whether a hypervisor is present and reads the machine's manufacturer: a VM vendor names the host, and on real hardware it is Hyper-V, which Windows runs on whenever virtualization-based security, WSL 2 or Hyper-V is on.
  - Hypervisors installed here, found by their kernel driver or module: VMware (`vmx86`, `vmmon`), VirtualBox (`VBoxSup`, `vboxdrv`) and KVM (`kvm`).
- `firmware` (`--firmware`) — what runs in rings -2 and -3. Read from DMI, `/proc/cpuinfo` and `/sys/class/mei` on Linux, and the registry's hardware description on Windows, without admin.
  - The BIOS/UEFI vendor and version (ring -2). A vendor not in `firmware.json` (AMI, Insyde, Phoenix, OEMs) is nonfree. coreboot is uses-nonfree, since most boards still run Intel FSP/ME or AMD AGESA blobs. Libreboot and Canoeboot also report themselves as coreboot, so mark yours free with a `--blacklist` entry named `coreboot`.
  - From the CPU vendor: the Intel ME or AMD PSP, and the CPU microcode with its revision (ring -3). The ME's firmware version comes from `/sys/class/mei` on Linux. The scan can't tell whether me_cleaner or the HAP bit disabled the ME.
- `hardware` (`--hardware`) — devices that only work with nonfree software, reported at ring 0 because their driver runs in the kernel (and a device's firmware can usually reach memory through DMA).
  - Linux: PCI devices and USB interfaces from udev (via pyudev, so libudev is needed), named from udev's hardware database like `lspci` and `lsusb` do. A device is nonfree when its driver taints the kernel with `P`, and uses-nonfree when its free driver loads firmware blobs installed in `/lib/firmware` (from `modinfo -F firmware`). A few linux-firmware blobs are free, so treat the blob count as an upper bound.
  - Windows: PCI, USB and HD Audio devices plugged in now, from the registry. A device on a third-party driver is nonfree; devices on Microsoft's own drivers are covered by Windows itself.
  - A driver named in the curated lists decides for its device: nvidia's devices get nouveau as the alternative, and a WireGuard adapter stays free.

**Browser** (`--browser`, only when asked for; never part of the default scan)
- `browser` — extensions you installed in Firefox and Chromium-based browsers (Chrome, Chromium, Brave, Edge, Vivaldi), and the Widevine DRM module those browsers download to play protected video. Widevine is nonfree and tagged `drm`.
- It reads only these local files, and never history, cookies or passwords:
  - Firefox: `extensions.json` and the `gmp-widevinecdm` folder in each profile, under `~/.mozilla/firefox` (plus its flatpak and snap locations), `~/Library/Application Support/Firefox/Profiles` or `%APPDATA%\Mozilla\Firefox\Profiles`.
  - Chromium-based: each extension's `manifest.json` (and its `_locales` folder for the display name) under `<profile>/Extensions`, and the `WidevineCdm` folder, under `~/.config/<browser>`, `~/Library/Application Support/<vendor>/<browser>` or `%LOCALAPPDATA%\<vendor>\<browser>\User Data`.
- Firefox's built-in add-ons, themes, dictionaries and language packs are skipped.
- With `--online-licenses`, Firefox extensions are looked up on addons.mozilla.org, which publishes the license each developer declares. A custom license stays unknown. Chrome Web Store doesn't publish licenses, so Chromium extensions rely on the curated `browser.json` and are otherwise unknown.

**Android phone** (`--android`, only when asked for; scored separately)
- `android` — the apps on an Android phone connected with [adb](https://developer.android.com/tools/adb) (from Google's platform-tools). The phone gets its own Freedom Index, so it never changes your machine's.
- Setup, once: on the phone, turn on Developer options and then USB debugging, connect the cable, and allow the computer when the phone asks. On Android 11 and later, wireless debugging with `adb pair` works too. No root is needed and nothing is installed on the phone.
- sficheck runs `adb devices` and then `adb shell pm list packages -f -i --show-versioncode`, which lists each app's id, version code and the app that installed it. With several devices connected, set `ANDROID_SERIAL` to pick one, as with any adb command.
- Apps on [F-Droid](https://f-droid.org/), which only ships free software, are free and carry F-Droid's anti-features. Apps tagged `nonfree-net`, `nonfree-dep`, `nonfree-add` or `tethered-net` are uses-nonfree, and `nonfree-assets` makes them semifree. The reference is the app's F-Droid page. An app installed from Google Play keeps the F-Droid verdict for its app id, with a note that Play's build can differ.
- F-Droid's index is about 65 MB. It's downloaded once a day at most (`--cache-ttl`), and only a 200 KB summary is read on later runs.
- Other apps are checked against the curated `android.json` (Google Play Services, the Play Store and other Google apps), and are unknown otherwise. microG reuses Google Play Services' app id, so microG users should mark `com.google.android.gms` free with a `--blacklist` entry.

**Languages** (`--software`; global installs, not project dependencies)
- Python: `pip` (default interpreter), `uv` tools, `pipx`
- JavaScript/TypeScript: `npm`, `pnpm`, `yarn`, `bun`, `deno`
- Rust `cargo` · Go `go` · Ruby `gem` · PHP `composer` · Perl `cpan` · Lua `luarocks` · R `r` · Julia `julia` · Haskell `ghc-pkg` · Elixir `mix` · Dart/Flutter `pub` · Swift `mint`
- JVM: `sdkman` (Oracle JDK/GraalVM builds are nonfree), `coursier`, and the opt-in caches `maven`, `gradle`
- .NET: `dotnet` global tools, opt-in `nuget` cache
- C/C++: `vcpkg`, `conan`

Opt-in sources only run when named, e.g. `--sources maven,gradle`.

## How a package is classified

Each package goes through a fixed chain, and the first step with an answer wins. Your own `--blacklist` files come first, so you can always overrule the tool. Next comes the ecosystem's own authority, when it has one: Parabola's blacklist for pacman, the archive area for dpkg, `meta.unfree` for nix. Then the bundled curated lists in `sficheck/data/lists/`. They come before declared licenses because a license field can be technically true and still misleading. 7-Zip is LGPL but bundles nonfree unRAR code, and VS Code's source is MIT but the Microsoft build is not.

After that the declared license is parsed as an SPDX expression or free text. `MIT OR Proprietary` is free, because you may choose the free branch. `MIT AND Proprietary` is semifree. `BUSL-1.1`, `SSPL`, `Elastic-2.0`, `Freeware` and npm's `UNLICENSED` are nonfree. SPDX ids count as free when [ScanCode's license database](https://scancode-licensedb.aboutcode.org/) files them as permissive, copyleft or public domain. With `--online-licenses`, packages with no usable license are looked up on deps.dev, Packagist, pub.dev, hex.pm, MetaCPAN, GitHub or addons.mozilla.org. Anything still unresolved is `unknown`, except under pacman and dpkg, whose vetted archives default to free.

Unknown packages are left out of the index by default. `--unknown-as-nonfree` counts them against you instead. Sources can overlap (the `windows` registry also lists programs winget installed), so the overall index is a rough figure. The per-source rows are the precise ones.

Statuses:
- *nonfree* — blatantly nonfree software.
- *semifree* — mostly free, but contains some nonfree software.
- *uses-nonfree* — free, but depends on, recommends or integrates with nonfree software or services.
- *unknown* — no license information could be found.

### How deep it reaches: protection rings

Proprietary findings also carry the CPU protection ring the software runs in. A proprietary calendar can only see what you give it. A kernel anticheat sees everything the OS does, and the Intel ME keeps running while the machine is off.

| Ring | Runs as | Examples |
|---|---|---|
| -3 ME | a coprocessor (ME = Management Engine) or the CPU itself, below the OS | Intel ME, AMD PSP, CPU microcode |
| -2 firmware | system firmware | BIOS/UEFI |
| -1 hypervisor | underneath every OS on the machine | Hyper-V, VMware, Parallels, the VirtualBox Extension Pack |
| 0 kernel | the kernel | Riot Vanguard, Easy Anti-Cheat, BattlEye, FACEIT AC, nvidia, Windows itself |
| 3 user | an ordinary program | everything else |

Rings 1 and 2 exist on x86 but mainstream OSes leave them unused. A curated entry names its ring; anything else proprietary is assumed to be userspace. `--sort ring` lists the deepest first, and `--max-ring 0` shows only the kernel and below.

## Options

```
(no layer flag)                                               scan every layer
--software                                                    scan the system and language package managers
--kernel                                                      scan kernel modules and drivers
--hypervisors                                                 scan the hypervisor underneath and installed ones
--firmware                                                    scan the BIOS/UEFI, Intel ME / AMD PSP and microcode
--hardware                                                    scan devices that need a nonfree driver or firmware blobs
--browser                                                     scan browser extensions and DRM modules (only when asked)
--android                                                     scan a phone's apps over adb (only when asked; own index)
--kind system|lang / --sources A,B / --skip A,B              narrow or name sources
--status S (repeatable) / -f, --full / --all / --show-unknown  what to show (default: nonfree)
--sort source|name|status|ring|alternatives  (-s, -a shortcuts)  -r   ordering
--max-ring N                                                  only ring N or deeper (-3 … 3)
--in-use                                                      only what is in use right now (see below)
--format table|markdown|json|csv  -o FILE                     output
--blacklist PATH|URL (repeatable)  --ignore PKG  --no-bundled list control
--online-licenses  --offline  --refresh  --cache-ttl HOURS    network and cache
--unknown-as-nonfree  --exit-code  --jobs N  --color  -q  -v
--install-hook pacman|apt|dnf  --remove-hook pacman|apt|dnf  warn at install time (Linux, root)
```

`--exit-code` makes the command exit 1 when anything proprietary is found, so it can be used in CI. Progress goes to stderr, so `--format json | jq` works.

`--in-use` keeps only what is in use right now, and the Freedom Index then covers only that. A nonfree program you installed years ago and never open drops out; a nonfree service running all the time stays.
- Running programs come from the process list ([psutil](https://github.com/giampaolo/psutil)). Each program's path is matched to the package that installed it: `pacman -Qqo`, `dpkg -S` or `rpm -qf` on Linux, `/snap/<name>/` for snaps, `flatpak ps` for flatpaks, Homebrew's `Cellar/<name>/`, and on Windows the install folder the registry records for each program (or scoop's `apps/<name>/`).
- Kernel drivers, firmware and devices are always in use, since those scans already report only what is loaded or present. A hypervisor counts only when this OS runs on it.
- Not counted: services that are enabled but stopped, autostart entries, and sources that can't map a running program to a package (the language package managers, winget, Chocolatey, nix and the browser). Windows programs that record no install folder are left out too.

### Warnings at install time

`sudo sficheck --install-hook pacman` (or `apt`, or `dnf`) adds a hook that warns before the package manager installs something proprietary:

```
sficheck: unrar is nonfree (proprietary license); free alternatives: unar
```

The hook only warns: it always lets the install go ahead, even if sficheck itself fails. It checks new installs only, never upgrades, using the same rules as a scan: your `--blacklist` lists, then Parabola's blacklist for pacman, the archive area for apt, or the License tag for dnf, then the curated lists. `sudo sficheck --remove-hook pacman` removes it again.

| Package manager | File written | How it's called |
|---|---|---|
| pacman | `/etc/pacman.d/hooks/sficheck.hook` | a `PreTransaction` hook for `Operation = Install`, given the package names |
| apt | `/etc/apt/apt.conf.d/50sficheck` | `DPkg::Pre-Install-Pkgs` with protocol version 2, which tells new installs from upgrades; each `.deb`'s section is read with `dpkg-deb` |
| dnf5 | `/etc/dnf/libdnf5-plugins/actions.d/sficheck.actions` | a `pre_transaction` action, run per new package with its name and License tag; needs `libdnf5-plugin-actions` |

The hook runs sficheck by the absolute path it was installed from, so reinstall the hook if you move sficheck.

Defaults for any option can live in `~/.config/sficheck/config.json` (`%APPDATA%\sficheck\config.json` on Windows), using the option names with underscores:

```json
{ "full": true, "ignore": ["steam"], "blacklist": ["~/my-blacklist.txt"], "skip": ["gradle"] }
```

User blacklists use either Parabola's text format (`name:replacement:ref:id:[status] description`) or the bundled JSON format.

Downloads (Parabola lists, registry lookups, `winget show` output) are cached for 24h in `~/.cache/sficheck` (`%LOCALAPPDATA%` on Windows). If the network fails, a stale cache is used.

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

`--format json` is meant for scripts and CI. Its shape is described by [`docs/output.schema.json`](docs/output.schema.json) (JSON Schema 2020-12), and every report starts with `"schema_version"`. New fields can appear at any time, so ignore keys you don't know. Removing, renaming or retyping a field bumps `schema_version`.

## Contributing to the lists

Curated entries live in `sficheck/data/lists/*.json`, one object per entry:

```json
{"name": "zoom", "status": "nonfree", "alternatives": ["jitsi-meet-desktop"], "description": "Proprietary video conferencing", "reference": "https://en.wikipedia.org/wiki/Zoom_(software)"}
```

Each list declares `"$schema": "../../../docs/lists.schema.json"`, so VS Code and other editors that support JSON Schema autocomplete fields and flag mistakes as you type, such as an unknown key or a non-free entry without a `reference`.

Add `"ring"` (-3, -2, -1, 0 or 3) when the software runs below userspace, such as a kernel driver or a hypervisor.

Add `"antifeatures"` to say why an entry matters beyond its license. They're [F-Droid's anti-features](https://f-droid.org/docs/Anti-Features/) plus `drm`: `ads`, `tracking`, `nonfree-net`, `nonfree-add`, `nonfree-dep`, `nonfree-assets`, `upstream-nonfree`, `tethered-net`, `known-vuln`, `disabled-algorithm`, `no-source-since` and `drm`. They show up in every output format but never change the status or the Freedom Index. Free software can have them too, such as a free app that phones home. Like a status, each tag needs a `reference` that states it. Entries from Parabola's privacy list (`--include-privacy`) are tagged `nonfree-net`, since nearly all of them exist to support a nonfree network service such as Google, Facebook or Twitter.

Add `"pattern"` (a case-insensitive regex) instead of an exact name for fuzzy matches, such as Windows display names. In pattern lists the first match in file order wins.

Every entry that isn't `free` must have a `reference`: a page that states the license. In order of preference, that's Parabola's blacklist or issue tracker, the Debian package tracker, the project's own license or terms page, a registry license field (npm, PyPI), or the Wikipedia infobox / Wikidata license. The tests fail without one, and the reference is shown in JSON, CSV and markdown output. If a claim can't be sourced, leave the entry out. An unknown result is better than an unsourced one.

Alternatives must be free software, a real replacement for the same job, and a valid package name or id in that list's ecosystem. Free-text hints go in parentheses. `python scripts/check_lists.py` checks references offline. `--online` also checks that each reference resolves and looks each alternative up on Repology, Flathub or winget-pkgs. Repology misses are only warnings, because Repology uses its own project names.

**Lists**
- `common.json` — cross-platform apps by package name (pacman/deb/flatpak/snap/brew/winget ids)
- `debian.json` — third-party `.deb` packages
- `windows.json` — registry DisplayName regexes
- `windows-packages.json` — winget/scoop/choco id regexes
- `lang.json` — language packages with missing or misleading metadata
- `kernel.json` — kernel drivers and modules by service or module name: anticheats, and the free drivers
- `hypervisors.json` — hypervisors by short name (`hyper-v`, `vmware`, `kvm`…)
- `firmware.json` — BIOS/UEFI vendors, and the ME, PSP and microcode

## Development

With [uv](https://docs.astral.sh/uv/) and make:

```sh
make sync      # dev environment from uv.lock
make format    # sort imports, reformat
make lint      # ruff, mypy, complexipy, vulture, deptry
make test      # pytest, including Hypothesis property tests
make audit     # pip-audit the locked dependencies
make install   # install the command for your user (uv tool install)
make clean     # caches and build output
uv run tox -p  # the tests on every supported Python
uv run python scripts/check_lists.py --online   # after editing the lists
```

## Origins

sficheck is a fork of [absolutely-proprietary](https://github.com/vmavromatis/absolutely-proprietary) by Vasilis Mavromatis and contributors. The original was a single script for Arch-based distros: it checked pacman packages against Parabola's blacklists and printed your Stallman Freedom Index. It was renamed and heavily extended in 2026, adding:

- system package managers beyond pacman (dpkg, rpm, nix, flatpak, snap, brew, winget, scoop, choco, the Windows registry) and 28 language package managers
- the kernel, hypervisor, firmware and hardware scans (rings 0 to -3), each selectable on its own
- Windows and macOS support
- the classification chain: user blacklists, ecosystem authorities, curated lists, SPDX parsing and online license lookups
- JSON output, a config file, caching, and a test suite with Hypothesis property tests

The full history, including every upstream commit, is kept in this repository. Thanks to everyone who contributed to absolutely-proprietary.

## License

GPL-3.0-or-later, the same as upstream. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
