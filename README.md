# Absolutely Proprietary

Proprietary software detector. It audits everything installed through your system package manager and your language package managers, then prints your Stallman Freedom Index (free / classified).

It runs on GNU/Linux (Arch, Debian, Ubuntu, NixOS and anything with flatpak/snap/brew), Windows and macOS. Python 3.11+. Dependencies: [msgspec](https://jcristharif.com/msgspec/) (list files), [license-expression](https://github.com/aboutcode-org/license-expression) and [spdx-license-list](https://pypi.org/project/spdx-license-list/) (licenses), [httpx2](https://pypi.org/project/httpx2/) (online lookups), and on Linux [pyudev](https://pyudev.readthedocs.io/) (devices, needs libudev).

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

**Below userspace** (opt-in)
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

**Languages** (global installs, not project dependencies)
- Python: `pip` (default interpreter), `uv` tools, `pipx`
- JavaScript/TypeScript: `npm`, `pnpm`, `yarn`, `bun`, `deno`
- Rust `cargo` · Go `go` · Ruby `gem` · PHP `composer` · Perl `cpan` · Lua `luarocks` · R `r` · Julia `julia` · Haskell `ghc-pkg` · Elixir `mix` · Dart/Flutter `pub` · Swift `mint`
- JVM: `sdkman` (Oracle JDK/GraalVM builds are nonfree), `coursier`, and the opt-in caches `maven`, `gradle`
- .NET: `dotnet` global tools, opt-in `nuget` cache
- C/C++: `vcpkg`, `conan`

Opt-in sources only run when named, e.g. `--sources maven,gradle`.

## How a package is classified

Each package goes through a fixed chain, and the first step with an answer wins. Your own `--blacklist` files come first, so you can always overrule the tool. Next comes the ecosystem's own authority, when it has one: Parabola's blacklist for pacman, the archive area for dpkg, `meta.unfree` for nix. Then the bundled curated lists in `absolutely_proprietary/data/lists/`. They come before declared licenses because a license field can be technically true and still misleading. 7-Zip is LGPL but bundles nonfree unRAR code, and VS Code's source is MIT but the Microsoft build is not.

After that the declared license is parsed as an SPDX expression or free text. `MIT OR Proprietary` is free, because you may choose the free branch. `MIT AND Proprietary` is semifree. `BUSL-1.1`, `SSPL`, `Elastic-2.0`, `Freeware` and npm's `UNLICENSED` are nonfree. SPDX ids count as free when the SPDX license list marks them FSF-free or OSI-approved. With `--online-licenses`, packages with no usable license are looked up on deps.dev, Packagist, pub.dev, hex.pm, MetaCPAN or GitHub. Anything still unresolved is `unknown`, except under pacman and dpkg, whose vetted archives default to free.

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
--sources A,B / --skip A,B / --kind system|lang              what to scan
--kernel                                                      also scan kernel modules and drivers
--hypervisors                                                 also scan the hypervisor underneath and installed ones
--firmware                                                    also scan the BIOS/UEFI, Intel ME / AMD PSP and microcode
--hardware                                                    also scan devices that need a nonfree driver or firmware blobs
--status S (repeatable) / -f, --full / --all / --show-unknown  what to show (default: nonfree)
--sort source|name|status|ring|alternatives  (-s, -a shortcuts)  -r   ordering
--max-ring N                                                  only ring N or deeper (-3 … 3)
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

## Contributing to the lists

Curated entries live in `absolutely_proprietary/data/lists/*.json`, one object per entry:

```json
{"name": "zoom", "status": "nonfree", "alternatives": ["jitsi-meet-desktop"], "description": "Proprietary video conferencing", "reference": "https://en.wikipedia.org/wiki/Zoom_(software)"}
```

Add `"ring"` (-3, -2, -1, 0 or 3) when the software runs below userspace, such as a kernel driver or a hypervisor.

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

```sh
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
pytest && ruff check . && ruff format --check . && mypy absolutely_proprietary tests scripts
python scripts/check_lists.py --online   # after editing the lists
```
