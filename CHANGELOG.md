## Unreleased

### BREAKING CHANGE

- a layer flag no longer adds to the software scan; pass
--software as well to keep both.

### Feat

- **sources**: add rpm for Fedora, RHEL and openSUSE
- **lists**: publish a JSON Schema for the curated lists
- **json**: version the JSON report and publish its schema
- **cli**: scan every layer by default and add --software

## 0.1.0 (2026-10-12)

### BREAKING CHANGE

- the docker and podman sources and `--kind container`
are gone.
- Python 3.10 is no longer supported (e.g. the system
Python of Ubuntu 22.04 and Debian 11).
- the interactive "Save list to file?" prompts are gone;
use -o FILE with --format instead.

### Feat

- **render**: capitalize the ME ring label
- **render**: leave sources with no packages out of the summaries
- **cli**: add --hardware to scan devices needing nonfree software
- **sources**: scan Windows devices on third-party drivers
- **sources**: add opt-in hardware source for Linux devices
- **cli**: add --firmware to scan rings -2 and -3
- **sources**: add opt-in firmware source
- **lists**: add curated firmware list (ME, PSP, microcode, BIOS)
- **cli**: add --hypervisors to scan ring -1
- **sources**: add opt-in hypervisors source
- **lists**: add curated hypervisor list
- **cli**: add --kernel to scan kernel modules and drivers
- **lists**: add curated kernel driver list
- **sources**: scan third-party Windows kernel drivers
- **sources**: add opt-in kernel source for loaded Linux modules
- **render**: show protection rings in every output format
- **cli**: add --max-ring filter and ring sort key
- **lists**: add kernel anticheat drivers at ring 0
- **lists**: tag kernel, hypervisor and microcode entries with a ring
- **lists**: read and validate a ring key in curated lists
- **sources**: give proprietary findings their source's default ring
- **models**: add protection-ring severity to entries and findings
- **scripts**: add check_lists.py to verify curated lists
- report where each classification comes from
- remove container image scanning
- new command-line interface
- render reports as table, markdown, JSON or CSV
- classify packages through a fixed chain of authorities
- look up missing licenses online
- audit Ruby, PHP, Perl, Lua, R, Julia, Dart, Haskell and Elixir
- audit JVM ecosystems (Maven, Gradle, SDKMAN!, Coursier)
- audit Rust, Go, .NET, C/C++ and Swift tools
- audit global JavaScript packages (npm, pnpm, yarn, bun, deno)
- audit Python packages (pip, uv tools, pipx)
- audit docker and podman images
- support Windows (registry, winget, scoop, Chocolatey)
- support Debian/Ubuntu, nix, flatpak, snap and brew
- add Source base class and metadata readers
- add bundled curated blacklists
- classify SPDX expressions and free-text licenses

### Fix

- **licenses**: don't crash on malformed license expressions
- **sources**: don't report a VM's 0xffffffff as the microcode version
- **sources**: detect Hyper-V underneath WSL 2
- **lists**: correct insync reference and llama.cpp alternative name
- **lists**: one sourced entry per Windows program
- **lists**: split and source windows-packages.json
- **lists**: verify lang.json against package registries
- **lists**: verify debian.json against sources
- **lists**: verify common.json against sources
- parse Parabola's blacklist format correctly

### Refactor

- rename project to sficheck
- **licenses**: free license IDs from license-expression's ScanCode index
- **sources**: Linux devices from pyudev
- **licenses**: take free license IDs from spdx-license-list
- **licenses**: parse expressions with license-expression
- **scripts**: check_lists fetches with httpx2
- **lists**: validate list files with msgspec
- **net**: fetch with httpx2
- **sources**: share one Windows registry helper
- **sources**: let a source build its own fallback finding
- **cli**: move finding filtering and sorting out of main
- replace the import-time script with core modules


- require Python 3.11
