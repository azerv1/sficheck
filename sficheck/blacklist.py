"""Blacklists: Parabola's remote lists, the bundled curated lists and user-supplied lists."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import msgspec

from sficheck.models import Entry, Ring, Status
from sficheck.net import Fetcher

log = logging.getLogger(__name__)

PARABOLA_BASE = "https://git.parabola.nu/abslibre/blacklist.git/plain/"
PARABOLA_LISTS = {
    "blacklist": PARABOLA_BASE + "blacklist.txt",
    "aur": PARABOLA_BASE + "aur-blacklist.txt",
    "privacy": PARABOLA_BASE + "your-privacy-blacklist.txt",
}
PARABOLA_ISSUE_URL = "https://labs.parabola.nu/issues/{}"

# Parabola tags that say *why* something is blacklisted, mapped to our statuses.
TAG_STATUS = {
    "nonfree": Status.NONFREE,
    "semifree": Status.SEMIFREE,
    "uses-nonfree": Status.USES_NONFREE,
    "use-nonfree": Status.USES_NONFREE,
    "recommends-nonfree": Status.USES_NONFREE,
    "antifeatures": Status.USES_NONFREE,
}
# Entries blacklisted for reasons unrelated to software freedom.
DEFAULT_SKIP_TAGS = frozenset({"technical", "branding", "policy", "libre"})

_LEADING_TAGS = re.compile(r"^[\s:]*((?:\[[^\]]*\]\s*)*):?\s*(.*)$", re.DOTALL)
_TAG = re.compile(r"\[([^\]]*)\]")


def parse_parabola_line(
    line: str,
    origin: str = "parabola",
    default_status: Status = Status.NONFREE,
    skip_tags: frozenset[str] = DEFAULT_SKIP_TAGS,
) -> Entry | None:
    """Parse ``name:replacement:ref:id:[tag]... description``; None for blank/skipped lines."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    name, replacement, ref, ref_id, rest = ([*line.split(":", 4), "", "", "", ""])[:5]
    match = _LEADING_TAGS.match(rest)
    tag_block, description = (match.group(1), match.group(2)) if match else ("", rest)
    tags = [t.strip().lower() for t in _TAG.findall(tag_block)]
    reason_tags = [t for t in tags if not t.startswith("fixme")]

    status = next((TAG_STATUS[t] for t in reason_tags if t in TAG_STATUS), None)
    if status is None:
        if any(t in skip_tags for t in reason_tags):
            return None
        status = default_status

    reference = ""
    if ref == "parabola" and ref_id.isdigit():
        reference = PARABOLA_ISSUE_URL.format(ref_id)
    replacement = replacement.strip()
    # Same name means Parabola ships a liberated build of the package.
    if replacement == name:
        replacement = f"{name} (Parabola build)"
    alternatives = (replacement,) if replacement else ()
    return Entry(
        name=name.strip(),
        status=status,
        alternatives=alternatives,
        description=description.strip(),
        origin=origin,
        reference=reference,
    )


def parse_parabola(text: str, origin: str = "parabola", default_status: Status = Status.NONFREE) -> Iterator[Entry]:
    for line in text.splitlines():
        entry = parse_parabola_line(line, origin, default_status)
        if entry is not None:
            yield entry


class ListEntry(msgspec.Struct, forbid_unknown_fields=True):
    """One entry of a JSON list (bundled or --blacklist); see README "Lists"."""

    name: str
    status: Status = Status.NONFREE
    alternatives: tuple[str, ...] = ()
    description: str = ""
    reference: str = ""
    pattern: str | None = None  # regex on display names, instead of an exact name
    ring: Ring | None = None

    def to_entry(self, origin: str) -> Entry:
        return Entry(
            name=self.name,
            status=self.status,
            alternatives=self.alternatives,
            description=self.description,
            origin=origin,
            reference=self.reference,
            ring=self.ring,
        )


class ListFile(msgspec.Struct):
    entries: list[ListEntry] = []


def lists_schema() -> dict[str, Any]:
    """The JSON Schema of a list file, as published in docs/lists.schema.json for editors."""
    # Round-trip through JSON so tuple defaults such as () come back as [], the way the file stores them.
    generated = msgspec.json.decode(msgspec.json.encode(msgspec.json.schema(ListFile)))
    schema: dict[str, Any] = {"$schema": "https://json-schema.org/draft/2020-12/schema", **generated}
    # The rule from README "Contributing to the lists": anything not free must cite a reference.
    schema["$defs"]["ListEntry"]["if"] = {"not": {"properties": {"status": {"const": "free"}}, "required": ["status"]}}
    schema["$defs"]["ListEntry"]["then"] = {"required": ["reference"], "properties": {"reference": {"minLength": 1}}}
    return schema


def parse_list(data: str | bytes | object, origin: str) -> ListFile:
    """Validate a JSON list given as text or as already-parsed data."""
    try:
        if isinstance(data, str | bytes):
            return msgspec.json.decode(data, type=ListFile)
        return msgspec.convert(data, ListFile)
    except msgspec.DecodeError as exc:  # ValidationError included; its message names the bad field
        raise ValueError(f"{origin}: {exc}") from exc


@dataclass(slots=True)
class Blacklist:
    """Name → Entry lookup, plus regex patterns for fuzzy names (Windows display names)."""

    by_name: dict[str, Entry] = field(default_factory=dict)
    patterns: list[tuple[re.Pattern[str], Entry]] = field(default_factory=list)

    def add(self, entry: Entry, pattern: str | None = None) -> None:
        """Later additions override earlier ones."""
        if pattern:
            self.patterns.insert(0, (re.compile(pattern, re.IGNORECASE), entry))
        else:
            self.by_name[entry.name.lower()] = entry

    def extend(self, entries: Iterable[Entry]) -> None:
        for entry in entries:
            self.add(entry)

    def lookup(self, *names: str) -> Entry | None:
        for name in names:
            if name and (entry := self.by_name.get(name.lower())):
                return entry
        for regex, entry in self.patterns:
            if any(name and regex.search(name) for name in names):
                return entry
        return None

    def __len__(self) -> int:
        return len(self.by_name) + len(self.patterns)

    def load_json(self, data: str | bytes | object, origin: str) -> None:
        """Patterns keep their file order (first match wins) but take precedence over older lists."""
        new_patterns = []
        for raw in parse_list(data, origin).entries:
            entry = raw.to_entry(origin)
            if pattern := raw.pattern:
                new_patterns.append((re.compile(pattern, re.IGNORECASE), entry))
            else:
                self.add(entry)
        self.patterns[:0] = new_patterns

    def merged(self, other: Blacklist) -> Blacklist:
        """A new list where ``other`` overrides ``self``."""
        return Blacklist({**self.by_name, **other.by_name}, [*other.patterns, *self.patterns])


def bundled_names() -> list[str]:
    return sorted(
        p.name.removesuffix(".json")
        for p in resources.files("sficheck.data.lists").iterdir()
        if p.name.endswith(".json")
    )


def load_bundled(*names: str) -> Blacklist:
    """Load bundled curated lists (``data/lists/<name>.json``); later names override earlier."""
    bl = Blacklist()
    root = resources.files("sficheck.data.lists")
    for name in names:
        text = root.joinpath(f"{name}.json").read_text(encoding="utf-8")
        bl.load_json(text, origin=f"bundled:{name}")
    return bl


def load_parabola(fetcher: Fetcher, include_aur: bool = True, include_privacy: bool = False) -> Blacklist:
    bl = Blacklist()
    wanted = ["blacklist"] + (["aur"] if include_aur else []) + (["privacy"] if include_privacy else [])
    for key in wanted:
        text = fetcher.get(PARABOLA_LISTS[key])
        if text is None:
            log.warning("Parabola %s list unavailable; results for pacman will be incomplete", key)
            continue
        default = Status.USES_NONFREE if key == "privacy" else Status.NONFREE
        bl.extend(parse_parabola(text, origin=f"parabola:{key}", default_status=default))
    return bl


def load_user(location: str, fetcher: Fetcher) -> Blacklist:
    """A user list: JSON in the bundled format, or Parabola-format text. Path or URL."""
    if re.match(r"^https?://", location):
        text = fetcher.get(location)
        if text is None:
            raise OSError(f"could not fetch {location}")
    else:
        text = Path(location).expanduser().read_text(encoding="utf-8")
    bl = Blacklist()
    origin = f"user:{Path(location).name}"
    if text.lstrip().startswith("{"):
        bl.load_json(text, origin)
    else:
        bl.extend(parse_parabola(text, origin=origin))
    return bl
