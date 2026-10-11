"""Property tests: invariants that must hold for any input, not just the examples in the other test files."""

from __future__ import annotations

import msgspec
import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from absolutely_proprietary.blacklist import (
    DEFAULT_SKIP_TAGS,
    PARABOLA_ISSUE_URL,
    TAG_STATUS,
    ListEntry,
    ListFile,
    parse_list,
    parse_parabola_line,
)
from absolutely_proprietary.licenses import _OR_RANK, classify, classify_many
from absolutely_proprietary.models import Ring, Status
from absolutely_proprietary.sources.firmware import _revision

# Real ids and free-text names across every status, plus made-up license-like tokens.
KNOWN = ["MIT", "GPL-3.0-or-later", "LGPL-2.1+", "Apache-2.0", "BSD-3-Clause", "Unlicense", "BUSL-1.1", "SSPL-1.0"]
KNOWN += ["CC-BY-NC-4.0", "JSON", "LicenseRef-proprietary", "UNLICENSED", "Freeware", "Proprietary", "Other"]
OPERATORS = {"and", "or", "with"}
licenses = st.one_of(
    st.sampled_from(KNOWN),
    st.from_regex(r"[A-Za-z][A-Za-z0-9.\-]{0,15}", fullmatch=True).filter(lambda s: s.lower() not in OPERATORS),
)
# Text dense in the characters the expression parser and the free-text fallback react to.
license_text = st.one_of(st.text(), st.text(alphabet="()/|&+-. ORANDWITHmitgplv23	"))


@given(license_text)
def test_classify_never_raises(text: str) -> None:
    assert classify(text) in Status


@given(licenses, licenses)
def test_or_is_the_freer_branch_in_any_order(a: str, b: str) -> None:
    freer = min(classify(a), classify(b), key=_OR_RANK.__getitem__)
    assert classify(f"{a} OR {b}") is classify(f"{b} OR {a}") is freer


@given(licenses, licenses)
def test_free_text_separators_mean_or(a: str, b: str) -> None:
    assume(not (a.lower() == "other" and b.lower().startswith("proprietary")))  # "Other/Proprietary" is one term
    assert classify(f"{a}/{b}") is classify(f"{a} || {b}") is classify(f"{a} | {b}") is classify(f"{a} OR {b}")


@given(licenses, licenses)
def test_a_list_of_licenses_means_any_of_them(a: str, b: str) -> None:
    assert classify_many([a, b]) is classify(f"{a} OR {b}")


package_names = st.from_regex(r"[a-z0-9][a-z0-9._+-]{0,20}", fullmatch=True)
descriptions = st.text(alphabet=st.characters(categories=["L", "N", "Zs"], include_characters=":,.()-"), max_size=40)


@given(st.text())
def test_parabola_parser_never_raises(line: str) -> None:
    entry = parse_parabola_line(line)
    assert entry is None or entry.status in Status


@given(package_names, st.one_of(st.just(""), package_names), st.integers(0, 99999), descriptions, st.data())
def test_parabola_lines_round_trip(
    name: str, replacement: str, issue: int, description: str, data: st.DataObject
) -> None:
    description = description.strip()
    assume(not description.startswith((":", "[")))  # would read as part of the tag block
    tag = data.draw(st.sampled_from(sorted(TAG_STATUS.keys() | DEFAULT_SKIP_TAGS)))
    entry = parse_parabola_line(f"{name}:{replacement}:parabola:{issue}:[{tag}] {description}")
    if tag in DEFAULT_SKIP_TAGS:
        assert entry is None
        return
    assert entry is not None
    assert (entry.name, entry.status, entry.description) == (name, TAG_STATUS[tag], description)
    assert entry.reference == PARABOLA_ISSUE_URL.format(issue)
    if replacement == name:
        assert entry.alternatives == (f"{name} (Parabola build)",)
    else:
        assert entry.alternatives == ((replacement,) if replacement else ())


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4),
    max_leaves=10,
)
# Close to a real list file, so the schema is exercised past its first check.
near_list_files = st.fixed_dictionaries(
    {
        "entries": st.lists(
            st.dictionaries(st.sampled_from([*ListEntry.__struct_fields__, "stauts"]), json_values), max_size=4
        )
    }
)
list_entries = st.builds(
    ListEntry,
    name=st.text(),
    status=st.sampled_from(Status),
    alternatives=st.lists(st.text()).map(tuple),
    description=st.text(),
    reference=st.text(),
    pattern=st.none() | st.text(),
    ring=st.none() | st.sampled_from(Ring),
)


@given(json_values | near_list_files)
def test_list_files_parse_or_raise_value_error(data: object) -> None:
    try:
        assert isinstance(parse_list(data, "test"), ListFile)
    except ValueError as exc:
        assert str(exc).startswith("test: ")


@given(st.lists(list_entries))
def test_list_files_round_trip(entries: list[ListEntry]) -> None:
    assert parse_list(msgspec.json.encode(ListFile(entries)), "test").entries == entries


@given(st.binary(max_size=16))
def test_microcode_revision_is_empty_or_hex(raw: bytes) -> None:
    revision = _revision(raw)
    if not any(raw):
        assert revision == ""
    else:
        value = int.from_bytes(raw, "little")
        assert revision == hex(value >> 32 if len(raw) == 8 else value)


@pytest.mark.parametrize("raw", [None, 0x1F, "0x1f"])
def test_microcode_revision_ignores_non_bytes(raw: object) -> None:
    assert _revision(raw) == ""
