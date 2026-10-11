"""Property tests: invariants that must hold for any input, not just the examples in the other test files."""

from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from absolutely_proprietary.licenses import _OR_RANK, classify, classify_many
from absolutely_proprietary.models import Status

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
