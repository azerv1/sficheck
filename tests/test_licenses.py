from __future__ import annotations

from pathlib import Path

import pytest

from absolutely_proprietary.licenses import classify, classify_many, sniff_dir, sniff_text
from absolutely_proprietary.models import Status


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ("MIT", Status.FREE),
        ("GPL-3.0-or-later", Status.FREE),
        ("GPL-2.0+", Status.FREE),
        ("Apache-2.0 WITH LLVM-exception", Status.FREE),
        ("GPL-2.0-only WITH Classpath-exception-2.0", Status.FREE),
        ("MIT OR Apache-2.0", Status.FREE),
        ("MIT/Apache-2.0", Status.FREE),
        ("(MIT OR Apache-2.0) AND Unicode-3.0", Status.FREE),
        ("MIT OR Proprietary", Status.FREE),
        ("MIT AND LicenseRef-proprietary", Status.SEMIFREE),
        ("LicenseRef-proprietary", Status.NONFREE),
        ("BUSL-1.1", Status.NONFREE),
        ("SSPL-1.0", Status.NONFREE),
        ("Elastic-2.0", Status.NONFREE),
        ("CC-BY-NC-4.0", Status.NONFREE),
        ("UNLICENSED", Status.NONFREE),  # npm's "all rights reserved"
        ("Unlicense", Status.FREE),
        ("Freeware", Status.NONFREE),
        ("Proprietary (Freeware)", Status.NONFREE),
        ("Microsoft Software License", Status.NONFREE),
        ("Other/Proprietary License", Status.NONFREE),
        ("Apache License, Version 2.0", Status.FREE),
        ("GNU General Public License v3 (GPLv3)", Status.FREE),
        ("BSD License", Status.FREE),
        ("GPL (>= 2)", Status.FREE),  # R
        ("GPL-2 | GPL-3", Status.FREE),  # R
        ("perl_5", Status.FREE),  # MetaCPAN
        ("Combined GPLv2 and proprietary software", Status.SEMIFREE),
        ("SEE LICENSE IN README.md", Status.UNKNOWN),
        ("NOASSERTION", Status.UNKNOWN),
        ("Dual License", Status.UNKNOWN),
        ("", Status.UNKNOWN),
        (None, Status.UNKNOWN),
    ],
)
def test_classify(expr: str | None, expected: Status) -> None:
    assert classify(expr) is expected


def test_word_boundaries() -> None:
    # "mit" must not match inside "permitted"; "gpl" still matches "gplv3"-style spellings.
    assert classify("Redistribution permitted") is Status.UNKNOWN
    assert classify("LGPLv3") is Status.FREE
    assert classify("GPLv2") is Status.FREE


def test_classify_many_picks_freest() -> None:
    assert classify_many(["Proprietary", "GPL-3.0"]) is Status.FREE
    assert classify_many([]) is Status.UNKNOWN


@pytest.mark.parametrize(
    ("text", "spdx"),
    [
        ("Permission is hereby granted, free of charge, to any person", "MIT"),
        ("                 Apache License\n           Version 2.0, January 2004", "Apache-2.0"),
        ("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3", "LGPL-3.0"),
        ("GNU GENERAL PUBLIC LICENSE\nVersion 2", "GPL-3.0"),
        ("Business Source License 1.1", "BUSL-1.1"),
        ("All rights reserved. Do not copy.", None),
    ],
)
def test_sniff_text(text: str, spdx: str | None) -> None:
    assert sniff_text(text) == spdx


def test_sniff_dir(tmp_path: Path) -> None:
    assert sniff_dir(tmp_path) is None
    (tmp_path / "COPYING").write_text("This is free and unencumbered software released into the public domain.")
    assert sniff_dir(tmp_path) == "Unlicense"
