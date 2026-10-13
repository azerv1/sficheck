from __future__ import annotations

from pathlib import Path

import pytest

from sficheck.licenses import classify, classify_many, sniff_dir, sniff_text
from sficheck.models import Status


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
        ("ASL 2.0", Status.FREE),  # Fedora/RHEL legacy (Callaway) name for Apache-2.0
        ("GPLv2 and LGPLv2+", Status.FREE),  # Callaway
        ("Redistributable, no modification permitted", Status.NONFREE),  # rpm firmware and drivers
        ("Freely redistributable without restriction", Status.NONFREE),  # Fedora: firmware only
        ("GPL+ and GPLv2+ and MIT and Redistributable, no modification permitted", Status.NONFREE),
        ("LicenseRef-Fedora-Firmware", Status.NONFREE),  # Fedora's tag for binary firmware
        ("GPL-2.0-or-later AND MIT AND LicenseRef-Fedora-Firmware", Status.SEMIFREE),
        ("LicenseRef-Not-Copyrightable", Status.FREE),
        ("MIT AND HPND-export-US AND HPND-export-US-acknowledgement", Status.FREE),  # krb5
        ("Python-2.0.1 AND HPND-SMC", Status.FREE),  # python3
        ("BSD-2-Clause-Views", Status.FREE),  # free in ScanCode, unmarked by SPDX
        ("JSON", Status.UNKNOWN),  # "Good, not Evil": ScanCode says permissive, the FSF says nonfree
        ("MS-LPL", Status.UNKNOWN),  # Windows-only
        ("Watcom-1.0", Status.UNKNOWN),
        ("2.0", Status.UNKNOWN),  # a ScanCode alias, not a license
        ("()", Status.UNKNOWN),  # crashed the expression parser
        ("(|0", Status.UNKNOWN),
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
