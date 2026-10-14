from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from sficheck import proc


@pytest.mark.skipif(sys.platform != "win32", reason="only Windows searches the current directory")
def test_which_ignores_a_same_named_file_in_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real, here = tmp_path / "bin", tmp_path / "repo"
    real.mkdir()
    here.mkdir()
    (real / "tool.cmd").write_text("@echo real\r\n", encoding="utf-8")
    (here / "tool.cmd").write_text("@echo fake\r\n", encoding="utf-8")
    (here / "elsewhere.cmd").write_text("@echo fake\r\n", encoding="utf-8")
    monkeypatch.chdir(here)
    monkeypatch.delenv("NoDefaultCurrentDirectoryInExePath", raising=False)  # set in some shells, not in cmd
    monkeypatch.setenv("PATH", str(real))
    found = proc.which("tool")
    assert found is not None and Path(found).parent == real
    assert proc.which("elsewhere") is None  # only in the current directory: not installed
    monkeypatch.setenv("PATH", os.pathsep.join([os.curdir, str(real)]))
    assert proc.which("elsewhere") is not None  # unless PATH asks for the current directory
