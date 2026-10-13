"""Write docs/output.schema.json, the JSON Schema of `sficheck --format json`, from sficheck.render.Report."""

from __future__ import annotations

import json
from pathlib import Path

from sficheck.render import output_schema

TARGET = Path(__file__).resolve().parent.parent / "docs" / "output.schema.json"

if __name__ == "__main__":
    TARGET.write_text(json.dumps(output_schema(), indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {TARGET}")
