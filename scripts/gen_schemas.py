"""Write the published JSON Schemas in docs/: the --format json report and the curated list files."""

from __future__ import annotations

import json
from pathlib import Path

from sficheck.blacklist import lists_schema
from sficheck.render import output_schema

DOCS = Path(__file__).resolve().parent.parent / "docs"

if __name__ == "__main__":
    for name, schema in (("output.schema.json", output_schema()), ("lists.schema.json", lists_schema())):
        target = DOCS / name
        target.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {target}")
