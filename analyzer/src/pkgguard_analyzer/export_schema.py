"""Write JSON Schemas to /schema so TypeScript code can generate matching types."""

import json
from pathlib import Path

from pkgguard_analyzer.schema import Report, VerdictRecord

SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schema"


def main() -> None:
    SCHEMA_DIR.mkdir(exist_ok=True)
    for filename, model in (("verdict-record.schema.json", VerdictRecord), ("report.schema.json", Report)):
        schema = model.model_json_schema(by_alias=True, mode="serialization")
        (SCHEMA_DIR / filename).write_text(json.dumps(schema, indent=2) + "\n")
        print(f"wrote schema/{filename}")


if __name__ == "__main__":
    main()
