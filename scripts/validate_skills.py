#!/usr/bin/env python3
"""
Validates every skill directory in skills/ against the required structure
and skill.json schema.
"""

import json
import os
import sys
from pathlib import Path

SKILL_JSON_SCHEMA = {
    "type": "object",
    "required": ["name", "version", "description", "platform", "tags", "author", "license"],
    "properties": {
        "name":                {"type": "string"},
        "version":             {"type": "string", "pattern": r"^\d+\.\d+\.\d+"},
        "description":         {"type": "string"},
        "platform":            {"type": "string", "enum": ["claude", "openai", "gemini", "generic"]},
        "model_compatibility": {"type": "array", "items": {"type": "string"}},
        "tags":                {"type": "array", "items": {"type": "string"}},
        "author":              {"type": "string"},
        "license":             {"type": "string"},
    },
}

REQUIRED_FILES = ["skill.json", "system.md", "README.md"]

PLATFORM_DIRS = ["claude", "openai", "gemini", "generic"]

errors: list[str] = []
skills_checked = 0

skills_root = Path(__file__).parent.parent / "skills"

for platform in PLATFORM_DIRS:
    platform_path = skills_root / platform
    if not platform_path.exists():
        continue
    for skill_dir in sorted(platform_path.iterdir()):
        if not skill_dir.is_dir():
            continue

        skills_checked += 1
        prefix = f"{platform}/{skill_dir.name}"

        # Check required files
        for fname in REQUIRED_FILES:
            if not (skill_dir / fname).exists():
                errors.append(f"{prefix}: missing required file '{fname}'")

        # Validate skill.json
        manifest_path = skill_dir / "skill.json"
        if manifest_path.exists():
            try:
                import jsonschema
                with open(manifest_path) as f:
                    manifest = json.load(f)
                jsonschema.validate(manifest, SKILL_JSON_SCHEMA)
            except json.JSONDecodeError as e:
                errors.append(f"{prefix}/skill.json: invalid JSON — {e}")
            except jsonschema.ValidationError as e:
                errors.append(f"{prefix}/skill.json: schema error — {e.message}")

        # Check system.md is non-empty
        system_path = skill_dir / "system.md"
        if system_path.exists() and system_path.stat().st_size == 0:
            errors.append(f"{prefix}/system.md: file is empty")

if errors:
    print(f"Found {len(errors)} error(s) across {skills_checked} skill(s):\n")
    for err in errors:
        print(f"  ✗ {err}")
    sys.exit(1)
else:
    print(f"All {skills_checked} skill(s) passed validation.")
