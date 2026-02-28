# CLAUDE.md

Instructions for Claude when contributing to this repository.

## What This Repo Is

A library of Claude AI skills. Each skill is a focused, self-contained capability for Claude Code in VS Code and Cursor.

## Structure

```
skills/
├── audit/           # Security review of Solidity changes while you develop
├── audit-helper/    # Full audit prep for security researchers
├── lint/            # Solidity linter (NatSpec, naming, best practices)
CLAUDE.md            # This file (read by Claude Code)
```

## Rules

- One skill, one purpose.
- No fabricated examples - outputs must reflect real model responses.
- No secrets, API keys, or personal data.
- Only list models in `model_compatibility` that have been tested.
