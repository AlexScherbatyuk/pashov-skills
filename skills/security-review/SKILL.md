---
name: security-review
description: Fast, focused security feedback on Solidity code while you develop - before you commit, not after an auditor does. Built for developers, not security researchers. Use when the user asks to "review my changes for security issues", "check this contract", "security-review", or wants a quick sanity check before pushing. Supports three modes - default (reviews git-changed files), ALL (full repo), or a specific filename.
---

# Smart Contract Security Review

Fast, focused security feedback while you're developing. Catch real issues early - before they reach an audit or mainnet.

Before scanning any code, read the full attack vector reference:
```
references/attack-vectors.md
```
It contains 48 attack vectors with precise detection patterns and false-positive signals. Use it as your scanning checklist for every file.

## Mode Selection

- **Default** (no arguments): run `git diff HEAD --name-only`, filter for `.sol` files. Stop and say so if there are no changed Solidity files.
- **ALL**: scan all `.sol` files in the repo (exclude `lib/`, `out/`, `node_modules/`, `.git/`).
- **`$filename`**: scan that specific file only.

## Context Loading

Check the skill's `assets/` directory before scanning:

- **`assets/false-positives.md`** - known non-issues for this codebase. Suppress any finding that matches. Note suppression count at the bottom of the report.
- **`assets/findings/`** - prior audit reports. Use as context to avoid duplicating known issues. Mark previously known findings as such.

## Review Process

For each file in scope:

1. Read the full file.
2. Scan against all 48 vectors in `references/attack-vectors.md`. For each vector, check whether the detection pattern is present, then check the false-positive signals before deciding to report it.
3. Only report findings where the detection pattern matches AND the false-positive conditions do not apply.
4. Use judgment on severity - a theoretical issue in code that's demonstrably bounded is not a finding.

Prioritize findings that are:
- Directly exploitable with a concrete attack path
- In functions handling value (ETH, tokens, governance power)
- In code that was changed (in default mode)

## Output Format

```
# Security Review

## Summary
<1-3 sentences: severity distribution, files reviewed, most critical finding>

## Findings

### [CRITICAL|HIGH|MEDIUM|LOW|INFO] Title
- **Location:** ContractName.functionName (line N)
- **Vector:** <vector name from attack-vectors.md>
- **Issue:** <what is wrong and why it matters>
- **Impact:** <what an attacker can do>
- **PoC:** <minimal attack scenario - one paragraph, no full exploit code>
- **Fix:** <concrete code-level recommendation>

## Scope
<files reviewed, mode, false positives suppressed (N)>
```

Order findings Critical first. Omit severity levels that have no findings.

## Constraints

- Do not report a finding unless you can point to a specific line or code pattern that triggers it.
- Do not report theoretical issues that are structurally prevented by the codebase (check false-positive signals).
- Never fabricate findings to appear thorough.
- Keep PoC concise - attack scenario, not a full working exploit.
