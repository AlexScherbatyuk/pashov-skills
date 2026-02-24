# Contributing to AI Skills

Thank you for your interest in contributing! This guide covers everything you need to know to add or improve skills.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Before You Start](#before-you-start)
- [Creating a New Skill](#creating-a-new-skill)
- [Skill Quality Standards](#skill-quality-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)

---

## Code of Conduct

By participating, you agree to our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

---

## Ways to Contribute

- **New skill** — Add a skill for any supported AI platform.
- **Improve an existing skill** — Fix bugs, improve prompts, add examples.
- **Documentation** — Fix typos, clarify instructions, add translations.
- **Bug report** — Open an issue using the bug report template.
- **Feature request** — Suggest new skill ideas or repository improvements.

---

## Before You Start

1. **Search existing issues and PRs** to avoid duplicating work.
2. For non-trivial changes, open an issue first to discuss your approach.
3. Fork the repository and create a branch from `main`.

```bash
git clone https://github.com/pashov/skills.git
cd skills
git checkout -b feat/my-skill-name
```

---

## Creating a New Skill

### 1. Choose the Right Directory

| Directory | Use for |
|-----------|---------|
| `skills/claude/` | Claude API, Claude Code slash commands |
| `skills/openai/` | ChatGPT, GPT-4o, Assistants API, GPT actions |
| `skills/gemini/` | Gemini API, Gemini extensions |
| `skills/generic/` | Model-agnostic prompts that work anywhere |

### 2. Copy the Template

```bash
cp -r skills/_template/ skills/<platform>/<your-skill-name>/
```

### 3. Fill in the Files

Every skill must include:

| File | Required | Description |
|------|----------|-------------|
| `skill.json` | Yes | Manifest: name, description, version, tags |
| `system.md` | Yes | The system prompt / skill definition |
| `README.md` | Yes | Usage instructions and examples |
| `examples/` | Recommended | Sample inputs and outputs |
| `CHANGELOG.md` | No | Skill-level changelog |

### 4. `skill.json` Manifest Format

```json
{
  "name": "my-skill-name",
  "version": "1.0.0",
  "description": "One sentence describing what this skill does.",
  "platform": "claude",
  "model_compatibility": ["claude-opus-4-6", "claude-sonnet-4-6"],
  "tags": ["productivity", "coding"],
  "author": "your-github-handle",
  "license": "MIT"
}
```

**`platform`** must be one of: `claude`, `openai`, `gemini`, `generic`.

**`model_compatibility`** — list the specific models this skill has been tested with.

### 5. Platform-Specific Notes

#### Claude (Anthropic)
- Slash command skills go in `skills/claude/` and follow the Claude Code skill format.
- System prompt skills should work with the Claude Messages API (`claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5`).
- Hooks-based skills should document required Claude Code hook events.
- Reference: [Claude API docs](https://docs.anthropic.com/)

#### OpenAI / ChatGPT
- System prompts must conform to the OpenAI Chat Completions API format.
- GPT Actions should include a valid OpenAPI schema in `action_schema.json`.
- Tested against: `gpt-4o`, `gpt-4o-mini`, `o1`, `o3-mini`.
- Reference: [OpenAI API docs](https://platform.openai.com/docs)

#### Gemini (Google)
- System instructions must work with the Gemini `generateContent` API.
- Function calling tools should include a schema in `tools.json`.
- Tested against: `gemini-2.0-flash`, `gemini-1.5-pro`.
- Reference: [Gemini API docs](https://ai.google.dev/docs)

---

## Skill Quality Standards

- **Focused** — Each skill does one thing well.
- **Tested** — Include at least one example showing input and expected output.
- **Safe** — Skills must not encourage harmful, deceptive, or unethical behavior.
- **Model-honest** — Clearly state which models the skill has been tested with.
- **No hardcoded secrets** — Never include API keys, tokens, or personal data.

---

## Pull Request Process

1. Ensure your branch is up to date with `main`.
2. Run the validation script (if applicable): `npm run validate` or `python scripts/validate.py`.
3. Fill in the PR template completely.
4. A maintainer will review within 5 business days.
5. Address review feedback promptly.
6. Once approved, a maintainer will merge.

---

## Reporting Bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template and include:
- Which skill and platform version is affected.
- Steps to reproduce.
- Expected vs. actual behavior.
- The model and API version used.
