# AI Skills

> A community-curated library of skills for AI assistants — Claude, ChatGPT, Gemini, and beyond.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/code%20of%20conduct-enforced-blue.svg)](CODE_OF_CONDUCT.md)
[![CI](https://github.com/pashov/skills/actions/workflows/ci.yml/badge.svg)](https://github.com/pashov/skills/actions/workflows/ci.yml)

---

## What are AI Skills?

AI Skills are reusable, shareable building blocks that extend the capabilities of AI assistants. Each skill defines a focused capability — a system prompt, a tool definition, a workflow template, or a slash command — that can be dropped into your AI environment of choice.

Think of them as plugins for your AI assistant.

---

## Supported Platforms

| Platform               | Type                                              | Notes                                 |
| ---------------------- | ------------------------------------------------- | ------------------------------------- |
| **Claude** (Anthropic) | Slash commands, system prompts, hooks             | Works with Claude Code and Claude API |
| **ChatGPT** (OpenAI)   | GPT actions, system prompts, custom instructions  | Works with GPT-4o and o-series models |
| **Gemini** (Google)    | System instructions, extensions, function calling | Works with Gemini 1.5 Pro / 2.x       |
| **Generic**            | Prompt templates                                  | Model-agnostic skills usable anywhere |

---

## Repository Structure

```
skills/
├── claude/          # Skills for Anthropic Claude (Claude Code, API)
├── openai/          # Skills for OpenAI ChatGPT / GPT models
├── gemini/          # Skills for Google Gemini
├── generic/         # Model-agnostic prompt templates & workflows
└── _template/       # Starter template for new skills
```

---

## Quick Start

### Using a Skill

1. Browse the [`skills/`](skills/) directory and pick a skill.
2. Read the skill's `README.md` for platform-specific setup instructions.
3. Copy the skill into your AI environment (API system prompt, Claude Code `~/.claude/`, etc.).

## Creating a Skill

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. The short version:

1. Copy [`skills/_template/`](skills/_template/) to the appropriate platform folder.
2. Fill in your skill's `skill.json` manifest and `system.md` prompt.
3. Add a `README.md` with usage instructions and examples.
4. Open a pull request.

---

## Contributing

We welcome contributions of all kinds — new skills, bug fixes, documentation improvements, and translations. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.

---

## Security

To report a security vulnerability, please follow our [Security Policy](SECURITY.md). Do not open a public issue.

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards.

---

## License

[MIT](LICENSE) © contributors
