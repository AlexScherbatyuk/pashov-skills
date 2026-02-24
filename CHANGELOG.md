# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Versioning Guide

Given a version number `MAJOR.MINOR.PATCH`:

- **MAJOR** — breaking changes to skill interfaces or manifest schema
- **MINOR** — new skills or backwards-compatible additions
- **PATCH** — bug fixes, prompt improvements, documentation updates

Pre-release versions are tagged as `v1.0.0-beta.1`, `v1.0.0-rc.1`, etc.

---

## [Unreleased]

### Added
- Initial repository structure
- Skill template (`skills/_template/`)
- Platform directories: `claude/`, `openai/`, `gemini/`, `generic/`
- `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
- GitHub Actions CI workflow
- Issue and PR templates

---

<!-- Add new releases above this line using the format below:

## [1.1.0] - YYYY-MM-DD

### Added
- New `skills/claude/my-skill` skill

### Changed
- Improved prompt in `skills/generic/summarizer`

### Fixed
- Corrected model compatibility list in `skills/openai/code-review/skill.json`

### Removed
- Deprecated `skills/generic/old-skill`

-->

[Unreleased]: https://github.com/pashov/skills/compare/HEAD...HEAD
