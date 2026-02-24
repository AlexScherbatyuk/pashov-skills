# Pull Request

## Type of Change

- [ ] New skill
- [ ] Improvement to an existing skill
- [ ] Bug fix
- [ ] Documentation update
- [ ] Repository tooling / CI
- [ ] Other (describe below)

## Summary

<!-- 2-4 sentences: what does this PR do and why? -->

## Skill Details *(fill in for new or updated skills)*

| Field | Value |
|-------|-------|
| Path | `skills/<platform>/<skill-name>/` |
| Platform | claude / openai / gemini / generic |
| Models tested | e.g. `claude-sonnet-4-6`, `gpt-4o` |

## Changes

<!-- Bullet-point list of what changed -->
-
-

## Testing

Describe how you tested the skill. Paste a representative input/output pair:

**Input:**
```
```

**Output:**
```
```

## Checklist

- [ ] `skill.json` manifest is filled in correctly (name, version, platform, tags)
- [ ] `system.md` contains the skill prompt
- [ ] `README.md` explains usage with at least one example
- [ ] No API keys, tokens, or sensitive data included
- [ ] Skill does not instruct the model to bypass provider safety guidelines
- [ ] `CHANGELOG.md` updated (for skill changes) or not applicable
- [ ] CI passes
