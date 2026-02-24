# Skill Name

> One-line description of what this skill does.

## Overview

What problem does this skill solve? Who is it for?

## Supported Models

| Model | Tested | Notes |
|-------|--------|-------|
| `claude-sonnet-4-6` | No | |
| `gpt-4o` | No | |
| `gemini-2.0-flash` | No | |

## Usage

### Claude (API)

```python
import anthropic

with open("system.md") as f:
    system = f.read()

client = anthropic.Anthropic()
message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    system=system,
    messages=[{"role": "user", "content": "Your input here"}],
)
print(message.content[0].text)
```

### OpenAI (API)

```python
import openai

with open("system.md") as f:
    system = f.read()

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": system},
        {"role": "user", "content": "Your input here"},
    ],
)
print(response.choices[0].message.content)
```

### Gemini (API)

```python
import google.generativeai as genai

with open("system.md") as f:
    system = f.read()

model = genai.GenerativeModel(
    model_name="gemini-2.0-flash",
    system_instruction=system,
)
response = model.generate_content("Your input here")
print(response.text)
```

## Examples

See [`examples/`](examples/) for sample inputs and outputs.

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_tokens` | 1024 | Maximum response length |

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for version history.
