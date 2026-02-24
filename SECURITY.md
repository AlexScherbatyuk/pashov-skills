# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |
| older branches | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a security issue, please email the maintainers directly via the contact listed on the [GitHub profile](https://github.com/pashov). Include as much detail as possible:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

You can expect an acknowledgement within **48 hours** and a status update within **7 days**.

## Security Considerations for AI Skills

Skills in this repository are prompt-based and interact with external AI APIs. Please keep the following in mind:

### Never include in a skill
- API keys, tokens, or credentials of any kind
- Personal or sensitive user data
- Internal system information (hostnames, IPs, internal URLs)

### Prompt injection risks
Skills that accept user-provided input should be designed defensively. Avoid constructing prompts that concatenate raw user input directly into privileged instructions. Document any known prompt injection vectors in the skill's `README.md`.

### Model output safety
Skills should not be designed to bypass the safety guidelines of any AI provider. Skills that instruct a model to ignore its system instructions or impersonate system roles will be rejected.

### Dependency security
If a skill includes code (e.g., a Python wrapper or Node.js helper), dependencies must be pinned to specific versions and reviewed before merging. Run `npm audit` or `pip-audit` where applicable.

## Disclosure Policy

Once a vulnerability is confirmed and patched, we will:

1. Release a patched version.
2. Credit the reporter (unless they prefer to remain anonymous).
3. Publish a brief advisory in `CHANGELOG.md`.
