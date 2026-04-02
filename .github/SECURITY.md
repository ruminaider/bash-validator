# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.4.x   | Yes       |
| 2.3.x   | Yes       |
| < 2.3   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in bash-validator, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly or use [GitHub's private vulnerability reporting](https://github.com/ruminaider/bash-validator/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce (a command that bypasses the validator when it shouldn't)
- Expected behavior vs actual behavior
- Which version you're running (`cat .claude-plugin/plugin.json`)

### Response timeline

- Acknowledgment within 48 hours
- Fix or mitigation plan within 7 days
- Patch release for critical issues within 14 days

## Security Model

bash-validator uses an **allow/ask/deny** model. The validator auto-approves commands it can statically verify as safe and prompts the user for everything else. Structural patterns (heredoc, inline code, command substitution) that are rejected 3+ times in a session escalate to denial. Safety gates (destructive commands) always defer to the user.

### Trust layers

1. **Enforcement (hook)** — deterministic static analysis. No LLM in the decision loop. Injection-proof.
2. **Learning (SessionStart hook)** — frequency-based pattern analysis on tokenized command data. Bounded by an immutable deny list.
3. **Prevention (skill)** — advisory guidance for subagents. Cannot bypass enforcement.

### Known attack surface

- **Inline code evasion:** The Python AST analyzer can be bypassed via subscript aliasing (`[open][0]("file")`) or dynamic attribute construction. These require deliberate adversarial effort and are unlikely in LLM-generated code. The fallback is always "ask the user."
- **Regex limitations:** The Node.js analyzer uses regex, not a parser. Obfuscated JS could bypass detection. Same fallback applies.
- **Self-modification:** `sed -i` targeting the validator is now flagged, but other file-writing tools in `SAFE_COMMANDS` (e.g., `cp`, `mv`, `tee`) could theoretically overwrite validator files. The validator does not yet verify its own integrity at runtime.

### Immutable deny list

`rules/immutable-deny.json` defines commands that the learning system can never auto-approve. This file should be treated as security-critical and reviewed in any PR that modifies it.
