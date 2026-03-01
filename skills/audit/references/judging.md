# Confidence Scoring

Each finding gets a confidence score from 0–100. Start from a base score reflecting how certain the exploit path is, then apply adjustments:

- Privileged caller required (owner, admin, multisig, governance) → subtract 15.
- Impact is self-contained (attacker's own funds only, unreachable state, narrow subset with no spillover) → subtract 15.
- No direct monetary loss (disruption, griefing, gas waste, incorrect state) → cap at 85.
- Attack path is incomplete (cannot write caller → call sequence → concrete outcome) → subtract 19.

The final score determines the indicator: 🔴 above 90 · 🟡 70–90 · 🔵 below 70.

Findings below the confidence threshold (default 80) are still included in the report table but do not get a **Fix** section — description only.

**Do not report:** Anything a linter, compiler, or seasoned developer would dismiss — INFO-level notes, gas micro-optimizations, naming, NatSpec, redundant comments.
