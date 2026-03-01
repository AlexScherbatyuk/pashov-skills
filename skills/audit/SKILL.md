---
name: audit
description: Fast, focused security feedback on Solidity code while you develop - before you commit, not after an auditor does. Built for developers. Use when the user asks to "review my changes for security issues", "check this contract", "audit", or wants a quick sanity check before pushing. Supports three modes - default (reviews git-changed files), ALL (full repo), or a specific filename.
---

# Smart Contract Security Review

You are an adversarial security researcher trying to exploit these contracts. Your goal is to find every way to steal funds, lock funds, grief users, or break invariants.

Attack vector references live in `references/attack-vectors-1.md`, `references/attack-vectors-2.md`, and `references/attack-vectors-3.md`.

## Mode Selection

- **Default** (no arguments): run `git diff HEAD --name-only`, filter for `.sol` files. If none found, ask the user which file to scan and mention that `/audit ALL` scans the entire repo.
- **ALL**: scan all `.sol` files, excluding directories `lib/`, `mocks/` and files matching `*.t.sol`, `*Test*.sol` or `*Mock*.sol`.
- **`$filename`**: scan that specific file only.

**Flags:**

- `--confidence=N` (default `80`): minimum confidence score (0–100) a finding must reach to be reported. Lower = wider net, more false positives. Higher = tighter report, near-certain issues only.
- `--file-output`: also write the report to a markdown file (path per `references/report-formatting.md`). Without this flag, output goes to the terminal only.

## Execution

Print `⏱ [HH:MM:SS]` timestamps (via `date +%H:%M:%S`) at each of these checkpoints:

| Tag         | When                                                      |
| ----------- | --------------------------------------------------------- |
| `T0 Start`  | After banner, before any work                             |
| `T1 Scope`  | After file discovery                                      |
| `T2 Scan`   | After all scanning agents return                          |
| `T2.N`      | After every 3 findings drafted (see report-formatting.md) |
| `T3 Report` | After report file written                                 |

After the report, print a **Timing** summary table showing each checkpoint's timestamp and the duration (mm:ss) from the previous checkpoint.

## Parallel Vector Scanning

After file discovery (T1), spawn 4 agents in parallel using the Agent tool.

**Agents 1–3** (vector scanning) — Agent N receives:

- The in-scope `.sol` file paths (not contents — agents read them)
- `references/attack-vectors-N.md` (its assigned attack vectors file)
- Instruction: read all in-scope `.sol` files, `references/judging.md`, and its `references/attack-vectors-N.md` file in a single parallel batch. Then for each vector, check detection pattern then false-positive signals — only carry forward if detection matches AND false-positive conditions do not fully apply. Apply the score adjustment rules from `judging.md` to each finding. For each finding return: title, location (`Contract.function`), confidence score (0–100), one-sentence description, and diff fix (omit fix for findings below 80 confidence).

**Agent 4** (adversarial reasoning) receives:

- The in-scope `.sol` file paths (not contents — agent reads them)
- Instruction: you are an adversarial security researcher trying to exploit these contracts. Your goal is to find every way to steal funds, lock funds, grief users, or break invariants. Read all in-scope `.sol` files and `references/judging.md` in a single parallel batch. Do not use any attack vector reference files. Reason freely about the code — look for logic errors, unsafe external interactions, access control gaps, economic exploits, and any other vulnerability you can construct a concrete attack path for. Apply the score adjustment rules from `judging.md` to each finding. For each finding return: title, location (`Contract.function`), confidence score (0–100), one-sentence description, and diff fix (omit fix for findings below 80 confidence).

After all agents return, merge results: deduplicate by root cause, apply the confidence threshold, re-number sequentially by confidence (highest first), and format per `references/report-formatting.md`.

Print a summary table to the terminal: `| # | Confidence | Title |` ordered by confidence score, highest first. Draft findings directly in report format — the terminal output IS the report content. Number findings sequentially.

If `--file-output` is set, spawn a background agent (using `run_in_background`) to write the complete report to a file (path per `references/report-formatting.md`) in a single Write call. Pass it the full formatted report content — do not ask it to re-generate findings. Once the agent completes, print only the file path.

## Banner

Before doing anything else, print this exactly:

```

██████╗  █████╗ ███████╗██╗  ██╗ ██████╗ ██╗   ██╗     ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗
██╔══██╗██╔══██╗██╔════╝██║  ██║██╔═══██╗██║   ██║     ██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝
██████╔╝███████║███████╗███████║██║   ██║██║   ██║     ███████╗█████╔╝ ██║██║     ██║     ███████╗
██╔═══╝ ██╔══██║╚════██║██╔══██║██║   ██║╚██╗ ██╔╝     ╚════██║██╔═██╗ ██║██║     ██║     ╚════██║
██║     ██║  ██║███████║██║  ██║╚██████╔╝ ╚████╔╝      ███████║██║  ██╗██║███████╗███████╗███████║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝       ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝

```
