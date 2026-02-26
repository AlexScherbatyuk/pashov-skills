---
name: lint
description: Lints and cleans Solidity code. Use whenever the user says "lint", "clean up my Solidity", "fix my code style", "add NatSpec", "remove unused imports", or wants their contracts formatted and tidied up. Apply this skill proactively when the user pastes Solidity code that looks messy, has missing documentation, or uses outdated patterns like require strings or bare imports.
---

# Solidity Linter

<context>
Cleans up Solidity code by applying formatting, removing dead weight, adding missing documentation, and enforcing community best practices. The goal is code that is readable, consistent, and professional - without changing any logic.

For the detailed rules behind each check, read `references/rules.md`.
</context>

<instructions>

## Workflow

### 1. Determine Scope

- **No argument**: lint all `.sol` files in `src/` and `contracts/` (excluding `lib/`, `out/`, `node_modules/`)
- **File argument**: lint only that file
- **Directory argument**: lint all `.sol` files in that directory recursively

Read each file fully before making any changes.

### 2. Run `forge fmt` First (if Foundry project)

If `foundry.toml` exists in the project root, run:

```bash
forge fmt
```

This handles mechanical formatting automatically: indentation (4 spaces), line length (120 chars), quote style (double), `uint` -> `uint256`, trailing whitespace, and opening brace placement. Do this first so subsequent edits are applied to already-formatted code.

If Foundry is not present, apply the same formatting rules manually when editing files.

### 3. Apply Linting Passes

Work through each file. Apply fixes in this order - mechanical fixes first, then structural, then documentation.

#### Pass 1 - Imports

- Replace bare imports with named imports: `import "File.sol"` -> `import {Contract} from "File.sol"`
- Remove unused imports: any named import whose symbol never appears in the file body

#### Pass 2 - Unused Code

- Remove unused local variables (compiler already warns about these)
- Rename unused function parameters to unnamed `/* name */` or `_name` convention
- Remove unused private functions (never called internally)
- Remove unused events (never emitted)
- Remove unused custom errors (never reverted with)
- Remove unused modifiers (never applied)

#### Pass 3 - Naming Conventions

Check and fix (see `references/rules.md` § Naming for full details):
- Contracts, structs, enums, events, errors: `PascalCase`
- Interfaces: must start with `I` (e.g., `IVault`, `IERC20`)
- Functions, local variables, parameters: `camelCase`
- Private/internal state variables and functions: `_camelCase`
- Constants and immutables: `UPPER_CASE_WITH_UNDERSCORES`

#### Pass 4 - Visibility and Types

- Add explicit visibility to any state variable or function missing it
- Apply principle of least privilege: `private` over `internal` when inheritance is not needed
- Replace `uint` with `uint256`, `int` with `int256` (if `forge fmt` hasn't done this already)

#### Pass 5 - `require` -> Custom Errors

Replace `require(condition, "message")` with the custom error pattern:

```solidity
// Before
require(balance >= amount, "Insufficient balance");

// After - define error at contract level
error InsufficientBalance(uint256 available, uint256 required);

// In function body
if (balance < amount) revert InsufficientBalance(balance, amount);
```

Add parameters to the custom error only when they provide useful diagnostic info. A parameterless error is fine when the condition is self-explanatory.

Do NOT convert `require` calls in test files or scripts - only `src/` / `contracts/`.

#### Pass 6 - `memory` -> `calldata` for External Functions

For `external` functions only, change reference-type parameters (`string`, `bytes`, arrays, structs) from `memory` to `calldata` when the function body does not modify them.

Does not apply to `public` functions (which can be called internally and need `memory`).

#### Pass 7 - Magic Numbers

Replace unexplained numeric literals with named constants:

```solidity
// Before
require(fee <= 1000);
uint256 reward = amount * 500 / 10000;

// After
uint256 private constant MAX_FEE_BPS = 1_000;
uint256 private constant DEFAULT_FEE_BPS = 500;
uint256 private constant BASIS_POINTS = 10_000;
```

Use Solidity time and ether units (`7 days`, `0.1 ether`) instead of raw numbers where applicable. Skip `0`, `1`, obvious array indices, and similarly self-evident literals.

#### Pass 8 - Declaration Ordering

Within each contract, ensure this order:

1. `using` statements
2. Constants
3. Immutables
4. Other state variables
5. Events
6. Custom errors
7. Modifiers
8. Constructor
9. `receive` / `fallback`
10. External functions
11. Public functions
12. Internal functions
13. Private functions

Only reorder if significantly out of order. Minor deviations can be flagged in the summary rather than reordered, to minimize diff noise.

#### Pass 9 - NatSpec

Add missing NatSpec. Read `references/rules.md` § NatSpec for the full tag spec and examples.

**External and public functions** - add:
- `@notice` - what the function does (plain English, one sentence)
- `@param <name>` - one per parameter
- `@return` - one per return value (skip if void)

**Contracts and interfaces** - add:
- `@title` - one-line name
- `@notice` - what the contract does

**Internal/private functions** - add `@dev` when behavior, preconditions, or invariants are non-obvious.

**Events** - add `@notice` (when emitted) and `@param` per parameter.

**Custom errors** - add `@notice` (when reverted).

**Public state variables** - add `@notice` (they have compiler-generated getters).

If a function has `@inheritdoc`, do not add other tags.

</instructions>

<output_format>
After all passes:

```
## Lint Complete

Files processed: N
Changes made: M

### Changes by file

**src/Vault.sol**
- [imports] Replaced 2 bare imports with named imports; removed 1 unused import
- [unused] Removed unused modifier `onlyLegacy`; removed unused event `Deprecated`
- [naming] Renamed constant `maxSupply` -> `MAX_SUPPLY`
- [visibility] Added explicit visibility to 3 state variables
- [errors] Converted 4 `require` strings to custom errors
- [calldata] Changed 2 `memory` params to `calldata` in external functions
- [ordering] Moved Events section above Modifiers
- [natspec] Added NatSpec to 6 external functions

### No changes needed
- src/libraries/MathLib.sol
```
</output_format>

<constraints>
- Never change logic - only style and documentation
- Never remove code that looks intentionally kept for storage layout in upgradeable contracts; flag it in the summary with a note instead
- Respect `// solhint-disable` and `// forge-fmt:off` directives
- Test files and scripts: apply import and formatting fixes, but skip NatSpec and error conversion unless explicitly asked
</constraints>
