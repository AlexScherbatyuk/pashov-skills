# Attack Vectors Reference (2/3 — Vectors 46–89)

126 total attack vectors. For each: detection pattern and false-positive signals.

---

**46. Missing Chain ID Validation in Deployment Configuration**

- **D:** Deploy script reads `$RPC_URL` from `.env` without `eth_chainId` assertion. Foundry script without `--chain-id` flag or `block.chainid` check. No dry-run before broadcast.
- **FP:** `require(block.chainid == expectedChainId)` at script start. CI validates chain ID before deployment.

**47. Missing or Incorrect Access Modifier**

- **D:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `pause`, `setOracle`) has no access guard or modifier references uninitialized variable. `public`/`external` on privileged operations with no restriction.
- **FP:** Function is intentionally permissionless with non-critical worst-case outcome (e.g., advancing a public time-locked process).

**48. Blacklistable or Pausable Token in Critical Payment Path**

- **D:** Push-model transfer `token.transfer(recipient, amount)` with USDC/USDT or other blacklistable token. Blacklisted recipient reverts entire function, DOSing withdrawals/liquidations/fees.
- **FP:** Pull-over-push pattern (recipients withdraw own funds). Skip-on-failure `try/catch` on fee distribution. Token whitelist excludes blacklistable tokens.

**49. Missing chainId (Cross-Chain Replay)**

- **D:** Signed payload omits `chainId`. Valid signature replayable on forks/other EVM chains. Or `chainId` hardcoded at deployment instead of `block.chainid`.
- **FP:** EIP-712 domain separator includes dynamic `chainId: block.chainid` and `verifyingContract`.

**50. Merkle Tree Second Preimage Attack**

- **D:** `MerkleProof.verify(proof, root, leaf)` where leaf derived from user input without double-hashing or type-prefixing. 64-byte input (two sibling hashes) passes as intermediate node.
- **FP:** Leaves double-hashed or include type prefix. Input length enforced != 64 bytes. OZ MerkleProof >= v4.9.2 with sorted-pair variant.

**51. Missing onERC1155BatchReceived Causes Token Lock**

- **D:** Contract implements `onERC1155Received` but not `onERC1155BatchReceived` (or returns wrong selector). `safeBatchTransferFrom` reverts, blocking batch settlement/distribution.
- **FP:** Both callbacks implemented correctly, or inherits OZ `ERC1155Holder`. Protocol exclusively uses single-item `safeTransferFrom`.

**52. ERC4626 Preview Rounding Direction Violation**

- **D:** `previewDeposit` returns more shares than `deposit` mints, or `previewMint` charges fewer assets than `mint`. Custom `_convertToShares`/`_convertToAssets` with wrong `Math.mulDiv` rounding direction.
- **FP:** OZ ERC4626 base without overriding conversion functions. Custom impl explicitly uses `Floor` for share issuance, `Ceil` for share burning.

**53. ERC721 Unsafe Transfer to Non-Receiver**

- **D:** `_transfer()`/`_mint()` used instead of `_safeTransfer()`/`_safeMint()`, sending NFTs to contracts without `IERC721Receiver`. Tokens permanently locked.
- **FP:** All paths use `safeTransferFrom`/`_safeMint`. Function is `nonReentrant`.

**54. Multi-Block TWAP Oracle Manipulation**

- **D:** TWAP observation window < 30 minutes. Post-Merge validators controlling consecutive blocks can hold manipulated AMM state across blocks, shifting TWAP cheaply.
- **FP:** TWAP window >= 30 min. Chainlink/Pyth as price source. Max-deviation circuit breaker against secondary source.

**55. Spot Price Oracle from AMM**

- **D:** Price from AMM reserves: `reserve0 / reserve1`, `getAmountsOut()`, `getReserves()`. Flash-loan exploitable atomically.
- **FP:** TWAP >= 30 min window. Chainlink/Pyth as primary source.

**56. Delegatecall to Untrusted Callee**

- **D:** `address(target).delegatecall(data)` where `target` is user-provided or unconstrained.
- **FP:** `target` is hardcoded immutable verified library address.

**57. ERC1155 setApprovalForAll Grants All-Token-All-ID Access**

- **D:** Protocol requires `setApprovalForAll(protocol, true)` for deposits/staking. No per-ID or per-amount granularity -- operator can transfer any ID at full balance.
- **FP:** Protocol uses direct `safeTransferFrom` with user as `msg.sender`. Operator is immutable contract with escrow-only transfer logic.

**58. ERC-1271 isValidSignature Delegated to Untrusted Module**

- **D:** `isValidSignature(hash, sig)` delegated to externally-supplied contract without whitelist check. Malicious module always returns `0x1626ba7e`, passing all signature checks.
- **FP:** Delegation only to owner-controlled whitelist. Module registry has timelock/guardian approval.

---

**59. Uninitialized Implementation Takeover**

- **D:** Implementation behind proxy has `initialize()` but constructor lacks `_disableInitializers()`. Attacker calls `initialize()` on implementation directly, becomes owner, can upgrade to malicious contract. Ref: Wormhole (2022), Parity (2017).
- **FP:** Constructor contains `_disableInitializers()`. OZ `Initializable` correctly gates the function. Not behind a proxy (standalone).

**60. Cross-Function Reentrancy**

- **D:** Two functions share state variable. Function A makes external call before updating shared state; Function B reads that state. `nonReentrant` on A but not B.
- **FP:** Both functions share same contract-level mutex. Shared state updated before any external call.

**61. Flash Loan Governance Attack**

- **D:** Voting uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block). Borrow tokens, vote, repay in one tx.
- **FP:** `getPastVotes(account, block.number - 1)` used. Timelock between snapshot and vote.

**62. Paymaster Gas Penalty Undercalculation**

- **D:** Paymaster prefund formula omits 10% EntryPoint penalty on unused execution gas (`postOpUnusedGasPenalty`). Large `executionGasLimit` with low usage drains paymaster deposit.
- **FP:** Prefund explicitly adds unused-gas penalty. Conservative overestimation covers worst case.

**63. Nested Mapping Inside Struct Not Cleared on `delete`**

- **D:** `delete myMapping[key]` on struct containing `mapping` or dynamic array. `delete` zeroes primitives but not nested mappings. Reused key exposes stale values.
- **FP:** Nested mapping manually cleared before `delete`. Key never reused after deletion.

**64. Block Number as Timestamp Approximation**

- **D:** Time computed as `(block.number - startBlock) * 13` assuming fixed block times. Variable across chains/post-Merge. Wrong interest/vesting/rewards.
- **FP:** `block.timestamp` used for all time-sensitive calculations.

**65. Non-Standard ERC20 Return Values (USDT-style)**

- **D:** `require(token.transfer(to, amount))` reverts on tokens returning nothing (USDT, BNB). Or return value ignored (silent failure).
- **FP:** OZ `SafeERC20.safeTransfer()`/`safeTransferFrom()` used throughout.

---

**68. ecrecover Returns address(0) on Invalid Signature**

- **D:** Raw `ecrecover` without `require(recovered != address(0))`. If `authorizedSigner` is uninitialized or `permissions[address(0)]` is non-zero, garbage signature gains privileges.
- **FP:** OZ `ECDSA.recover()` used (reverts on address(0)). Explicit zero-address check present.

**69. ERC1155 Custom Burn Without Caller Authorization**

- **D:** Public `burn(address from, uint256 id, uint256 amount)` callable by anyone without verifying `msg.sender == from` or operator approval. Any caller burns another user's tokens.
- **FP:** `require(from == msg.sender || isApprovedForAll(from, msg.sender))` before `_burn`. OZ `ERC1155Burnable` used.

**70. Re-initialization Attack**

- **D:** V2 uses `initializer` instead of `reinitializer(2)`. Or upgrade resets initialized counter / storage-collides bool to false. Ref: AllianceBlock (2024).
- **FP:** `reinitializer(version)` with correctly incrementing versions for V2+. Tests verify `initialize()` reverts after first call.

**71. UUPS `_authorizeUpgrade` Missing Access Control**

- **D:** `function _authorizeUpgrade(address) internal override {}` with empty body and no access modifier. Anyone can call `upgradeTo()`. Ref: CVE-2021-41264.
- **FP:** `_authorizeUpgrade()` has `onlyOwner` or equivalent. Multisig/governance controls owner role.

**72. Small-Type Arithmetic Overflow Before Upcast**

- **D:** Arithmetic on `uint8`/`uint16`/`uint32` before assigning to wider type: `uint256 result = a * b` where `a`,`b` are `uint8`. Overflow happens in narrow type before widening. Solidity 0.8 overflow check is still on the narrow type.
- **FP:** Operands explicitly upcast before operation: `uint256(a) * uint256(b)`. SafeCast used.

**73. ERC1155 uri() Missing {id} Substitution**

- **D:** `uri(uint256 id)` returns fully resolved URL instead of template with literal `{id}` placeholder per EIP-1155. Clients expect to substitute zero-padded hex ID client-side. Static/empty return collapses all token metadata.
- **FP:** Returns string containing literal `{id}`. Or per-ID on-chain URI with documented deviation from substitution spec.

**74. EIP-2612 Permit Front-Run DoS**

- **D:** `token.permit(...)` called inline in combined permit-and-action function without `try/catch`. Anyone can submit same permit first, incrementing nonce. Victim's subsequent call reverts permanently.
- **FP:** Permit wrapped in `try/catch`, falls through to pre-existing allowance. Permit is standalone call separate from action.

**75. ERC4626 Caller-Dependent Conversion Functions**

- **D:** `convertToShares()`/`convertToAssets()` branches on `msg.sender`-specific state (per-user fees, whitelist, balances). EIP-4626 requires caller-independence. Downstream aggregators get wrong sizing.
- **FP:** Implementation reads only global vault state (`totalSupply`, `totalAssets`, protocol-wide fee constants).

**76. Non-Atomic Proxy Initialization (Front-Running `initialize()`)**

- **D:** Proxy deployed in one tx, `initialize()` called in separate tx. Uninitialized proxy front-runnable. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty data, separate `initialize()`. Ref: Wormhole (2022).
- **FP:** Proxy constructor receives init calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(...))`. OZ `deployProxy()` used.

**77. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **D:** Same non-atomic deploy+init pattern as V76, but attacker inserts malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in ERC-1967 slot.
- **FP:** Atomic init calldata in constructor. `_disableInitializers()` in implementation constructor.

**78. Unsafe Downcast / Integer Truncation**

- **D:** `uint128(largeUint256)` without bounds check. Solidity >= 0.8 silently truncates on downcast (no revert). Dangerous in price feeds, share calculations, timestamps.
- **FP:** `require(x <= type(uint128).max)` before cast. OZ `SafeCast` used.

**79. ERC721 onERC721Received Arbitrary Caller Spoofing**

- **D:** `onERC721Received` uses parameters (`from`, `tokenId`) to update state without verifying `msg.sender` is the expected NFT contract. Anyone calls directly with fabricated parameters.
- **FP:** `require(msg.sender == address(nft))` before state update. Function is view-only or reverts unconditionally.

**80. Storage Layout Shift on Upgrade**

- **D:** V2 inserts new state variable in middle of contract instead of appending. Subsequent variables shift slots, corrupting state. Also: changing variable type between versions shifts slot boundaries.
- **FP:** New variables only appended. OZ storage layout validation in CI. Variable types unchanged between versions.

**81. Return Bomb (Returndata Copy DoS)**

- **D:** `(bool success, bytes memory data) = target.call(payload)` where `target` is user-supplied. Malicious target returns huge returndata; copying costs enormous gas.
- **FP:** Returndata not copied (assembly call without copy, or gas-limited). Callee is hardcoded trusted contract.

**82. Proxy Admin Key Compromise**

- **D:** `ProxyAdmin.owner()` returns EOA, not multisig/governance; no timelock on `upgradeTo`. Ref: PAID Network (2021), Ankr (2022).
- **FP:** Multisig (threshold >= 2) + timelock (24-72h). Admin role separate from operational roles.

**83. Improper Flash Loan Callback Validation**

- **D:** `onFlashLoan` callback doesn't verify `msg.sender == lendingPool`, or doesn't check `initiator`/`token`/`amount`. Callable directly without real flash loan.
- **FP:** Both `msg.sender == address(lendingPool)` and `initiator == address(this)` validated. Token/amount checked.

**84. ERC721 / ERC1155 Type Confusion in Dual-Standard Marketplace**

- **D:** Shared `buy`/`fill` function uses type flag for ERC721/ERC1155. `quantity` accepted for ERC721 without requiring == 1. `price * quantity` with `quantity = 0` yields zero payment. Ref: TreasureDAO (2022).
- **FP:** ERC721 branch `require(quantity == 1)`. Separate code paths for ERC721/ERC1155.

---

**85. Governance Flash-Loan Upgrade Hijack**

- **D:** Proxy upgrades via governance using current-block vote weight (`balanceOf` or `getPastVotes(block.number)`). No voting delay or timelock. Flash-borrow, vote, execute upgrade in one tx.
- **FP:** `getPastVotes(block.number - 1)`. Timelock 24-72h. High quorum thresholds. Staking lockup required.

**86. DoS via Unbounded Loop**

- **D:** Loop over user-growable unbounded array: `for (uint i = 0; i < users.length; i++)`. Eventually hits block gas limit.
- **FP:** Array length capped at insertion: `require(arr.length < MAX)`. Loop iterates fixed small constant.

**87. ERC4626 Deposit/Withdraw Share-Count Asymmetry**

- **D:** `_convertToShares` uses `Rounding.Floor` for both deposit and withdraw paths. `withdraw(a)` burns fewer shares than `deposit(a)` minted, manufacturing free shares. Single rounding helper called on both paths without distinct rounding args.
- **FP:** `deposit` uses `Floor`, `withdraw` uses `Ceil` (vault-favorable both directions). OZ ERC4626 without custom conversion overrides.

**88. Diamond Proxy Cross-Facet Storage Collision**

- **D:** EIP-2535 Diamond facets declare storage variables without EIP-7201 namespaced storage. Multiple facets independently start at slot 0, writing to same slots.
- **FP:** All facets use single `DiamondStorage` struct at namespaced position (EIP-7201). No top-level state variables in facets.

**89. Cross-Contract Reentrancy**

- **D:** Two contracts share logical state (balances in A, collateral check in B). A makes external call before syncing state B reads. A's `ReentrancyGuard` doesn't protect B.
- **FP:** State B reads is synchronized before A's external call. No re-entry path from A's callee into B.
