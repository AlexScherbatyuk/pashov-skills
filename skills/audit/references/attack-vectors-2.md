# Attack Vectors Reference (2/3 — Vectors 46–85)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

## Core (continued)

**46. Griefing via Dust Deposits Resetting Timelocks or Cooldowns**

- **Detect:** Time-based lock, cooldown, or delay is reset on any deposit or interaction with no minimum-amount guard: `lastActionTime[user] = block.timestamp` inside a `deposit(uint256 amount)` with no `require(amount >= MIN_AMOUNT)`. Attacker calls `deposit(1)` repeatedly, just before the victim's lock expires, resetting the cooldown indefinitely at negligible cost. Variant: vault that checks `totalSupply > 0` before first depositor can join — attacker donates 1 wei to permanently inflate the share price and trap subsequent depositors; or a contract guarded by `require(address(this).balance > threshold)` that the attacker manipulates by sending dust.
- **FP:** Minimum deposit enforced unconditionally: `require(amount >= MIN_DEPOSIT)`. Cooldown reset only for the depositing user, not system-wide. Time lock assessed independently of deposit amounts on a per-user basis.

**47. Insufficient Gas Forwarding / 63/64 Rule Exploitation**

- **Detect:** Contract forwards an external call without enforcing a minimum gas budget: `target.call(data)` (no explicit gas) or `target.call{gas: userProvidedGas}(data)`. The EVM's 63/64 rule means the callee receives at most 63/64 of the remaining gas. In meta-transaction and relayer patterns, a malicious relayer provides just enough gas for the outer function to complete but not enough for the subcall to succeed. The subcall returns `(false, "")` — which the outer function may misread as a business-logic rejection, marking the user's transaction as "processed" while the actual effect never happened. Silently censors user intent while consuming their allocated gas/fee.
- **FP:** `gasleft()` validated against a minimum threshold before the subcall: `require(gasleft() >= minGas)`. Return value and return data both checked after the call. Relayer pattern uses EIP-2771 with a verified gas parameter that the recipient contract re-validates.

**48. Chainlink Feed Deprecation / Wrong Decimal Assumption**

- **Detect:** (a) Chainlink aggregator address is hardcoded in the constructor or an immutable with no admin path to update it. When Chainlink deprecates the feed and migrates to a new aggregator contract, the protocol continues reading from the frozen old feed, which may return a stale or zeroed price indefinitely. (b) Price normalization assumes `feed.decimals() == 8` (common for USD feeds) without calling `feed.decimals()` at runtime. Some feeds (e.g., ETH/ETH) return 18 decimals — the 10^10 scaling discrepancy produces wildly wrong collateral values, enabling instant over-borrowing or mass liquidations.
- **FP:** Feed address is updatable via a governance-gated setter. `feed.decimals()` called and stored; used to normalize `latestRoundData().answer` before any arithmetic. Deviation check against a secondary oracle rejects anomalous values.

**49. Fee-on-Transfer Token Accounting**

- **Detect:** Deposit recorded as `deposits[user] += amount` then `transferFrom(..., amount)`. Fee-on-transfer tokens (SAFEMOON, STA) cause the contract to receive `amount - fee` but record `amount`. Subsequent withdrawals drain other users.
- **FP:** Balance measured before/after transfer: `uint256 before = token.balanceOf(this); token.transferFrom(...); uint256 received = token.balanceOf(this) - before;` and `received` used for accounting.

**50. Rebasing / Elastic Supply Token Accounting**

- **Detect:** Contract holds rebasing tokens (stETH, AMPL, aTokens) and caches `token.balanceOf(this)` in a state variable used for future accounting. After a rebase, cached value diverges from actual balance.
- **FP:** Protocol enforces at the code level that rebasing tokens cannot be deposited (explicit revert or whitelist). Accounting always reads `balanceOf` live. Wrapper tokens (wstETH) used instead.

**51. ERC20 Non-Compliant: Return Values / Events**

- **Detect:** Custom `transfer()`/`transferFrom()` doesn't return `bool`, or always returns `true` on failure. `mint()` missing `Transfer(address(0), to, amount)` event. `burn()` missing `Transfer(from, address(0), amount)`. `approve()` missing `Approval` event. Breaks DEX and wallet composability.
- **FP:** OpenZeppelin `ERC20.sol` used as base with no custom overrides of the transfer/approve/event logic.

**52. Non-Standard ERC20 Return Values (USDT-style)**

- **Detect:** `require(token.transfer(to, amount))` reverts on tokens that return nothing (USDT, BNB). Or return value ignored entirely (silent failure on failed transfer). (SWC-104)
- **FP:** OpenZeppelin `SafeERC20.safeTransfer()`/`safeTransferFrom()` used throughout.

**53. Blacklistable or Pausable Token in Critical Payment Path**

- **Detect:** Protocol hard-codes or accepts USDC, USDT, or another token with admin-controlled blacklisting or global pause, and routes payments through a push model: `token.transfer(recipient, amount)`. If `recipient` is blacklisted by the token issuer, or the token is globally paused, every push to that address reverts — permanently bricking withdrawals, liquidations, fee collection, or reward claims. Attacker can weaponize this by ensuring a critical address (vault, fee receiver, required counterparty) is blacklisted. Also relevant: protocol sends fee to a fixed `feeRecipient` inside a state-changing function — if `feeRecipient` is blacklisted, the entire function is permanently DOSed.
- **FP:** Pull-over-push: recipients withdraw their own funds; a blacklisted recipient only blocks themselves. Skip-on-failure logic (`try/catch`) used for fee or reward distribution. Supported token whitelist explicitly excludes blacklistable/pausable tokens.

**54. EIP-2612 Permit Front-Run Causing DoS**

- **Detect:** Contract calls `token.permit(owner, spender, value, deadline, v, r, s)` inline as part of a combined permit-and-action function, with no `try/catch` around the permit call. The same permit signature can be submitted by anyone — if an attacker (or MEV bot) front-runs by submitting the permit signature first, the nonce is incremented; the subsequent victim transaction's inline `permit()` call then reverts (wrong nonce), causing the entire action to fail. Because the user only has the one signature, they may be permanently blocked from that code path.
- **FP:** Permit wrapped in `try { token.permit(...); } catch {}` — falls through and relies on pre-existing allowance if permit already consumed. Permit is a standalone user call; the main action function only calls `transferFrom` (not combined).

**55. ERC777 tokensToSend / tokensReceived Reentrancy**

- **Detect:** Contract calls `transfer()` or `transferFrom()` on a token that may implement ERC777 (registered via ERC1820 registry) before completing state updates. ERC777 fires a `tokensToSend` hook on the sender's registered hook contract and a `tokensReceived` hook on the recipient's — these callbacks trigger on plain ERC20-style `transfer()` calls, not just ETH. A recipient's `tokensReceived` or sender's `tokensToSend` can re-enter the calling contract before balances are updated. Pattern: `token.transferFrom(msg.sender, address(this), amount)` followed by state updates, or `token.transfer(user, amount)` before clearing user balance, with no `nonReentrant` guard and no ERC777 exclusion.
- **FP:** Strict CEI — all state committed before any token transfer. `nonReentrant` applied to all public entry points. Protocol enforces a token whitelist that explicitly excludes ERC777-compatible tokens.

**56. Token Decimal Mismatch in Cross-Token Arithmetic**

- **Detect:** Protocol multiplies or divides token amounts using a hardcoded `1e18` denominator or assumes all tokens share the same decimals. USDC has 6 decimals, WETH has 18 — a formula like `price = usdcAmount * 1e18 / wethAmount` is off by 1e12. Pattern: collateral ratio, LTV, interest rate, or exchange rate calculations that combine two tokens' amounts with no per-token decimal normalization. `token.decimals()` is never called, or is called but its result is not used in scaling factors.
- **FP:** All amounts normalized to a canonical precision (WAD/RAY) immediately after transfer, using each token's actual `decimals()`. Explicit normalization factor `10 ** (18 - token.decimals())` applied per token before any cross-token arithmetic. Protocol only supports tokens with identical, verified decimals.

**57. Zero-Amount Transfer Revert Breaking Distribution Logic**

- **Detect:** Contract calls `token.transfer(recipient, amount)` or `token.transferFrom(from, to, amount)` where `amount` can be zero — e.g., when fees round to 0, a user claims before any yield accrues, or a distribution loop pays out a zero share. Some non-standard ERC20 tokens (LEND, early BNB, certain stablecoins) include `require(amount > 0)` in their transfer logic and revert on zero-amount calls. Any fee distribution loop, reward claim, or conditional-payout path that omits a `if (amount > 0)` guard will permanently DoS on these tokens.
- **FP:** All transfer calls are preceded by `if (amount > 0)` or `require(amount > 0)`. Protocol enforces a minimum claim/distribution amount upstream. Supported token whitelist only includes tokens verified to accept zero-amount transfers (OZ ERC20 base allows them).

**58. Stale Cached ERC20 Balance from Direct Token Transfers**

- **Detect:** Contract tracks token holdings in a state variable (`totalDeposited`, `_reserves`, `cachedBalance`) that is only updated through the protocol's own deposit/receive functions. The actual `token.balanceOf(address(this))` can exceed the cached value via direct `token.transfer(contractAddress, amount)` calls made outside the protocol's accounting flow. When protocol logic uses the cached variable — not `balanceOf` live — for share pricing, collateral ratios, or withdrawal limits, an attacker donates tokens directly to inflate actual holdings, then exploits the gap between cached and real state (inflated share price, under-collateralized accounting). Distinct from ERC4626 first-depositor inflation attack (see Vector 86): applies to any contract with split accounting, not just vaults.
- **FP:** All accounting reads `token.balanceOf(address(this))` live — no cached balance variable used in financial math. Cached value is reconciled against `balanceOf` at the start of every state-changing function. Direct token transfers are explicitly considered in the accounting model (e.g., treated as protocol revenue, not phantom deposits).

**59. Merkle Tree Second Preimage Attack**

- **Detect:** `MerkleProof.verify(proof, root, leaf)` where the leaf is derived from variable-length or 32-byte user-supplied input without double-hashing or type-prefixing. An attacker can pass a 64-byte value (concatenation of two sibling hashes at an intermediate node) as if it were a leaf — the standard hash tree produces the same root, so verification passes with a shorter proof. Pattern: `leaf = keccak256(abi.encodePacked(account, amount))` without an outer hash or prefix; no length restriction enforced on leaf inputs.
- **FP:** Leaves are double-hashed (`keccak256(keccak256(data))`). Leaf includes a type prefix or domain tag that intermediate nodes cannot satisfy. Input length enforced to be ≠ 64 bytes. OpenZeppelin MerkleProof ≥ v4.9.2 with `processProofCalldata` or sorted-pair variant used correctly.

**60. Merkle Proof Reuse — Leaf Not Bound to Caller**

- **Detect:** Merkle proof accepted without tying the leaf to `msg.sender`. Pattern: `require(MerkleProof.verify(proof, root, keccak256(abi.encodePacked(amount))))` or leaf contains only an address that is not checked against `msg.sender`. Anyone who observes the proof in the mempool can front-run and claim the same entitlement by submitting it from a different address.
- **FP:** Leaf explicitly encodes the caller: `keccak256(abi.encodePacked(msg.sender, amount))`. Function validates that the leaf's embedded address equals `msg.sender` before acting. Proof is single-use and recorded as consumed after the first successful call.

**61. Diamond Proxy Cross-Facet Storage Collision**

- **Detect:** EIP-2535 Diamond proxy where two or more facets declare storage variables without EIP-7201 namespaced storage structs — each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, …. Different facets independently start at slot 0, so both write to the same slot. Also flag: facet uses a library that writes to storage without EIP-7201 namespacing.
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**62. Nested Mapping Inside Struct Not Cleared on `delete`**

- **Detect:** `delete myMapping[key]` or `delete myArray[i]` where the deleted item is a struct containing a `mapping` or a dynamic array. Solidity's `delete` zeroes primitive fields but does not recursively clear mappings — the nested mapping's entries persist in storage. If the same key is later reused (e.g., a re-deposited user, re-created proposal), old mapping values are unexpectedly visible. Pattern: struct with `mapping(address => uint256)` or `uint256[]` field; `delete` called on the struct without manually iterating and clearing the nested mapping.
- **FP:** Nested mapping manually cleared before `delete` (iterate and zero every entry). Struct key is never reused after deletion. Codebase explicitly accounts for residual mapping values in subsequent reads (always initialises before use).

**63. Small-Type Arithmetic Overflow Before Upcast**

- **Detect:** Arithmetic expression operates on `uint8`, `uint16`, `uint32`, `int8`, or other sub-256-bit types before the result is assigned to a wider type. Pattern: `uint256 result = a * b` where `a` and `b` are `uint8` — multiplication executes in `uint8` and overflows silently (wraps mod 256) before widening. Also: ternary returning a small literal `(condition ? 1 : 0)` inferred as `uint8`; addition `uint16(x) + uint16(y)` assigned to `uint32`. Underflow possible for signed sub-types.
- **FP:** Each operand is explicitly upcast before the operation: `uint256(a) * uint256(b)`. SafeCast used. Solidity 0.8+ overflow protection applies only within the type of the expression — if both operands are `uint8`, the check is still on `uint8` range, not `uint256`.

**64. Front-Running Exact-Zero Balance Check with Dust Transfer**

- **Detect:** An `external` or `public` function contains `require(token.balanceOf(address(this)) == 0)`, `require(address(this).balance == 0)`, or any strict equality check against a zero balance that gates a state transition (e.g., starting an auction, initializing a pool, opening a deposit round). An attacker front-runs the legitimate caller's transaction by sending a dust amount of the token or ETH to the contract, making the balance non-zero and causing the victim's transaction to revert. The attack is repeatable at negligible cost, creating a permanent DoS on the guarded function. Distinct from Vector 39 (force-feeding ETH to break invariants) — this targets the zero-check gate itself as a griefing/DoS vector rather than inflating a balance used in financial math.
- **FP:** Check uses `<=` threshold instead of `== 0` (e.g., `require(balance <= DUST_THRESHOLD)`). Function is access-controlled so only a trusted caller can trigger it. Balance is tracked via an internal accounting variable that ignores direct transfers, not via `balanceOf` or `address(this).balance`.

---

## ERC721

**65. ERC721 Unsafe Transfer to Non-Receiver**

- **Detect:** `_transfer()` (unsafe) used instead of `_safeTransfer()`, or `_mint()` instead of `_safeMint()`, sending NFTs to contracts that may not implement `IERC721Receiver`. Tokens permanently locked in the recipient contract.
- **FP:** All transfer and mint paths use `safeTransferFrom` or `_safeMint`, which perform the `onERC721Received` callback check. Function is `nonReentrant` to prevent callback abuse.

**66. ERC721 onERC721Received Arbitrary Caller Spoofing**

- **Detect:** Contract implements `onERC721Received` and uses its parameters (`operator`, `from`, `tokenId`) to update state — recording ownership, incrementing counters, or crediting balances — without verifying that `msg.sender` is the expected NFT contract address. Anyone can call `onERC721Received(attacker, victim, fakeTokenId, "")` directly with fabricated parameters, fooling the contract into believing it received an NFT it never got. Pattern: `function onERC721Received(...) { credited[from][tokenId] = true; }` with no `require(msg.sender == nftContract)`.
- **FP:** `msg.sender` is validated against a known NFT contract address before any state update: `require(msg.sender == address(nft))`. The function is `view` or reverts unconditionally (acts as a sink only). State changes are gated on verifiable on-chain ownership (`IERC721(msg.sender).ownerOf(tokenId) == from`) before committing.

**67. ERC721 Approval Not Cleared in Custom Transfer Override**

- **Detect:** Contract overrides `transferFrom` or `safeTransferFrom` with custom logic — fee collection, royalty payment, access checks — but does not call `super._transfer()` or `super.transferFrom()` internally. OpenZeppelin's `_transfer` is the function that executes `delete _tokenApprovals[tokenId]`. Skipping it leaves the previous approved address permanently approved on the token under the new owner. Pattern: custom `transferFrom` that calls a bespoke `_transferWithFee(from, to, tokenId)` without the approval-clear step.
- **FP:** Custom override calls `super.transferFrom(from, to, tokenId)` or `super._transfer(from, to, tokenId)` internally, preserving OZ's approval clearing. Or explicitly calls `delete _tokenApprovals[tokenId]` / `_approve(address(0), tokenId, owner)` before returning.

**68. ERC721Enumerable Index Corruption on Burn or Transfer**

- **Detect:** Contract extends `ERC721Enumerable` and overrides `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling the corresponding `super` function. `ERC721Enumerable` maintains four interdependent index structures (`_ownedTokens`, `_ownedTokensIndex`, `_allTokens`, `_allTokensIndex`) that must be updated atomically on every mint, burn, and transfer. Skipping the super call leaves stale entries — `tokenOfOwnerByIndex` returns wrong token IDs, `ownerOf` for enumerable lookups resolves incorrectly, and `totalSupply` diverges from actual supply.
- **FP:** Override always calls `super._beforeTokenTransfer(from, to, tokenId, batchSize)` or `super._update(to, tokenId, auth)` as its first statement. Contract does not inherit `ERC721Enumerable` and tracks supply independently.

**69. EIP-2981 Royalty Signaled But Never Enforced**

- **Detect:** Contract implements `IERC2981.royaltyInfo(tokenId, salePrice)` and `supportsInterface(0x2a55205a)` returns `true`, advertising royalty support. However, the protocol's own transfer, listing, or settlement logic never calls `royaltyInfo()` and never routes payment to the royalty recipient. EIP-2981 is a signaling standard — it cannot force payment. Any marketplace that does not voluntarily query and pay royalties will bypass them entirely. Pattern: `royaltyInfo()` implemented, but `transferFrom` and all settlement paths contain no corresponding payment call.
- **FP:** Protocol's own marketplace or settlement contract reads `royaltyInfo()` and transfers the royalty amount to the recipient before or after completing the sale — enforced on-chain. Royalties are intentionally zero (`royaltyBps = 0`) and this is documented.

**70. ERC721A / Lazy Ownership — ownerOf Uninitialized in Batch Range**

- **Detect:** Contract uses ERC721A (or OpenZeppelin `ERC721Consecutive`) for gas-efficient batch minting. Ownership is stored lazily: only the first token of a consecutive run has its ownership struct written; all subsequent IDs in the range inherit it by binary search. Before any transfer occurs, `ownerOf(id)` for IDs in the middle of a batch may return `address(0)` or the batch-start owner depending on implementation version. Access control that calls `ownerOf(tokenId) == msg.sender` on freshly minted tokens without an explicit transfer may fail or return incorrect results. Pattern: `require(ownerOf(tokenId) == msg.sender)` in a staking or approval function called immediately after a batch mint.
- **FP:** Protocol always waits for an explicit `transferFrom` or `safeTransferFrom` before checking ownership (each transfer initializes the packed slot). Contract uses standard OZ `ERC721` where every mint writes `_owners[tokenId]` directly.

**71. setApprovalForAll Grants Permanent Unlimited Operator Access**

- **Detect:** Protocol requires users to call `nft.setApprovalForAll(protocol, true)` to enable staking, escrow, or any protocol-managed transfer. This grants the operator irrevocable, time-unlimited control over every current and future token the user holds in that collection. No expiry, no per-token scoping, and no per-amount limit. If the approved operator contract is exploited, upgraded maliciously, or its admin key is compromised, an attacker can drain all tokens from all users who granted approval in a single sweep. Pattern: `require(nft.isApprovedForAll(msg.sender, address(this)), "must approve")` at the entry point of a staking or escrow function.
- **FP:** Protocol uses individual `approve(address(this), tokenId)` before each transfer, requiring per-token user action. Operator is an immutable non-upgradeable contract with a formally verified transfer function. Protocol provides an on-chain `revokeAll()` helper users are trained to call after each interaction.

**72. ERC721 transferFrom with Unvalidated `from` Parameter**

- **Detect:** Custom ERC721 overrides `transferFrom(from, to, tokenId)` and verifies that `msg.sender` is the owner or approved, but does not verify that `from == ownerOf(tokenId)`. An attacker who is an approved operator for `tokenId` can call `transferFrom(victim, attacker, tokenId)` with a fabricated `from` address — the approval check passes for the operator, the token moves, but `from` was not the actual owner and may not be the intended origin for accounting, event logging, or protocol-level state. Pattern: `require(isApprovedOrOwner(msg.sender, tokenId))` without a subsequent `require(from == ownerOf(tokenId))`.
- **FP:** `super.transferFrom()` or OZ's `_transfer(from, to, tokenId)` called internally — OZ's `_transfer` explicitly checks `from == ownerOf(tokenId)` and reverts with `ERC721IncorrectOwner` if not. Custom override includes an explicit `require(ownerOf(tokenId) == from)` before transfer logic.

**73. NFT Staking / Escrow Records msg.sender Instead of ownerOf**

- **Detect:** Staking or escrow contract accepts an ERC721 via `nft.transferFrom(msg.sender, address(this), tokenId)` and records `depositor[tokenId] = msg.sender`. An operator (approved but not the owner) can call `stake(tokenId)` — the transfer succeeds because the operator holds approval, but `msg.sender` is the operator, not the real owner. The real owner loses their NFT; the operator is credited as depositor and receives all staking rewards and the right to unstake. Pattern: `depositor[tokenId] = msg.sender` without cross-checking against `nft.ownerOf(tokenId)` before the transfer.
- **FP:** Contract reads `address realOwner = nft.ownerOf(tokenId)` before accepting the transfer and records `depositor[tokenId] = realOwner`. Or requires `require(nft.ownerOf(tokenId) == msg.sender, "not owner")` so operators cannot stake on others' behalf.

**74. ERC721Consecutive (EIP-2309) Balance Corruption with Single-Token Batch**

- **Detect:** Contract uses OpenZeppelin's `ERC721Consecutive` extension (OZ < 4.8.2) and mints a batch of exactly one token via `_mintConsecutive(to, 1)`. A bug in that version fails to increment the recipient's balance for size-1 batches. `balanceOf(to)` returns 0 despite ownership being assigned. When the owner later calls `transferFrom`, the internal balance decrement underflows (reverts in checked math, or wraps in unchecked), leaving the token in a frozen state or causing downstream accounting errors in any contract that relies on `balanceOf` for reward distribution or collateral checks.
- **FP:** OZ version ≥ 4.8.2 used (patched via GHSA-878m-3g6q-594q). Batch size is always ≥ 2. Contract uses standard `ERC721._mint` (non-consecutive) where every mint writes the balance mapping directly.

**75. ERC721 / ERC1155 Type Confusion in Dual-Standard Marketplace**

- **Detect:** Marketplace or aggregator handles both ERC721 and ERC1155 in a shared `buy` or `fill` function using a type flag, but the `quantity` parameter required for ERC1155 amount is also accepted for ERC721 without validation that it equals 1. Price is computed as `price * quantity`. An attacker passes `quantity = 0` for an ERC721 listing — price calculation yields zero, NFT transfers successfully, payment is zero. Root cause of the TreasureDAO exploit (March 2022, $1.4M): `buyItem(listingId, 0)` for an ERC721 listing passed all checks and transferred the NFT for free.
- **FP:** ERC721 branch explicitly `require(quantity == 1)` before any price arithmetic. Separate code paths for ERC721 and ERC1155 with no shared quantity parameter. Price computed independently of quantity for ERC721 listings.

---

## ERC1155

**76. ERC1155 totalSupply Inflation via Reentrancy Before Supply Update**

- **Detect:** Contract extends `ERC1155Supply` (or custom supply tracking) and increments `totalSupply[id]` AFTER calling `_mint`, which triggers the `onERC1155Received` callback on the recipient. During the callback, `totalSupply[id]` has not yet been updated. Any governance, reward, or share-price formula that reads `totalSupply[id]` inside the callback (directly or via a re-entrant call to the same contract) observes an artificially low total, inflating the caller's computed share. OZ pre-4.3.2 `ERC1155Supply` had exactly this ordering — supply updated post-callback. Real finding: ChainSecurity disclosure, OZ advisory GHSA-9c22-pwxw-p6hx (2021).
- **FP:** OZ ≥ 4.3.2 used — supply incremented before the mint callback in patched versions. `nonReentrant` on all mint functions. No totalSupply-dependent logic is callable from within a mint callback path.

**77. ERC1155 safeBatchTransferFrom with Unchecked Mismatched Array Lengths**

- **Detect:** Custom ERC1155 overrides `_safeBatchTransferFrom` or iterates `ids` and `amounts` arrays in a loop without first asserting `require(ids.length == amounts.length)`. A caller passes `ids = [1, 2, 3]` and `amounts = [100]` — the loop processes only as many iterations as the shorter array (Solidity reverts on OOB access in 0.8+, but a `for (uint i = 0; i < ids.length; i++)` loop that reads `amounts[i]` will revert mid-batch rather than rejecting cleanly). In assembly-optimized or unchecked implementations, the shorter array access silently reads uninitialized memory or produces wrong transfers.
- **FP:** OZ ERC1155 base used without overriding batch transfer — OZ checks `ids.length == amounts.length` at the start and reverts with `ERC1155InvalidArrayLength`. Custom override explicitly asserts equal lengths as its first statement before any transfer logic.

**78. ERC1155 onERC1155Received Return Value Not Validated**

- **Detect:** Custom ERC1155 implementation calls `IERC1155Receiver(to).onERC1155Received(operator, from, id, value, data)` when transferring to a contract address, but does not check that the returned `bytes4` equals `IERC1155Receiver.onERC1155Received.selector` (`0xf23a6e61`). A recipient contract that returns any other value (including `bytes4(0)` or nothing) should cause the transfer to revert per EIP-1155, but without the check the transfer silently succeeds. Tokens are permanently locked in a contract that cannot handle them.
- **FP:** OZ ERC1155 used as base — it validates the selector and reverts with `ERC1155InvalidReceiver` on mismatch. Custom implementation explicitly checks: `require(retval == IERC1155Receiver.onERC1155Received.selector, "ERC1155: rejected")`.

**79. ERC1155 setApprovalForAll Grants All-Token-All-ID Operator Access**

- **Detect:** Protocol requires `setApprovalForAll(protocol, true)` to enable deposits, staking, or settlement across a user's ERC1155 holdings. Unlike ERC20 allowances (per token, per amount) or ERC721 single-token approve, ERC1155 has no per-ID or per-amount approval granularity — `setApprovalForAll` is an all-or-nothing grant covering every token ID the user holds and any they acquire in the future. A single compromised or malicious operator can call `safeTransferFrom(victim, attacker, anyId, fullBalance, "")` for every ID in one or more transactions, draining everything. Pattern: protocol documents "approve all tokens to use our platform" as a required first step.
- **FP:** Protocol uses individual `safeTransferFrom(from, to, id, amount, data)` calls that each require the user as `msg.sender` directly. Operator is a formally verified immutable contract whose only transfer logic routes tokens to the protocol's own escrow. Users are prompted to revoke approval via `setApprovalForAll(protocol, false)` after each session.

**80. ERC1155 Batch Transfer Partial-State Callback Window**

- **Detect:** Custom ERC1155 batch mint or transfer processes IDs in a loop — updating `_balances[id][to]` one ID at a time and calling `onERC1155Received` per iteration, rather than committing all balance updates first and then calling the single `onERC1155BatchReceived` hook once. During the per-ID callback, later IDs in the batch have not yet been credited. A re-entrant call from the callback can read stale balances for uncredited IDs, enabling double-counting or theft of not-yet-transferred amounts. Pattern: `for (uint i; i < ids.length; i++) { _balances[ids[i]][to] += amounts[i]; _doSafeTransferAcceptanceCheck(...); }`.
- **FP:** All balance updates for the entire batch are committed before any callback fires — mirroring OZ's approach: update all balances in one loop, then call `_doSafeBatchTransferAcceptanceCheck` once. `nonReentrant` applied to all transfer and mint entry points.

**81. ERC1155 Fungible / Non-Fungible Token ID Collision**

- **Detect:** Protocol uses ERC1155 to represent both fungible tokens (specific IDs with `supply > 1`) and unique items (other IDs with intended `supply == 1`), relying only on convention rather than enforcement. No `require(totalSupply(id) == 0)` before minting an "NFT" ID, or no check that prevents minting additional copies of an ID already at supply 1. An attacker who can call the public mint function mints a second copy of an "NFT" ID, breaking uniqueness. Or role tokens (e.g., `ROLE_ID = 1`) are fungible and freely tradeable, undermining access control that is gated on `balanceOf(user, ROLE_ID) > 0`.
- **FP:** Contract explicitly enforces `require(totalSupply(id) + amount <= maxSupply(id))` with `maxSupply` set to 1 for NFT IDs at creation time. Fungible and non-fungible ranges are disjoint and enforced with `require(id < FUNGIBLE_CUTOFF || id >= NFT_START)`. Role tokens are non-transferable (transfer overrides revert for role IDs).

**82. ERC1155 uri() Missing {id} Substitution Causes Metadata Collapse**

- **Detect:** `uri(uint256 id)` returns a fully resolved URL (e.g., `"https://api.example.com/token/42"`) instead of a template containing the literal `{id}` placeholder as required by EIP-1155. Clients and marketplaces that follow the standard substitute the zero-padded 64-character hex token ID for `{id}` client-side — returning a fully resolved URL breaks this substitution, pointing all IDs to the same metadata endpoint or creating malformed double-substituted URLs. Additionally, if `uri(id)` returns an empty string or a hardcoded static value identical for all IDs, off-chain systems treat all tokens as identical, destroying per-token metadata and market value.
- **FP:** `uri(id)` returns a string containing the literal `{id}` substring per EIP-1155 spec, and clients substitute the hex-encoded token ID. Protocol overrides `uri(id)` to return a fully unique per-ID on-chain URI (e.g., full base64-encoded JSON) and explicitly documents deviation from the `{id}` substitution requirement.

**83. Missing onERC1155BatchReceived Causes Token Lock on Batch Transfer**

- **Detect:** Receiving contract implements `IERC1155Receiver.onERC1155Received` (for single transfers) but not `IERC1155Receiver.onERC1155BatchReceived` (for batch transfers), or implements the latter returning a wrong selector. `safeBatchTransferFrom` to such a contract reverts on the callback check, permanently preventing batch delivery. Protocol that accepts individual deposits from users but attempts batch settlement or batch reward distribution internally will be permanently stuck if the recipient is one of these incomplete receivers. Pattern: `onERC1155BatchReceived` is absent, `returns (bytes4(0))`, or reverts unconditionally.
- **FP:** Contract implements both `onERC1155Received` and `onERC1155BatchReceived` returning the correct selectors, or inherits from OZ `ERC1155Holder` which provides both. Protocol's internal settlement exclusively uses single-item `safeTransferFrom` and is documented to never issue batch calls to contract recipients.

**84. ERC1155 Custom Burn Without Caller Authorization Check**

- **Detect:** Custom `burn(address from, uint256 id, uint256 amount)` or `burnBatch(address from, ...)` function is callable by any address without verifying that `msg.sender == from` or that `msg.sender` is an approved operator for `from`. Any caller can burn another user's tokens by passing their address as `from`. Pattern: `function burn(address from, uint256 id, uint256 amount) external { _burn(from, id, amount); }` with no authorization guard. Distinct from OZ's `_burn` (which is internal) — the risk is in public wrappers that expose it without access control.
- **FP:** Burn function requires `require(from == msg.sender || isApprovedForAll(from, msg.sender), "not authorized")` before calling `_burn`. OZ's `ERC1155Burnable` extension used — it includes the owner/operator check. Burn is restricted to a privileged role (admin/governance) and the `from` address is not user-supplied.

**85. ERC1155 ID-Based Role Access Control With Publicly Mintable Role Tokens**

- **Detect:** Protocol implements access control by checking ERC1155 token balance: `require(balanceOf(msg.sender, ADMIN_ROLE_ID) > 0)` or `require(balanceOf(msg.sender, MINTER_ROLE_ID) >= 1)`. The role token IDs (`ADMIN_ROLE_ID`, `MINTER_ROLE_ID`) are public constants. If the ERC1155 `mint` function for those IDs is not separately access-controlled — e.g., it's callable by any holder of a lower-tier token, or via a public presale — any attacker can acquire the role token and gain elevated privileges. Role tokens are also transferable by default, creating a secondary market for protocol permissions.
- **FP:** Minting of all role-designated token IDs is gated behind a separate access control system (e.g., OZ `AccessControl` with `MINTER_ROLE` on the ERC1155 contract itself). Role tokens for privileged IDs are non-transferable: `_beforeTokenTransfer` reverts for those IDs when `from != address(0) && to != address(0)`. Protocol uses a dedicated non-token access control system rather than ERC1155 balances for privilege gating.
