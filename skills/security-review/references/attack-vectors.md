# Attack Vectors Reference

48 attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

## Reentrancy

**1. Single-Function Reentrancy**
- **Detect:** External call (`call{value:}`, `transfer`, `send`, `safeTransfer`, `safeTransferFrom`) happens *before* state update (balance set to 0, flag set, counter decremented). Classic: check-external-effect instead of check-effect-external.
- **FP:** State updated before the call (CEI followed). `nonReentrant` modifier present. Callee is a verified EOA.

**2. Cross-Function Reentrancy**
- **Detect:** Two functions share a state variable. Function A makes an external call before updating shared state; Function B reads or modifies that same state. `nonReentrant` on A but not B.
- **FP:** Both functions are guarded by the same contract-level mutex. Shared state updated before any external call in A.

**3. Cross-Contract Reentrancy**
- **Detect:** Two separate contracts share logical state (e.g., balances in A, collateral check in B). A makes an external call before syncing the state B reads. A's `ReentrancyGuard` does not protect B.
- **FP:** State B reads is synchronized before A's external call. No re-entry path can reach B's read while A's state is stale.

**4. Read-Only Reentrancy**
- **Detect:** Protocol calls a `view` function (e.g., `get_virtual_price()`, `totalAssets()`, `convertToAssets()`) on an external contract from within a callback (`receive`, `onERC721Received`, flash loan hook). The external contract has no reentrancy guard on its view functions - a mid-execution call can return a transitional/manipulated value.
- **FP:** External contract's view functions are themselves `nonReentrant`. Protocol uses Chainlink or another oracle instead of the external view. External contract's lock is public and the protocol checks it.

**5. ERC721/ERC1155 Callback Reentrancy**
- **Detect:** `safeTransferFrom` (ERC721) or `safeMint`/`safeTransferFrom` (ERC1155) called before state updates. These invoke `onERC721Received`/`onERC1155Received` on recipient contracts.
- **FP:** All state committed before the safe transfer. Function is `nonReentrant`.

---

## Access Control

**6. Missing or Incorrect Access Modifier**
- **Detect:** State-changing function (`setOwner`, `withdrawFunds`, `mint`, `pause`, `setOracle`, `updateFees`) has no access guard, or modifier references an uninitialized variable. `public`/`external` visibility on privileged operations with no restriction.
- **FP:** Function is intentionally permissionless by design. Access enforced at a higher protocol layer (documented).

**7. Unsafe Single-Step Ownership Transfer**
- **Detect:** Inherits `Ownable` (not `Ownable2Step`). `transferOwnership` immediately sets the new owner with no acceptance step. A typo is irreversible.
- **FP:** Uses `Ownable2Step`. New owner must call `acceptOwnership()`. Or `renounceOwnership` is overridden to revert.

**8. tx.origin Authentication**
- **Detect:** `require(tx.origin == owner)` or `require(tx.origin == authorized)` used for authentication. Vulnerable to phishing via malicious intermediary contract.
- **FP:** `tx.origin == msg.sender` used only to assert caller is not a contract (anti-bot pattern, not auth).

**9. Unprotected Initializer (Upgradeable Contract)**
- **Detect:** `initialize()` function has no `initializer` modifier, or constructor does not call `_disableInitializers()`. Anyone can call `initialize()` on the bare implementation contract, claim ownership, and self-destruct it.
- **FP:** Constructor calls `_disableInitializers()`. `initializer` modifier from OpenZeppelin `Initializable` is present. Transparent proxy with admin-only upgrade path.

**10. Role Assignment to Zero Address / Misconfigured RBAC**
- **Detect:** `grantRole(ROLE, address(0))` or `_setupRole(role, address(0))` in deployment/init. Or `DEFAULT_ADMIN_ROLE` with no separate admin. Permanent lockout or privilege misconfiguration.
- **FP:** Zero-address grant is intentional for a burn-role pattern (documented). Multi-sig timelocked admin validates recipients.

---

## Arithmetic / Math

**11. Integer Overflow / Underflow**
- **Detect:** Arithmetic inside `unchecked {}` blocks (Solidity ≥0.8) that could over/underflow: subtraction without a prior `require(amount <= balance)`, multiplication of two large values. Any arithmetic in Solidity <0.8 without SafeMath. (SWC-101)
- **FP:** Value range is provably bounded by earlier checks. `unchecked` used only for loop counter increments where overflow is impossible.

**12. Precision Loss - Division Before Multiplication**
- **Detect:** Expression `(a / b) * c` in integer math. Division truncates first, then multiplication amplifies the error. Common in fee calculations: `fee = (amount / 10000) * bps`. Correct form: `(a * c) / b`.
- **FP:** `b` is a power of 2 or 10 and `a` is guaranteed divisible by `b`. Precision loss is documented and rounds in protocol's favor by design.

**13. Unsafe Downcast / Integer Truncation**
- **Detect:** Explicit cast to smaller type without bounds check: `uint128(largeUint256)`. Solidity ≥0.8 silently truncates on downcast (does NOT revert). Especially dangerous in price feeds, share calculations, timestamps.
- **FP:** Value validated against `type(uint128).max` before cast. OpenZeppelin `SafeCast` library used. Domain mathematically constrains value to target range.

**14. Rounding in Favor of the Attacker**
- **Detect:** `shares = assets / pricePerShare` rounds down for the user but up for shares redeemed. First-depositor vault manipulation: when `totalSupply == 0`, attacker donates to inflate `totalAssets`, subsequent deposits round to 0 shares. Division without explicit rounding direction.
- **FP:** `Math.mulDiv(a, b, c, Rounding.Up)` used. Virtual offset (OpenZeppelin ERC4626 `_decimalsOffset()`) prevents first-depositor attack. Dead shares minted to `address(0)` on init.

---

## Oracle Manipulation

**15. Spot Price Oracle from AMM**
- **Detect:** Price computed from AMM reserves directly: `price = reserve0 / reserve1`, `getAmountsOut()`, `getReserves()`. Any lending, liquidation, or collateral logic built on spot price is flash-loan exploitable atomically.
- **FP:** TWAP oracle with a long window (Uniswap v3 30+ min on deep liquidity). Chainlink or Pyth as primary source. Pool liquidity provably makes manipulation uneconomic.

**16. Chainlink Staleness / No Validity Checks**
- **Detect:** `latestRoundData()` called but any of these checks are missing: `answer > 0`, `updatedAt > block.timestamp - MAX_STALENESS`, `answeredInRound >= roundId`, fallback on failure.
- **FP:** All four checks present. Circuit breaker or fallback oracle used when any check fails.

**17. L2 Sequencer Uptime Not Checked**
- **Detect:** Contract on Arbitrum/Optimism/Base/etc. uses Chainlink feeds but does not query the L2 Sequencer Uptime Feed before consuming prices. Stale data during sequencer downtime can trigger wrong liquidations.
- **FP:** Sequencer uptime feed queried explicitly (`answer == 0` = up), with a grace period enforced after restart.

**18. Flash Loan-Assisted Price Manipulation**
- **Detect:** A function reads price/ratio from an on-chain source (AMM reserves, vault `totalAssets()`), and that source can be manipulated atomically in the same tx via flash loan + swap. Attacker sequence: borrow → move price → call function → restore → repay.
- **FP:** Price source is TWAP with a long enough window. Cooldown enforced between reads. Separate-block-only callable.

---

## Flash Loans

**19. Flash Loan Governance Attack**
- **Detect:** Governance voting uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block). Attacker borrows governance tokens, votes, repays in one tx.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock between snapshot and vote. Staking required before voting.

**20. Improper Flash Loan Callback Validation**
- **Detect:** `onFlashLoan` callback does not verify `msg.sender == lendingPool`, or does not verify `initiator`, or does not check `token`/`amount` match. Attacker can call the callback directly without a real flash loan.
- **FP:** Both `msg.sender == address(lendingPool)` and `initiator == address(this)` are validated. Token and amount checked against pre-stored values.

---

## MEV / Frontrunning

**21. Missing Slippage Protection (Sandwich Attack)**
- **Detect:** Swap/deposit/withdrawal with `minAmountOut = 0`, or `minAmountOut` computed on-chain from current pool state (always passes). Pattern: `router.swap(..., 0, deadline)`.
- **FP:** `minAmountOut` set off-chain by the user and validated on-chain. Private RPC or MEV-protected routing used.

**22. Missing or Expired Deadline on Swaps**
- **Detect:** `deadline = block.timestamp` (computed inside the tx, always valid), `deadline = type(uint256).max`, or no deadline at all. Transaction can be held in mempool and executed at any future price.
- **FP:** Deadline set by user to a meaningful future timestamp and validated on-chain. Private RPC used.

**23. On-Chain Randomness Frontrunning**
- **Detect:** Randomness from `block.prevrandao`, `blockhash()`, `block.timestamp`, `block.coinbase`, or combinations. Validators can influence RANDAO; all block values are visible before tx inclusion. (SWC-120)
- **FP:** Chainlink VRF v2+ used. Commit-reveal with future-block reveal and economic punishment for non-reveal.

---

## Denial of Service

**24. DoS via Unbounded Loop**
- **Detect:** Loop iterates over an array that grows with user interaction and is unbounded: `for (uint i = 0; i < users.length; i++) { ... }`. If anyone can push to `users`, the function will eventually hit the block gas limit. (SWC-128)
- **FP:** Array length capped at insertion time. Loop iterates a fixed small count. Admin can paginate.

**25. DoS via Push Payment to Rejecting Contract**
- **Detect:** ETH/token distribution in a single loop using push model (`recipient.call{value:}("")`). If any recipient reverts on receive, the entire loop reverts. Also: `transfer()`/`send()` to contracts with expensive `fallback()`. (SWC-113)
- **FP:** Pull-over-push pattern used. Loop uses `try/catch` and continues on failure.

**26. Block Stuffing / Gas Griefing on Subcalls**
- **Detect:** Time-sensitive function can be blocked by filling blocks. Related: relayer pattern forwards calls without checking `gasleft()` - exploits 63/64 rule where the subcall fails silently and is marked as "sent." (SWC-126)
- **FP:** `gasleft()` checked explicitly before forwarding. Time window is so long (days/weeks) that block stuffing is uneconomical.

**27. Return Bomb (Returndata Copy DoS)**
- **Detect:** `(bool success, bytes memory data) = target.call(payload)` where `target` is user-supplied or unconstrained. Malicious target returns huge returndata; copying it costs enormous gas.
- **FP:** Returndata not copied (`assembly { success := call(...) }` without copy, or gas-limited call). Callee is a known, trusted contract.

---

## Delegatecall

**28. Delegatecall to Untrusted / User-Supplied Callee**
- **Detect:** `address(target).delegatecall(data)` where `target` is user-provided or unconstrained. Callee executes in the caller's storage context - can overwrite owner, balances, call `selfdestruct`. (SWC-112)
- **FP:** `target` is a hardcoded immutable verified library address. Function is admin-only behind a timelocked multi-sig.

**29. Proxy Storage Slot Collision**
- **Detect:** Proxy stores `implementation`/`admin` at sequential slots (0, 1) and implementation contract also declares variables from slot 0. Implementation's slot 0 write overwrites the proxy's `implementation` pointer.
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). Implementation uses `__gap` array. OpenZeppelin Transparent or UUPS proxy pattern used correctly.

**30. Function Selector Clash in Proxy**
- **Detect:** Proxy and implementation share a 4-byte function selector collision. A call intended for the implementation gets routed to the proxy's own function (or vice versa), silently executing the wrong logic.
- **FP:** Transparent proxy pattern used (admin calls always hit proxy admin; user calls always delegate). Deployment tooling verifies no selector clashes.

---

## Signature Issues

**31. Missing Nonce (Signature Replay)**
- **Detect:** Signed message has no per-user nonce, or nonce is present in the struct but never stored/incremented after use. Same valid signature can be submitted multiple times. (SWC-121)
- **FP:** Monotonic per-signer nonce included in signed payload, stored, checked for reuse, incremented atomically. `usedSignatures[hash]` mapping invalidates after first use.

**32. Missing chainId (Cross-Chain Replay)**
- **Detect:** Signed payload doesn't include `chainId`. Valid signature on mainnet replayable on forks or other EVM chains where the contract is deployed. Or `chainId` hardcoded at deployment rather than read via `block.chainid`.
- **FP:** EIP-712 domain separator includes `chainId: block.chainid` (dynamic) and `verifyingContract`. Domain separator re-checked or invalidated if `block.chainid` changes.

**33. Signature Malleability**
- **Detect:** Raw `ecrecover(hash, v, r, s)` used without validating `s <= 0x7FFF...20A0`. Both `(v,r,s)` and `(v',r,s')` recover the same address. If signatures are used as unique identifiers (stored to prevent replay), a malleable variant bypasses the uniqueness check. (SWC-117)
- **FP:** OpenZeppelin `ECDSA.recover()` used (validates `s` range and `v`). Full message hash used as dedup key, not the signature bytes.

**34. ERC-2771 + Multicall msg.sender Spoofing**
- **Detect:** Contract implements both ERC-2771 (`_msgSender()` reads last 20 bytes of calldata from trusted forwarder) and a `multicall` using `delegatecall`. Attacker crafts calldata via the trusted forwarder where subcall data's last 20 bytes are a victim address. `_msgSender()` in the subcall resolves to the victim.
- **FP:** Multicall explicitly handles ERC-2771 context suffix per subcall (OpenZeppelin patched version). Contract uses `msg.sender` directly, not `_msgSender()`. No trusted forwarder is set.

---

## Token Integration

**35. Non-Standard ERC20 Return Values (USDT-style)**
- **Detect:** `require(token.transfer(to, amount))` reverts on tokens that return nothing (USDT, BNB). Or return value ignored entirely (silent failure on failed transfer). (SWC-104)
- **FP:** OpenZeppelin `SafeERC20.safeTransfer()`/`safeTransferFrom()` used throughout.

**36. Fee-on-Transfer Token Accounting**
- **Detect:** Deposit recorded as `deposits[user] += amount` then `transferFrom(..., amount)`. Fee-on-transfer tokens (SAFEMOON, STA) cause the contract to receive `amount - fee` but record `amount`. Subsequent withdrawals drain other users.
- **FP:** Balance measured before/after transfer: `uint256 before = token.balanceOf(this); token.transferFrom(...); uint256 received = token.balanceOf(this) - before;` and `received` used for accounting.

**37. Rebasing / Elastic Supply Token Accounting**
- **Detect:** Contract holds rebasing tokens (stETH, AMPL, aTokens) and caches `token.balanceOf(this)` in a state variable used for future accounting. After a rebase, cached value diverges from actual balance.
- **FP:** Protocol explicitly excludes rebasing tokens. Accounting always reads `balanceOf` live. Wrapper tokens (wstETH) used instead.

**38. ERC20 Approve Race / Allowance Frontrunning**
- **Detect:** `approve(spender, newAmount)` called when existing allowance > 0. Watcher frontruns: spends old allowance, then spends new allowance. Double-spend of `oldAmount + newAmount`. Also: USDT reverts on non-zero-to-non-zero approval.
- **FP:** `increaseAllowance()`/`decreaseAllowance()` used. Allowance always set to 0 before new value. Atomic allowance handling via contract.

**39. ERC4626 Inflation Attack (First Depositor)**
- **Detect:** Vault shares math: `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, attacker deposits 1 wei, donates large amount to vault, victim's deposit rounds to 0 shares. No virtual offset or dead shares protection.
- **FP:** OpenZeppelin ERC4626 with `_decimalsOffset()` override. Dead shares minted to `address(0)` at init. Minimum deposit enforced.

---

## Proxy / Upgrade Patterns

**40. UUPS Implementation Not Initialized / selfdestruct Risk**
- **Detect:** UUPS implementation deployed without `_disableInitializers()` in constructor. Anyone can call `initialize()` on the bare implementation, claim ownership, call `upgradeTo(maliciousImpl)` with `selfdestruct`, destroying all proxies that point to it.
- **FP:** Constructor calls `_disableInitializers()`. Implementation verifies it's being called via a proxy. Transparent proxy (upgrade logic in proxy admin, not implementation).

**41. Missing Storage Gap in Upgradeable Base Contract**
- **Detect:** Upgradeable base contract has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts the derived contract's storage layout, overwriting existing variables.
- **FP:** EIP-1967 custom storage slots used for all new variables. Flat inheritance (single contract) where additions to the end are safe. Formal storage layout diff run before each upgrade.

---

## Timestamp / Block Values

**42. Block Timestamp Dependence**
- **Detect:** `block.timestamp` used for game outcomes, randomness (`block.timestamp % N`), or auction timing where a 15-second manipulation changes the outcome. (SWC-116)
- **FP:** Timestamp used only for periods spanning minutes or longer (hours, days), where 15-second validator manipulation is irrelevant. Used only for logging.

**43. Weak On-Chain Randomness**
- **Detect:** Randomness from `block.prevrandao` (RANDAO, validator-influenceable), `blockhash(block.number - 1)` (known before inclusion), `block.timestamp`, `block.coinbase`, or combinations. (SWC-120)
- **FP:** Chainlink VRF v2+ used. Commit-reveal with future-block reveal and economic punishment for non-reveal.

---

## Uninitialized Storage

**44. Uninitialized Local Storage Pointer**
- **Detect:** (Solidity <0.5) Local struct/array variable without explicit `memory`/`storage` defaults to `storage`, pointing to slot 0. Writes overwrite the contract's first state variable (often `owner`). Also check assembly for uninitialized storage pointers. (SWC-109)
- **FP:** Code is Solidity ≥0.5 (compiler enforces explicit data location). All `<0.5` struct/array locals use `memory`.

---

## Arithmetic / Timestamp

**45. Block Number as Timestamp Approximation**
- **Detect:** Time computed as `(block.number - startBlock) * 13` assuming fixed block times. Post-Merge Ethereum has variable block times; Polygon/Arbitrum/BSC have very different averages. Causes wrong interest accrual, vesting, or reward calculations.
- **FP:** `block.timestamp` used instead of `block.number` for time math. Chain-specific and block time is verified constant. Calculation is non-financial and imprecision acceptable.

---

## ERC Standards Compliance

**46. ERC20 Non-Compliant: Return Values / Events**
- **Detect:** Custom `transfer()`/`transferFrom()` doesn't return `bool`, or always returns `true` on failure. `mint()` missing `Transfer(address(0), to, amount)` event. `burn()` missing `Transfer(from, address(0), amount)`. `approve()` missing `Approval` event. Breaks DEX and wallet composability.
- **FP:** OpenZeppelin `ERC20.sol` used as base. All custom overrides validated against EIP-20 spec.

**47. ERC721 Unsafe Transfer to Non-Receiver**
- **Detect:** `_transfer()` (unsafe) used instead of `_safeTransfer()`, or `_mint()` instead of `_safeMint()`, sending NFTs to contracts that may not implement `IERC721Receiver`. Tokens permanently locked in the recipient contract.
- **FP:** Recipient validated as EOA before transfer (`to.code.length == 0`). Protocol is a custodian where sending to non-receiver contracts is documented intent. `_safeMint` used throughout.

---

## Cross-Chain

**48. Missing chainId / Message Uniqueness in Bridge**
- **Detect:** Bridge/messaging contract processes incoming messages but lacks: `processedMessages[messageHash]` check (replay), `destinationChainId == block.chainid` validation, or source chain ID in the message hash. A message from Chain A to Chain B can be replayed on Chain C, or submitted twice on the destination.
- **FP:** Each message has a unique nonce per sender. Hash of `(sourceChain, destinationChain, nonce, payload)` stored in `processedMessages` and checked before execution. Contract address included in message hash.

---

## Severity Guide

| Severity | Criteria |
|---|---|
| **CRITICAL** | Direct theft of funds, permanent loss of user assets, protocol takeover |
| **HIGH** | Significant loss possible with moderate preconditions, broken core invariant |
| **MEDIUM** | Limited loss or requires specific conditions; DoS without permanent damage |
| **LOW** | Best practice violation, minor accounting issue, limited impact |
| **INFO** | Code quality, documentation, no security impact |
