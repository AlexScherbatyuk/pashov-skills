# Attack Vectors Reference (1/3 — Vectors 1–45)

126 total attack vectors. For each: detection pattern and false-positive signals.

---

**1. Staking Reward Front-Run by New Depositor**

- **D:** Reward checkpoint (`rewardPerTokenStored`) updated AFTER new stake recorded: `_balances[user] += amount` before `updateReward()`. New staker earns rewards for unstaked period.
- **FP:** `updateReward(account)` executes before any balance update. `rewardPerTokenPaid[user]` tracks per-user checkpoint.

**2. ERC1155 safeBatchTransferFrom Unchecked Array Lengths**

- **D:** Custom `_safeBatchTransferFrom` iterates `ids`/`amounts` without `require(ids.length == amounts.length)`. Assembly-optimized paths may silently read uninitialized memory.
- **FP:** OZ ERC1155 base used unmodified. Custom override asserts equal lengths as first statement.

**3. DoS via Push Payment to Rejecting Contract**

- **D:** ETH distribution in a single loop via `recipient.call{value:}("")`. Any reverting recipient blocks entire loop.
- **FP:** Pull-over-push pattern. Loop uses `try/catch` and continues on failure.

**4. tx.origin Authentication**

- **D:** `require(tx.origin == owner)` used for auth. Phishable via intermediary contract.
- **FP:** `tx.origin == msg.sender` used only as anti-contract check, not auth.

**5. Function Selector Clashing (Proxy Backdoor)**

- **D:** Proxy contains a function whose 4-byte selector collides with an implementation function. User calls route to proxy logic instead of delegating.
- **FP:** Transparent proxy pattern separates admin/user routing. UUPS proxy has no custom functions — all calls delegate.

**6. validateUserOp Signature Not Bound to nonce or chainId**

- **D:** `validateUserOp` reconstructs digest manually (not via `entryPoint.getUserOpHash`) omitting `userOp.nonce` or `block.chainid`. Enables cross-chain or in-chain replay.
- **FP:** Digest from `entryPoint.getUserOpHash(userOp)` (includes sender, nonce, chainId). Custom digest explicitly includes both.

**7. Proxy Storage Slot Collision**

- **D:** Proxy stores `implementation`/`admin` at sequential slots (0, 1); implementation also declares variables from slot 0. Implementation writes overwrite proxy pointers.
- **FP:** EIP-1967 randomized slots used. OZ Transparent/UUPS pattern.

**8. ERC721Consecutive Balance Corruption with Single-Token Batch**

- **D:** OZ `ERC721Consecutive` (< 4.8.2) + `_mintConsecutive(to, 1)` — size-1 batch fails to increment balance. `balanceOf` returns 0 despite ownership.
- **FP:** OZ >= 4.8.2 (patched). Batch size always >= 2. Standard `ERC721._mint` used.

**9. ERC1155 Fungible / Non-Fungible Token ID Collision**

- **D:** ERC1155 represents both fungible and unique items with no enforcement: missing `require(totalSupply(id) == 0)` before NFT mint, or no cap preventing additional copies of supply-1 IDs.
- **FP:** `require(totalSupply(id) + amount <= maxSupply(id))` with `maxSupply=1` for NFTs. Fungible/NFT ID ranges disjoint and enforced. Role tokens non-transferable.

**10. Storage Layout Collision Between Proxy and Implementation**

- **D:** Proxy declares state variables at sequential slots (not EIP-1967). Implementation also starts at slot 0. Proxy's admin overlaps implementation's `initialized` flag. Ref: Audius (2022).
- **FP:** EIP-1967 slots. OZ Transparent/UUPS pattern. No state variables in proxy contract.

**11. Metamorphic Contract via CREATE2 + SELFDESTRUCT**

- **D:** `CREATE2` deployment where deployer can `selfdestruct` and redeploy different bytecode at same address. Governance-approved code swapped before execution. Ref: Tornado Cash Governance (2023). Post-Dencun (EIP-6780): largely mitigated except same-tx create-destroy-recreate.
- **FP:** Post-Dencun: `selfdestruct` no longer destroys code unless same tx as creation. `EXTCODEHASH` verified at execution time. Not deployed via `CREATE2` from mutable deployer.

**12. Missing Nonce (Signature Replay)**

- **D:** Signed message has no per-user nonce, or nonce present but never stored/incremented after use. Same signature resubmittable.
- **FP:** Monotonic per-signer nonce in signed payload, checked and incremented atomically. Or `usedSignatures[hash]` mapping.

**13. Front-Running Zero Balance Check with Dust Transfer**

- **D:** `require(token.balanceOf(address(this)) == 0)` gates a state transition. Dust transfer makes balance non-zero, DoS-ing the function at negligible cost.
- **FP:** Threshold check (`<= DUST_THRESHOLD`) instead of `== 0`. Access-controlled function. Internal accounting ignores direct transfers.

---

**14. Cross-Chain Deployment Replay**

- **D:** Deployment tx replayed on another chain. Same deployer nonce on both chains produces same CREATE address under different control. No EIP-155 chain ID protection. Ref: Wintermute.
- **FP:** EIP-155 signatures. `CREATE2` via deterministic factory at same address on all chains. Per-chain deployer EOAs.

**15. msg.value Reuse in Loop / Multicall**

- **D:** `msg.value` read inside a loop or `delegatecall`-based multicall. Each iteration/sub-call sees the full original value — credits `n * msg.value` for one payment.
- **FP:** `msg.value` captured to local variable, decremented per iteration, total enforced. Function non-payable. Multicall uses `call` not `delegatecall`.

**16. Missing or Expired Deadline on Swaps**

- **D:** `deadline = block.timestamp` (always valid), `deadline = type(uint256).max`, or no deadline. Tx holdable in mempool indefinitely.
- **FP:** Deadline is calldata parameter validated as `require(deadline >= block.timestamp)`, not derived from `block.timestamp` internally.

**17. Signature Malleability**

- **D:** Raw `ecrecover` without `s <= 0x7FFF...20A0` validation. Both `(v,r,s)` and `(v',r,s')` recover same address. Bypasses signature-based dedup.
- **FP:** OZ `ECDSA.recover()` used (validates `s` range). Message hash used as dedup key, not signature bytes.

**18. Write to Arbitrary Storage Location**

- **D:** (1) `sstore(slot, value)` where `slot` derived from user input without bounds. (2) Solidity <0.6: direct `arr.length` assignment + indexed write at crafted large index wraps slot arithmetic.
- **FP:** Assembly is read-only (`sload` only). Slot is compile-time constant or non-user-controlled. Solidity >= 0.6 used.

**19. Hardcoded Network-Specific Addresses**

- **D:** Literal `address(0x...)` constants for external dependencies (oracles, routers, tokens) in deployment scripts/constructors. Wrong contracts on different chains.
- **FP:** Per-chain config file keyed by chain ID. Script asserts `block.chainid`. Addresses passed as constructor args from environment. Deterministic cross-chain addresses (e.g., Permit2).

**20. Weak On-Chain Randomness**

- **D:** Randomness from `block.prevrandao`, `blockhash(block.number - 1)`, `block.timestamp`, `block.coinbase`, or combinations. Validator-influenceable or visible before inclusion.
- **FP:** Chainlink VRF v2+. Commit-reveal with future-block reveal and slashing for non-reveal.

**21. ERC4626 Inflation Attack (First Depositor)**

- **D:** `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, deposit 1 wei + donate inflates share price, victim's deposit rounds to 0 shares. No virtual offset.
- **FP:** OZ ERC4626 with `_decimalsOffset()`. Dead shares minted to `address(0)` at init.

**22. ERC1155 onERC1155Received Return Value Not Validated**

- **D:** Custom ERC1155 calls `onERC1155Received` but doesn't check returned `bytes4` equals `0xf23a6e61`. Non-compliant recipient silently accepts tokens it can't handle.
- **FP:** OZ ERC1155 base validates selector. Custom impl explicitly checks return value.

---

**23. Rounding in Favor of the User**

- **D:** `shares = assets / pricePerShare` rounds down for deposit but up for redeem. Division without explicit rounding direction. First-depositor donation amplifies the error.
- **FP:** `Math.mulDiv` with explicit `Rounding.Up` where vault-favorable. OZ ERC4626 `_decimalsOffset()`. Dead shares at init.

**24. NFT Staking Records msg.sender Instead of ownerOf**

- **D:** `depositor[tokenId] = msg.sender` without checking `nft.ownerOf(tokenId)`. Approved operator (not owner) calls stake — transfer succeeds via approval, operator credited as depositor.
- **FP:** Reads `nft.ownerOf(tokenId)` before transfer and records actual owner. Or `require(nft.ownerOf(tokenId) == msg.sender)`.

**25. Immutable Variable Context Mismatch**

- **D:** Implementation uses `immutable` variables (embedded in bytecode, not storage). Proxy `delegatecall` gets implementation's hardcoded values regardless of per-proxy needs. E.g., `immutable WETH` — every proxy gets same address.
- **FP:** Immutable values intentionally identical across all proxies. Per-proxy config uses storage via `initialize()`.

**26. extcodesize Zero in Constructor**

- **D:** `require(msg.sender.code.length == 0)` as EOA check. Contract constructors have `extcodesize == 0` during execution, bypassing the check.
- **FP:** Check is non-security-critical. Function protected by merkle proof, signed permit, or other mechanism unsatisfiable from constructor.

**27. ERC721Enumerable Index Corruption on Burn or Transfer**

- **D:** Override of `_beforeTokenTransfer` (OZ v4) or `_update` (OZ v5) without calling `super`. Index structures (`_ownedTokens`, `_allTokens`) become stale — `tokenOfOwnerByIndex` returns wrong IDs, `totalSupply` diverges.
- **FP:** Override always calls `super` as first statement. Contract doesn't inherit `ERC721Enumerable`.

**28. Block Stuffing / Gas Griefing on Subcalls**

- **D:** Time-sensitive function blockable by filling blocks. For relayer gas-forwarding griefing (63/64 rule), see Vector 47.
- **FP:** Function not time-sensitive or window long enough that block stuffing is economically infeasible.

**29. Chainlink Feed Deprecation / Wrong Decimal Assumption**

- **D:** (a) Chainlink aggregator address hardcoded/immutable with no update path — deprecated feed returns stale/zero price. (b) Assumes `feed.decimals() == 8` without runtime check — some feeds return 18 decimals, causing 10^10 scaling error.
- **FP:** Feed address updatable via governance. `feed.decimals()` called and used for normalization. Secondary oracle deviation check.

**30. Zero-Amount Transfer Revert**

- **D:** `token.transfer(to, amount)` where `amount` can be zero (rounded fee, unclaimed yield). Some tokens (LEND, early BNB) revert on zero-amount transfers, DoS-ing distribution loops.
- **FP:** `if (amount > 0)` guard before all transfers. Minimum claim amount enforced. Token whitelist verified to accept zero transfers.

**31. Flash Loan-Assisted Price Manipulation**

- **D:** Function reads price from on-chain source (AMM reserves, vault `totalAssets()`) manipulable atomically via flash loan + swap in same tx.
- **FP:** TWAP with >= 30min window. Multi-block cooldown between price reads. Separate-block enforcement.

**32. ERC721A Lazy Ownership — ownerOf Uninitialized in Batch Range**

- **D:** ERC721A/`ERC721Consecutive` batch mint: only first token has ownership written. `ownerOf(id)` for mid-batch IDs may return `address(0)` before any transfer. Access control checking `ownerOf == msg.sender` fails on freshly minted tokens.
- **FP:** Explicit transfer initializes packed slot before ownership check. Standard OZ `ERC721` writes `_owners[tokenId]` per mint.

**33. Bytecode Verification Mismatch**

- **D:** Verified source doesn't match deployed bytecode behavior: different compiler settings, obfuscated constructor args, or `--via-ir` vs legacy pipeline mismatch. No reproducible build (no pinned compiler in config).
- **FP:** Deterministic build with pinned compiler/optimizer in committed config. Verification in deployment script (Foundry `--verify`). Sourcify full match. Constructor args published.

---

**34. Insufficient Gas Forwarding / 63/64 Rule**

- **D:** External call without minimum gas budget: `target.call(data)` with no gas check. 63/64 rule leaves subcall with insufficient gas. In relayer patterns, subcall silently fails but outer tx marks request as "processed."
- **FP:** `require(gasleft() >= minGas)` before subcall. Return value + returndata both checked. EIP-2771 with verified gas parameter.

**35. Read-Only Reentrancy**

- **D:** Protocol calls `view` function (`get_virtual_price()`, `totalAssets()`) on external contract from within a callback. External contract has no reentrancy guard on view functions — returns transitional/manipulated value mid-execution.
- **FP:** External view functions are `nonReentrant`. Chainlink oracle used instead. External contract's reentrancy lock checked before calling view.

**36. ERC4626 Round-Trip Profit Extraction**

- **D:** `redeem(deposit(a)) > a` or inverse — rounding errors in both `_convertToShares` and `_convertToAssets` favor the user, yielding net profit per round-trip.
- **FP:** Rounding per EIP-4626: deposit/mint round down (vault-favorable), withdraw/redeem round up (vault-favorable). OZ ERC4626 with `_decimalsOffset()`.

**37. Missing chainId / Message Uniqueness in Bridge**

- **D:** Bridge processes messages without `processedMessages[hash]` replay check, `destinationChainId == block.chainid` validation, or source chain ID in hash. Message replayable cross-chain or on same chain.
- **FP:** Unique nonce per sender. Hash of `(sourceChain, destChain, nonce, payload)` stored and checked. Contract address in hash.

**38. Diamond Shared-Storage Cross-Facet Corruption**

- **D:** EIP-2535 Diamond facets declare top-level state variables (plain `uint256 foo`) instead of namespaced storage structs. Multiple facets independently start at slot 0, corrupting each other.
- **FP:** All facets use single `DiamondStorage` struct at namespaced position (EIP-7201). No top-level state variables. OZ `@custom:storage-location` pattern.

**39. Transparent Proxy Admin Routing Confusion**

- **D:** Admin address also used for regular protocol interactions. Calls from admin route to proxy admin functions instead of delegating — silently failing or executing unintended logic.
- **FP:** Dedicated `ProxyAdmin` contract used exclusively for admin calls. OZ `TransparentUpgradeableProxy` enforces separate admin.

**40. Nonce Gap from Reverted Transactions (CREATE Address Mismatch)**

- **D:** Deployment script uses `CREATE` and pre-computes addresses from deployer nonce. Reverted/extra tx advances nonce — subsequent deployments land at wrong addresses. Pre-configured references point to empty/wrong contracts.
- **FP:** `CREATE2` used (nonce-independent). Script reads nonce from chain before computing. Addresses captured from deployment receipts, not pre-assumed.

**41. Single-Function Reentrancy**

- **D:** External call (`call{value:}`, `safeTransfer`, etc.) before state update — check-external-effect instead of check-effect-external (CEI).
- **FP:** State updated before call (CEI followed). `nonReentrant` modifier. Callee is hardcoded immutable with known-safe receive/fallback.

**42. Beacon Proxy Single-Point-of-Failure Upgrade**

- **D:** Multiple proxies read implementation from single Beacon. Compromising Beacon owner upgrades all proxies at once. `UpgradeableBeacon.owner()` returns single EOA.
- **FP:** Beacon owner is multisig + timelock. `Upgraded` events monitored. Per-proxy upgrade authority where isolation required.

**43. EIP-2981 Royalty Signaled But Never Enforced**

- **D:** `royaltyInfo()` implemented and `supportsInterface(0x2a55205a)` returns true, but transfer/settlement logic never calls `royaltyInfo()` or routes payment. EIP-2981 is advisory only.
- **FP:** Settlement contract reads `royaltyInfo()` and transfers royalty on-chain. Royalties intentionally zero and documented.

**44. Precision Loss - Division Before Multiplication**

- **D:** `(a / b) * c` — truncation before multiplication amplifies error. E.g., `fee = (amount / 10000) * bps`. Correct: `(a * c) / b`.
- **FP:** `a` provably divisible by `b` (enforced by `require(a % b == 0)` or mathematical construction).

**45. Upgrade Race Condition / Front-Running**

- **D:** `upgradeTo(V2)` and post-upgrade config calls are separate txs in public mempool. Window for front-running (exploit old impl) or sandwiching between upgrade and config.
- **FP:** `upgradeToAndCall()` bundles upgrade + init. Private mempool (Flashbots Protect). V2 safe with V1 state from block 0. Timelock makes execution predictable.
