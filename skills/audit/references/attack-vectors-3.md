# Attack Vectors Reference (3/3 — Vectors 90–132)

126 total attack vectors. For each: detection pattern and false-positive signals.

---

**90. ERC20 Non-Compliant: Return Values / Events**

- **D:** Custom `transfer()`/`transferFrom()` doesn't return `bool` or always returns `true` on failure. `mint()`/`burn()` missing `Transfer` events. `approve()` missing `Approval` event.
- **FP:** OZ `ERC20.sol` base with no custom overrides of transfer/approve/event logic.

**91. Fee-on-Transfer Token Accounting**

- **D:** Deposit records `deposits[user] += amount` then `transferFrom(..., amount)`. Fee-on-transfer tokens cause contract to receive less than recorded.
- **FP:** Balance measured before/after: `uint256 before = token.balanceOf(this); transferFrom(...); received = balanceOf(this) - before;` and `received` used for accounting.

**92. Arbitrary `delegatecall` in Implementation**

- **D:** Implementation exposes `delegatecall` to user-supplied address without restriction. Pattern: `target.delegatecall(data)` where `target` is caller-controlled. Ref: Furucombo (2021).
- **FP:** Target is hardcoded immutable address. Whitelist of approved targets enforced. `call` used instead.

**93. Counterfactual Wallet Initialization Parameters Not Bound to Deployed Address**

- **D:** Factory `createAccount` uses CREATE2 but salt doesn't incorporate all init params (especially owner). Attacker calls `createAccount` with different owner, deploying wallet they control to same counterfactual address.
- **FP:** Salt derived from all init params: `salt = keccak256(abi.encodePacked(owner, ...))`. Factory reverts if account exists. Initializer called atomically with deployment.

**95. Chainlink Staleness / No Validity Checks**

- **D:** `latestRoundData()` called but missing checks: `answer > 0`, `updatedAt > block.timestamp - MAX_STALENESS`, `answeredInRound >= roundId`, fallback on failure.
- **FP:** All four checks present. Circuit breaker or fallback oracle on failure.

**96. Transient Storage Low-Gas Reentrancy (EIP-1153)**

- **D:** Contract uses `transfer()`/`send()` (2300-gas) as reentrancy guard + uses `TSTORE`/`TLOAD`. Post-Cancun, `TSTORE` succeeds under 2300 gas unlike `SSTORE`. Second pattern: transient reentrancy lock not cleared at call end — persists for entire tx, causing DoS via multicall/flash loan callback.
- **FP:** `nonReentrant` backed by regular storage slot (or transient mutex properly cleared). CEI followed unconditionally.

**97. Missing Slippage Protection (Sandwich Attack)**

- **D:** Swap/deposit/withdrawal with `minAmountOut = 0`, or `minAmountOut` computed on-chain from current pool state.
- **FP:** `minAmountOut` set off-chain by user and validated on-chain.

**99. abi.encodePacked Hash Collision with Dynamic Types**

- **D:** `keccak256(abi.encodePacked(a, b))` where two+ args are dynamic types (`string`, `bytes`, dynamic arrays). No length prefix means different inputs produce identical hashes. Affects permits, access control keys, nullifiers.
- **FP:** `abi.encode()` used instead. Only one dynamic type arg. All args fixed-size.

**100. ERC1155 ID-Based Role Access Control With Publicly Mintable Role Tokens**

- **D:** Access control via `require(balanceOf(msg.sender, ROLE_ID) > 0)` where `mint` for those IDs is not separately gated. Role tokens transferable by default.
- **FP:** Minting role-token IDs gated behind separate access control. Role tokens non-transferable (`_beforeTokenTransfer` reverts for non-mint/burn). Dedicated non-token ACL used.

**101. ERC721 Approval Not Cleared in Custom Transfer Override**

- **D:** Custom `transferFrom` override skips `super._transfer()` or `super.transferFrom()`, missing the `delete _tokenApprovals[tokenId]` step. Previous approval persists under new owner.
- **FP:** Override calls `super.transferFrom` or `super._transfer` internally. Or explicitly deletes approval / calls `_approve(address(0), tokenId, owner)`.

**102. Off-By-One in Bounds or Range Checks**

- **D:** (1) `i <= arr.length` in loop (accesses OOB index). (2) `arr[arr.length - 1]` in `unchecked` without length > 0 check. (3) `>=` vs `>` confusion in financial logic (early unlock, boundary-exceeding deposit). (4) Integer division rounding accumulation across N recipients.
- **FP:** Loop uses `<` with fixed-length array. Last-element access preceded by length check. Financial boundaries demonstrably correct for the invariant.

**103. Minimal Proxy (EIP-1167) Implementation Destruction**

- **D:** EIP-1167 clones `delegatecall` a fixed implementation. If implementation is destroyed, all clones become no-ops with locked funds. Pattern: `Clones.clone(impl)` where impl has no `selfdestruct` protection or is uninitialized.
- **FP:** No `selfdestruct` in implementation. `_disableInitializers()` in constructor. Post-Dencun: code not destroyed. Beacon proxies used for upgradeability.

**104. Immutable / Constructor Argument Misconfiguration**

- **D:** Constructor sets `immutable` values (admin, fee, oracle, token) that can't change post-deploy. Multiple same-type `address` params where order can be silently swapped. No post-deploy verification.
- **FP:** Deployment script reads back and asserts every configured value. Constructor validates: `require(admin != address(0))`, `require(feeBps <= 10000)`.

**105. Missing Storage Gap in Upgradeable Base Contract**

- **D:** Inherited upgradeable base has no `uint256[N] private __gap;`. Adding state variables in a future version shifts all derived contracts' storage slots.
- **FP:** EIP-7201 / EIP-1967 namespaced storage used. `__gap` present and correctly sized. Single non-inherited contract.

**106. Non-Atomic Multi-Contract Deployment (Partial System Bootstrap)**

- **D:** Deployment script deploys interdependent contracts across separate transactions. Midway failure leaves half-deployed state with missing references or unwired contracts. Pattern: multiple `vm.broadcast()` blocks or sequential `await deploy()` with no idempotency checks.
- **FP:** Single `vm.startBroadcast()`/`vm.stopBroadcast()` block. Factory deploys+wires all in one tx. Script is idempotent. Hardhat-deploy with resumable migrations.

**107. Stale Cached ERC20 Balance from Direct Token Transfers**

- **D:** Contract tracks holdings in state variable (`totalDeposited`, `_reserves`) updated only through protocol functions. Direct `token.transfer(contract)` inflates real balance beyond cached value. Attacker exploits gap for share pricing/collateral manipulation.
- **FP:** Accounting reads `balanceOf(this)` live. Cached value reconciled at start of every state-changing function. Direct transfers treated as revenue.

**108. Merkle Proof Reuse — Leaf Not Bound to Caller**

- **D:** Merkle leaf doesn't include `msg.sender`: `MerkleProof.verify(proof, root, keccak256(abi.encodePacked(amount)))`. Proof can be front-run from different address.
- **FP:** Leaf encodes `msg.sender`: `keccak256(abi.encodePacked(msg.sender, amount))`. Proof recorded as consumed after first use.

**109. L2 Sequencer Uptime Not Checked**

- **D:** Contract on L2 (Arbitrum/Optimism/Base) uses Chainlink feeds without querying L2 Sequencer Uptime Feed. Stale data during downtime triggers wrong liquidations.
- **FP:** Sequencer uptime feed queried (`answer == 0` = up), with grace period after restart.

**110. CREATE2 Address Squatting (Counterfactual Front-Running)**

- **D:** CREATE2 salt not bound to `msg.sender`. Attacker precomputes address and deploys first. For AA wallets: attacker deploys wallet to user's counterfactual address with attacker as owner.
- **FP:** Salt incorporates `msg.sender`: `keccak256(abi.encodePacked(msg.sender, userSalt))`. Factory restricts deployer. Different owner in constructor produces different address.

**111. Rebasing / Elastic Supply Token Accounting**

- **D:** Contract holds rebasing tokens (stETH, AMPL, aTokens) and caches `balanceOf(this)`. After rebase, cached value diverges from actual balance.
- **FP:** Rebasing tokens blocked at code level (revert/whitelist). Accounting reads `balanceOf` live. Wrapper tokens (wstETH) used.

---

**112. Banned Opcode in Validation Phase (Simulation-Execution Divergence)**

- **D:** `validateUserOp`/`validatePaymasterUserOp` references `block.timestamp`, `block.number`, `block.coinbase`, `block.prevrandao`, `block.basefee`. Per ERC-7562, banned in validation — values differ between simulation and execution.
- **FP:** Banned opcodes only in execution phase (`execute`/`executeBatch`). Entity is staked under ERC-7562 reputation system.

**114. Paymaster ERC-20 Payment Deferred to postOp Without Pre-Validation**

- **D:** `validatePaymasterUserOp` doesn't transfer/lock tokens — payment deferred to `postOp` via `safeTransferFrom`. User can revoke allowance between validation and execution; paymaster loses deposit.
- **FP:** Tokens transferred/locked during `validatePaymasterUserOp`. `postOp` only refunds excess.

**115. Integer Overflow / Underflow**

- **D:** Arithmetic in `unchecked {}` (>=0.8) without prior bounds check: subtraction without `require(amount <= balance)`, large multiplications. Any arithmetic in <0.8 without SafeMath.
- **FP:** Range provably bounded by earlier checks in same function. `unchecked` only for `++i` loop increments where `i < arr.length`.

**116. Token Decimal Mismatch in Cross-Token Arithmetic**

- **D:** Cross-token math uses hardcoded `1e18` or assumes identical decimals. Pattern: collateral/LTV/rate calculations combining token amounts without per-token `decimals()` normalization.
- **FP:** Amounts normalized to canonical precision (WAD/RAY) using each token's `decimals()`. Explicit `10 ** (18 - decimals())` scaling. Protocol only supports tokens with identical verified decimals.

**117. UUPS Upgrade Logic Removed in New Implementation**

- **D:** New UUPS implementation doesn't inherit `UUPSUpgradeable` or removes `upgradeTo`/`upgradeToAndCall`. Proxy permanently loses upgrade capability. Pattern: V2 missing `_authorizeUpgrade` override.
- **FP:** Every version inherits `UUPSUpgradeable`. Tests verify `upgradeTo` works after each upgrade. OZ upgrades plugin checks in CI.

**118. ERC1155 Batch Transfer Partial-State Callback Window**

- **D:** Custom batch mint/transfer updates `_balances` and calls `onERC1155Received` per ID in loop, instead of committing all updates first then calling `onERC1155BatchReceived` once. Callback reads stale balances for uncredited IDs.
- **FP:** All balance updates committed before any callback (OZ pattern). `nonReentrant` on all transfer/mint entry points.

**119. ERC1155 totalSupply Inflation via Reentrancy Before Supply Update**

- **D:** `totalSupply[id]` incremented AFTER `_mint` callback. During `onERC1155Received`, `totalSupply` is stale-low, inflating caller's share in any supply-dependent formula. Ref: OZ GHSA-9c22-pwxw-p6hx (2021).
- **FP:** OZ >= 4.3.2 (patched ordering). `nonReentrant` on all mint functions. No supply-dependent logic callable from mint callback.

**120. ERC721/ERC1155 Callback Reentrancy**

- **D:** `safeTransferFrom`/`safeMint` called before state updates. Callbacks (`onERC721Received`/`onERC1155Received`) enable reentry.
- **FP:** All state committed before safe transfer. `nonReentrant` applied.

**121. ERC4626 Mint/Redeem Asset-Cost Asymmetry**

- **D:** `redeem(s)` returns more assets than `mint(s)` costs — cycling yields net profit. Root cause: `_convertToAssets` rounds up in `redeem` and down in `mint` (opposite of EIP-4626 spec). Pattern: `previewRedeem` uses `Rounding.Ceil`, `previewMint` uses `Rounding.Floor`.
- **FP:** `redeem` uses `Math.Rounding.Floor`, `mint` uses `Math.Rounding.Ceil`. OZ ERC4626 without custom conversion overrides.

---

**123. Griefing via Dust Deposits Resetting Timelocks or Cooldowns**

- **D:** Timelock/cooldown resets on any deposit with no minimum: `lastActionTime[user] = block.timestamp` inside `deposit(uint256 amount)` without `require(amount >= MIN)`. Attacker calls `deposit(1)` to reset victim's lock indefinitely.
- **FP:** Minimum deposit enforced unconditionally. Cooldown resets only for depositing user. Lock assessed independently of deposit amounts per-user.

**124. Block Timestamp Dependence**

- **D:** `block.timestamp` used for game outcomes, randomness (`block.timestamp % N`), or auction timing where ~15s manipulation changes outcome.
- **FP:** Timestamp used only for hour/day-scale periods. Timestamp used only for event logging with no state effect.

**125. Function Selector Clash in Proxy**

- **D:** Proxy and implementation share a 4-byte selector collision. Call intended for implementation routes to proxy's function (or vice versa).
- **FP:** Transparent proxy pattern (admin/user call routing separates namespaces). UUPS with no custom proxy functions — all calls delegate unconditionally.

**126. ERC4626 Missing Allowance Check in withdraw() / redeem()**

- **D:** `withdraw(assets, receiver, owner)` / `redeem(shares, receiver, owner)` where `msg.sender != owner` but no allowance check/decrement before burning shares. Any address can burn arbitrary owner's shares.
- **FP:** `_spendAllowance(owner, caller, shares)` called unconditionally when `caller != owner`. OZ ERC4626 without custom overrides.

**128. validateUserOp Missing EntryPoint Caller Restriction**

- **D:** `validateUserOp` is `public`/`external` without `require(msg.sender == entryPoint)`. Also check `execute`/`executeBatch` for same restriction.
- **FP:** `require(msg.sender == address(_entryPoint))` or `onlyEntryPoint` modifier present. Internal visibility used.

**129. Deployment Transaction Front-Running (Ownership Hijack)**

- **D:** Deployment tx sent to public mempool without private relay. Attacker extracts bytecode and deploys first (or front-runs initialization). Pattern: `eth_sendRawTransaction` via public RPC, constructor sets `owner = msg.sender`.
- **FP:** Private relay used (Flashbots Protect, MEV Blocker). Owner passed as constructor arg, not `msg.sender`. Chain without public mempool. CREATE2 salt tied to deployer.

**130. Diamond Proxy Facet Selector Collision**

- **D:** EIP-2535 Diamond where two facets register same 4-byte selector. Malicious facet via `diamondCut` hijacks calls to critical functions. Pattern: `diamondCut` adds facet with overlapping selectors, no on-chain collision check.
- **FP:** `diamondCut` validates no selector collisions. `DiamondLoupeFacet` enumerates/verifies selectors post-cut. Multisig + timelock on `diamondCut`.

**131. ERC777 tokensToSend / tokensReceived Reentrancy**

- **D:** Token `transfer()`/`transferFrom()` called before state updates on a token that may implement ERC777 (ERC1820 registry). ERC777 hooks fire on ERC20-style calls, enabling reentry from sender's `tokensToSend` or recipient's `tokensReceived`.
- **FP:** CEI — all state committed before transfer. `nonReentrant` on all entry points. Token whitelist excludes ERC777.

**132. Deployer Privilege Retention Post-Deployment**

- **D:** Deployer EOA retains owner/admin/minter/pauser/upgrader after deployment script completes. Pattern: `Ownable` sets `owner = msg.sender` with no `transferOwnership()`. `AccessControl` grants `DEFAULT_ADMIN_ROLE` to deployer with no `renounceRole()`.
- **FP:** Script includes `transferOwnership(multisig)`. Admin role granted to timelock/governance, deployer renounces. `Ownable2Step` with pending owner set to multisig.
