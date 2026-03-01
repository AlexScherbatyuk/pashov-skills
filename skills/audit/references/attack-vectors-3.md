# Attack Vectors Reference (3/3 — Vectors 86–133)

133 total attack vectors. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

## ERC4626

**86. ERC4626 Inflation Attack (First Depositor)**

- **Detect:** Vault shares math: `shares = assets * totalSupply / totalAssets`. When `totalSupply == 0`, attacker deposits 1 wei, donates large amount to vault, victim's deposit rounds to 0 shares. No virtual offset or dead shares protection.
- **FP:** OpenZeppelin ERC4626 with `_decimalsOffset()` override. Dead shares minted to `address(0)` at init.

**87. Rounding in Favor of the Attacker**

- **Detect:** `shares = assets / pricePerShare` rounds down for the user but up for shares redeemed. First-depositor vault manipulation: when `totalSupply == 0`, attacker donates to inflate `totalAssets`, subsequent deposits round to 0 shares. Division without explicit rounding direction.
- **FP:** `Math.mulDiv(a, b, c, Rounding.Up)` used with explicit rounding direction appropriate for the operation. Virtual offset (OpenZeppelin ERC4626 `_decimalsOffset()`) prevents first-depositor attack. Dead shares minted to `address(0)` at init.

**88. ERC4626 Preview Rounding Direction Violation**

- **Detect:** `previewDeposit(a)` returns more shares than `deposit(a)` actually mints; `previewRedeem(s)` returns more assets than `redeem(s)` actually transfers; `previewMint(s)` returns fewer assets than `mint(s)` actually charges; `previewWithdraw(a)` returns fewer shares than `withdraw(a)` actually burns. EIP-4626 mandates that preview functions round in the vault's favor — they must never overstate what the user receives or understate what the user pays. Custom `_convertToShares`/`_convertToAssets` implementations that apply the wrong `Math.mulDiv` rounding direction (e.g., `Rounding.Ceil` when `Rounding.Floor` is required) violate this. Integrators that use preview return values for slippage checks will pass with an incorrect expectation and receive less than they planned for.
- **FP:** OpenZeppelin ERC4626 base used without overriding `_convertToShares`/`_convertToAssets`. Custom implementation explicitly passes `Math.Rounding.Floor` for share issuance (deposit/previewDeposit) and `Math.Rounding.Ceil` for share burning (withdraw/previewWithdraw).

**89. ERC4626 Round-Trip Profit Extraction**

- **Detect:** A full operation cycle yields strictly more than the starting amount: `redeem(deposit(a)) > a`, `deposit(redeem(s)) > s`, `mint(withdraw(a)) > a`, or `withdraw(mint(s)) > s`. Possible when rounding errors in `_convertToShares` and `_convertToAssets` both truncate in the user's favor, so no value is lost in either direction and a net gain emerges with large inputs or a manipulated share price. Combined with the first-depositor inflation attack (Vector 86), the share price can be engineered so that round-trip profit scales with the amount — enabling systematic value extraction.
- **FP:** Rounding directions satisfy EIP-4626: shares issued on deposit/mint round down (vault-favorable), shares burned on withdraw/redeem round up (vault-favorable). OpenZeppelin ERC4626 with `_decimalsOffset()` used.

**90. ERC4626 Caller-Dependent Conversion Functions**

- **Detect:** `convertToShares()` or `convertToAssets()` branches on `msg.sender`-specific state — per-user fee tiers, whitelist status, individual balances, or allowances — causing identical inputs to return different outputs for different callers. EIP-4626 requires these functions to be caller-independent. Downstream aggregators, routers, and on-chain interfaces call these functions to size positions before routing; a caller-dependent result silently produces wrong sizing for some users.
- **FP:** Implementation reads only global vault state (`totalSupply()`, `totalAssets()`, protocol-wide fee constants) with no `msg.sender`-dependent branching.

**91. ERC4626 Missing Allowance Check in withdraw() / redeem()**

- **Detect:** `withdraw(assets, receiver, owner)` or `redeem(shares, receiver, owner)` where `msg.sender != owner` but no allowance validation or decrement is performed before burning shares. EIP-4626 requires that if `caller != owner`, the caller must hold sufficient share approval; the allowance must be consumed atomically. Missing this check lets any address burn shares from an arbitrary owner and redirect the assets to any receiver — equivalent to an unchecked `transferFrom`.
- **FP:** `_spendAllowance(owner, caller, shares)` called unconditionally before the share burn when `caller != owner`. OpenZeppelin ERC4626 used without custom overrides of `withdraw`/`redeem`.

**92. ERC4626 Deposit/Withdraw Share-Count Asymmetry**

- **Detect:** For the same asset amount `a`, `withdraw(a)` burns fewer shares than `deposit(a)` minted — meaning a user can deposit, immediately withdraw the same assets, and retain surplus shares for free. Equivalently, `deposit(withdraw(a).assets)` returns more shares than `withdraw(a)` burned, manufacturing shares from nothing. Root cause: `_convertToShares` applies `Rounding.Floor` (rounds down) for both the deposit path (shares issued) and the withdraw path (shares required to burn), when EIP-4626 requires deposit to round down and withdraw to round up. The gap between the two floors is the free share. Pattern: a single `_convertToShares(assets, Rounding.Floor)` helper called on both code paths without distinct rounding arguments. (Covers `prop_RT_deposit_withdraw` and `prop_RT_withdraw_deposit` from the a16z ERC4626 property test suite.)
- **FP:** `deposit`/`previewDeposit` call `_convertToShares(assets, Math.Rounding.Floor)` and `withdraw`/`previewWithdraw` call `_convertToShares(assets, Math.Rounding.Ceil)` — opposite directions, vault-favorable in each case. OpenZeppelin ERC4626 used without custom conversion overrides.

**93. ERC4626 Mint/Redeem Asset-Cost Asymmetry**

- **Detect:** For the same share count `s`, `redeem(s)` returns more assets than `mint(s)` costs — so cycling redeem → remint yields a net profit on every loop. Equivalently, `mint(redeem(s).shares)` costs fewer assets than `redeem(s)` returned. Root cause: `_convertToAssets` rounds up in `redeem` (user receives more) and rounds down in `mint` (user pays less), the opposite of what EIP-4626 requires. The spec mandates that `redeem` rounds down (vault keeps the rounding error) and `mint` rounds up (user pays the rounding error). Pattern: `previewRedeem` and `redeem` call `_convertToAssets(shares, Rounding.Ceil)` while `previewMint` and `mint` call `_convertToAssets(shares, Rounding.Floor)`. The delta between the two is extractable per cycle. (Covers `prop_RT_mint_redeem` and `prop_RT_redeem_mint` from the a16z ERC4626 property test suite.)
- **FP:** `redeem`/`previewRedeem` call `_convertToAssets(shares, Math.Rounding.Floor)` and `mint`/`previewMint` call `_convertToAssets(shares, Math.Rounding.Ceil)`. OpenZeppelin ERC4626 used without custom conversion overrides.

---

## ERC4337

**94. validateUserOp Missing EntryPoint Caller Restriction**

- **Detect:** `validateUserOp(UserOperation calldata, bytes32, uint256)` is `public` or `external` without a guard that enforces `msg.sender == address(entryPoint)`. Anyone can call the validation function directly, bypassing the EntryPoint's replay and gas-accounting protections. Also check `execute` and `executeBatch` — they should be similarly restricted to the EntryPoint or the wallet owner.
- **FP:** Function starts with `require(msg.sender == address(_entryPoint), ...)` or uses an `onlyEntryPoint` modifier. Internal visibility used.

**95. validateUserOp Signature Not Bound to nonce or chainId**

- **Detect:** `validateUserOp` reconstructs the signed digest manually (not via `entryPoint.getUserOpHash(userOp)`) and omits `userOp.nonce` or `block.chainid` from the signed payload. Enables cross-chain replay (same signature valid on other chains sharing the contract address) or in-chain replay after the wallet state is reset. Pattern: `keccak256(abi.encode(userOp.sender, userOp.callData, ...))` without nonce/chainId.
- **FP:** Signed digest is computed via `entryPoint.getUserOpHash(userOp)` — EntryPoint includes sender, nonce, chainId, and entryPoint address. Custom digest explicitly includes `block.chainid` and `userOp.nonce`.

**96. Paymaster ERC-20 Payment Deferred to postOp Without Pre-Validation**

- **Detect:** `validatePaymasterUserOp` does not transfer tokens or lock funds — payment is deferred entirely to `postOp` via `safeTransferFrom`. Between validation and execution the user can revoke the ERC-20 allowance (or drain their balance), causing `postOp` to revert. The paymaster still owes the bundler its gas costs, losing deposit without collecting payment. Pattern: `postOp` contains `token.safeTransferFrom(user, address(this), cost)` with no corresponding lock in the validation phase.
- **FP:** Tokens are transferred or locked (e.g., via `transferFrom` into the paymaster) during `validatePaymasterUserOp` itself. `postOp` is used only to refund excess, never to collect initial payment.

**97. Paymaster Gas Penalty Undercalculation**

- **Detect:** Paymaster computes the prefund amount as `requiredPreFund + (refundPostopCost * maxFeePerGas)` without including the 10% penalty the EntryPoint applies to unused execution gas (`postOpUnusedGasPenalty`). When a UserOperation specifies a large `executionGasLimit` and uses little of it, the EntryPoint deducts a penalty the paymaster did not budget for, draining its deposit. Pattern: prefund formula lacks any reference to unused-gas penalty or `_getUnusedGasPenalty`.
- **FP:** Prefund calculation explicitly adds the unused-gas penalty: `requiredPreFund + penalty + (refundCost * price)`. Paymaster uses conservative overestimation that covers worst-case penalty.

**98. Banned Opcode in Validation Phase (Simulation-Execution Divergence)**

- **Detect:** `validateUserOp` or `validatePaymasterUserOp` references `block.timestamp`, `block.number`, `block.coinbase`, `block.prevrandao`, or `block.basefee`. Per ERC-7562, these opcodes are banned in the validation phase because their values can differ between bundler simulation (off-chain) and on-chain execution, causing ops that pass simulation to revert on-chain. The bundler pays gas for the failed inclusion.
- **FP:** Banned opcodes appear only in the execution phase (inside `execute`/`executeBatch` logic, not in validation). The entity using the banned opcode is staked and tracked under the ERC-7562 reputation system (reduces but does not eliminate risk).

**99. Counterfactual Wallet Initialization Parameters Not Bound to Deployed Address**

- **Detect:** Factory's `createAccount` uses `CREATE2` but the salt does not incorporate all initialization parameters (especially the owner address). An attacker can call `createAccount` with a different owner before the legitimate user, deploying a wallet they control to the same counterfactual address. Pattern: `salt` is a plain user-supplied value or only includes a partial subset of init data; `CREATE2` address can be predicted and front-run with different constructor args.
- **FP:** Salt is derived from all initialization parameters: `salt = keccak256(abi.encodePacked(owner, ...))`. Factory reverts if the account already exists. Initializer is called atomically in the same transaction as deployment.

**100. ERC-1271 isValidSignature Delegated to Untrusted or Arbitrary Module**

- **Detect:** `validateUserOp` or the wallet's `isValidSignature` implementation calls `isValidSignature(hash, sig)` on an externally-supplied or user-registered contract address without verifying that the contract is an explicitly whitelisted module or owner-registered guardian. A malicious module that always returns `0x1626ba7e` (ERC-1271 magic value) passes all signature checks. Pattern: `ISignatureValidator(module).isValidSignature(...)` where `module` comes from user input or an unguarded registry.
- **FP:** `isValidSignature` is only delegated to contracts in an owner-controlled whitelist or to the wallet owner's EOA address directly. Module registry has a timelock or guardian approval before a new module can validate signatures.

---

## Deployment

**101. Non-Atomic Proxy Initialization (Front-Running `initialize()`)**

- **Detect:** Deployment script deploys a proxy contract in one transaction and calls `initialize()` in a separate, subsequent transaction. Between these two transactions the proxy sits on-chain in an uninitialized state. An attacker monitoring the mempool sees the deployment, front-runs the `initialize()` call, and becomes the owner/admin of the proxy. This is the root cause of the Wormhole bridge vulnerability ($10M bounty) and the broader CPIMP (Clandestine Proxy In the Middle of Proxy) attack class. Pattern: `deploy(proxy)` followed by a separate `proxy.initialize(...)` call in the script rather than passing initialization calldata to the proxy constructor. In Foundry scripts, look for `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` bytes followed by a later `initialize()` call. In Hardhat, look for two separate `await` calls — one for deploy, one for initialize.
- **FP:** Proxy constructor receives initialization calldata as the third argument: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used, which atomically deploys and initializes. Script uses a deployer factory contract that performs deploy+init in a single on-chain transaction.

**102. Missing `_disableInitializers()` on Implementation Contract**

- **Detect:** The implementation contract behind a proxy does not call `_disableInitializers()` in its constructor. Even when the proxy is properly initialized, the implementation contract itself remains directly callable. An attacker calls `initialize()` on the implementation address (not the proxy), becomes its owner, then calls `upgradeTo()` to point it at a malicious contract containing `selfdestruct`. If the proxy delegates to this now-destroyed implementation, all calls to the proxy revert — bricking the system. This is exactly how the Wormhole whitehat exploit worked: the attacker initialized the implementation, became guardian, upgraded to a `selfdestruct` contract, and destroyed the bridge's implementation. Pattern: implementation contract inherits `Initializable` but its constructor is empty or missing. No `/// @custom:oz-upgrades-unsafe-allow constructor` + `_disableInitializers()` pair.
- **FP:** Constructor contains `_disableInitializers()`: `constructor() { _disableInitializers(); }`. Implementation uses the `@custom:oz-upgrades-unsafe-allow constructor` annotation with an explicit disable call. Contract is not behind a proxy (standalone deployment).

**103. Deployment Transaction Front-Running (Ownership Hijack)**

- **Detect:** Deployment script broadcasts a contract creation transaction to the public mempool without using a private/protected transaction relay. An attacker sees the pending deployment, extracts the bytecode, and deploys an identical contract first with themselves as the owner — or front-runs the initialization with different parameters. For token contracts, the attacker can deploy to a predictable address and pre-seed liquidity pairs to manipulate trading. Pattern: deployment transactions sent via public RPC (`eth_sendRawTransaction`) without Flashbots Protect, MEV Blocker, or a private mempool relay. Constructor sets `owner = msg.sender` or `admin = tx.origin` without additional verification.
- **FP:** Deployment uses a private transaction relay (Flashbots Protect, MEV Blocker, private mempool). Owner address is passed as a constructor argument rather than derived from `msg.sender`. Deployment is on a chain without a public mempool (e.g., Arbitrum sequencer, private L2). Contract uses CREATE2 with a salt tied to the deployer's address.

**104. Cross-Chain Deployment Replay**

- **Detect:** A deployment transaction from one EVM chain is replayed on another chain. If the deployer EOA has the same nonce on both chains, the CREATE opcode produces the same contract address on the second chain — but now controlled by whoever replayed the transaction. The Wintermute incident demonstrated this: an attacker replayed a deployment transaction across EVM-compatible chains to gain control of the same address on multiple networks. Pattern: deployer EOA reused across chains without nonce management. Deployment transactions lack EIP-155 chain ID protection. Script deploys to multiple chains from the same EOA without verifying per-chain nonce state.
- **FP:** Deployment transactions use EIP-155 (chain ID in v value of signature). Script uses `CREATE2` with a factory already deployed at the same address on all target chains (e.g., deterministic deployment proxies). Per-chain deployer EOAs or hardware wallets with chain-specific derivation paths.

**105. Hardcoded Network-Specific Addresses**

- **Detect:** Deployment script or constructor contains hardcoded addresses for external dependencies (oracles, routers, tokens, registries) that differ across networks. When the script is reused on a different chain or testnet, these addresses point to wrong contracts, EOAs, or undeployed addresses — silently misconfiguring the system. A USDC address hardcoded for Ethereum mainnet resolves to an unrelated contract (or an EOA) on Arbitrum or Polygon. Pattern: literal `address(0x...)` constants in deployment scripts or constructor arguments that represent external protocol addresses. No per-chain configuration mapping or environment variable lookup.
- **FP:** Addresses are loaded from a per-chain configuration file (JSON, TOML) keyed by chain ID. Script asserts `block.chainid` matches expected chain before using hardcoded addresses. Addresses are passed as constructor arguments from the deployment environment, not embedded in source. Deterministic addresses that are guaranteed identical across chains (e.g., CREATE2-deployed singletons like Permit2).

**106. Immutable / Constructor Argument Misconfiguration**

- **Detect:** Constructor sets `immutable` variables or critical storage values (admin address, fee basis points, token address, oracle address) that cannot be changed after deployment. If the deployment script passes wrong values — swapped argument order, wrong decimal precision, zero address, test values — the contract is permanently misconfigured with no recourse except redeployment. Pattern: constructor accepts multiple `address` parameters of the same type where argument order can be silently swapped. `immutable` variables set from constructor args without post-deployment validation. Fee parameters in basis points vs. percentage (100 vs. 10000) with no bounds checking. No deployment verification script that reads back on-chain state to confirm correct configuration.
- **FP:** Deployment script includes post-deploy assertions that read back every immutable/constructor-configured value and compare against expected values. Constructor validates arguments: `require(admin != address(0))`, `require(feeBps <= 10000)`. Integration test suite deploys and verifies the full configuration before mainnet deployment.

**107. Deployer Privilege Retention Post-Deployment**

- **Detect:** The deployer EOA retains elevated permissions (owner, admin, minter, pauser, upgrader) after the deployment script completes. The deployer's private key — which was necessarily hot during deployment — remains a single point of failure for the entire system. If the key is compromised later, the attacker inherits all admin capabilities. Pattern: deployment script calls `new Contract()` or `initialize()` but never transfers ownership to a multisig, timelock, or governance contract. `Ownable` constructor sets `owner = msg.sender` (the deployer) and no subsequent `transferOwnership()` call exists in the script. `AccessControl` grants `DEFAULT_ADMIN_ROLE` to the deployer without a later `renounceRole()`.
- **FP:** Deployment script includes explicit ownership transfer: `contract.transferOwnership(multisig)`. Admin role is granted to a timelock or governance contract, and deployer renounces its role in the same script. Two-step ownership transfer (`Ownable2Step`) used with pending owner set to the target multisig.

**108. Non-Atomic Multi-Contract Deployment (Partial System Bootstrap)**

- **Detect:** Deployment script deploys multiple interdependent contracts across separate transactions without atomic guarantees. If the script fails midway (gas exhaustion, RPC error, nonce conflict, reverted transaction), the system is left in a half-deployed state: some contracts reference addresses that don't exist yet, or contracts are deployed but not wired together. A partially deployed lending protocol might have a vault deployed but no oracle configured, allowing deposits at a zero price. Pattern: Foundry script with multiple `vm.broadcast()` blocks or Hardhat deploy script with sequential `await deploy()` calls where later deployments depend on earlier ones. No idempotency checks (does the contract already exist?) or rollback mechanism. No deployment state file tracking which steps completed.
- **FP:** Script uses a single `vm.startBroadcast()` / `vm.stopBroadcast()` block that batches all transactions atomically (note: Foundry still sends individual txs, but script halts on first failure). Deployment uses a factory contract that deploys and wires all contracts in a single transaction. Script is idempotent — checks for existing deployments before each step. Hardhat-deploy module with tagged, resumable migrations.

**109. CREATE2 Address Squatting (Counterfactual Front-Running)**

- **Detect:** A CREATE2-based deployment uses a salt that is not bound to the deployer's address (`msg.sender`). An attacker who knows the factory address, salt, and init code can precompute the deployment address and deploy there first (either via the same factory or a different one with matching parameters). For account abstraction wallets, this is especially dangerous: an attacker deploys a wallet to the user's counterfactual address with themselves as the owner, then receives funds intended for the legitimate user. Pattern: `CREATE2` salt is a user-supplied value, sequential counter, or derived from public data (e.g., `keccak256(username)`) without incorporating `msg.sender`. Factory's `deploy()` function is permissionless and does not bind salt to caller.
- **FP:** Salt incorporates `msg.sender`: `salt = keccak256(abi.encodePacked(msg.sender, userSalt))`. Factory restricts who can deploy: `require(msg.sender == authorizedDeployer)`. Init code includes owner address in constructor arguments, so different owners produce different init code hashes and thus different CREATE2 addresses.

**110. Nonce Gap from Reverted Transactions (CREATE Address Mismatch)**

- **Detect:** Deployment script uses `CREATE` (not CREATE2) and pre-computes expected contract addresses based on the deployer's nonce. If any transaction reverts or if an unrelated transaction is sent from the deployer EOA between script runs, the nonce advances but no contract is deployed. Subsequent deployments land at different addresses than expected, and contracts that were pre-configured to reference the expected addresses now point to empty addresses or wrong contracts. Pattern: script pre-computes addresses via `address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, nonce)))))` and hardcodes them into other contracts. Multiple scripts share the same deployer EOA without coordinated nonce management. Deployment script assumes a specific starting nonce.
- **FP:** `CREATE2` used with deterministic addressing (nonce-independent). Script reads current nonce from chain via `eth_getTransactionCount` before computing addresses. Addresses are captured from actual deployment receipts and passed forward, never pre-assumed. Dedicated deployer EOA used per deployment (fresh nonce = 0).

**111. Missing Chain ID Validation in Deployment Configuration**

- **Detect:** Deployment script reads RPC endpoint and chain parameters from environment variables or config files without validating that the connected chain matches the intended target. A misconfigured `RPC_URL` (e.g., mainnet URL in a staging config, or a compromised/rogue RPC endpoint) causes the script to deploy to the wrong chain with real funds, or to a chain where the deployment has different security assumptions. Pattern: script reads `$RPC_URL` from `.env` without calling `eth_chainId` and asserting it matches the expected value. Foundry script without `--chain-id` flag or `block.chainid` assertion. No dry-run or simulation step before broadcast.
- **FP:** Script asserts `require(block.chainid == expectedChainId)` at the start. Foundry `--verify` flag combined with explicit `--chain` parameter. CI/CD pipeline validates chain ID before executing deployment. Multi-chain deployment framework (e.g., Foundry multi-fork) with per-chain config validated against RPC responses.

**112. Bytecode Verification Mismatch (Source-to-Deployment Discrepancy)**

- **Detect:** The source code verified on a block explorer (Etherscan, Sourcify) does not faithfully represent the deployed bytecode's behavior. This can happen through: (a) different compiler settings (optimizer runs, EVM version) producing semantically different bytecode from the same source; (b) constructor arguments that alter behavior but are not visible in the verified source; (c) deliberately crafted source that passes verification but contains obfuscated malicious logic (e.g., a second contract in the same file with phishing/scam code verified under the victim's address). Research has shown that verification services can be abused to associate misleading source code with deployed contracts. Pattern: deployment script uses different `solc` version or optimizer settings than the verification step. Constructor arguments encode addresses or parameters not visible in source. Verification submitted with `--via-ir` but compilation used legacy pipeline (or vice versa). No reproducible build (no committed `foundry.toml` / `hardhat.config.ts` with pinned compiler settings).
- **FP:** Deterministic build: `foundry.toml` or `hardhat.config.ts` committed with pinned compiler version and optimizer settings. Verification is part of the deployment script (Foundry `--verify`, Hardhat `verify` task) using identical settings. Sourcify full match (metadata hash matches). Constructor arguments are ABI-encoded and published alongside verification.

---

## Upgradeability

**113. Uninitialized Implementation Takeover**

- **Detect:** Implementation contract has an `initialize()` function but the constructor does not call `_disableInitializers()`. Anyone can call `initialize()` directly on the implementation (not the proxy), claim ownership, then call `upgradeTo()` to replace the implementation or `selfdestruct` via delegatecall. Pattern: UUPS/Transparent/Beacon implementation with `initializer` modifier but no `_disableInitializers()` in constructor. Real-world: Wormhole Bridge (2022), Parity Multisig Library (2017, ~$150M frozen).
- **FP:** Constructor calls `_disableInitializers()`. `initializer` modifier from OpenZeppelin `Initializable` is present and correctly gates the function. Implementation verifies it is being called through a proxy before executing any logic.

**114. Storage Layout Collision Between Proxy and Implementation**

- **Detect:** Proxy contract declares state variables (e.g. `address admin`, `address implementation`) at standard sequential slots (0, 1, ...) instead of EIP-1967 randomized slots. Implementation also declares variables starting at slot 0. Proxy's admin address is non-zero so implementation reads it as `initialized = true` (or vice versa), enabling re-initialization or corrupting owner. Pattern: custom proxy with `address public admin` at slot 0; no EIP-1967 compliance. Real-world: Audius Governance (2022, ~$6M stolen -- `proxyAdmin` added to proxy storage, shadowing `initialized` flag).
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly. No state variables declared in the proxy contract itself.

**115. Storage Layout Shift on Upgrade**

- **Detect:** V2 implementation inserts a new state variable in the middle of the contract rather than appending it at the end. All subsequent variables shift to different storage slots, silently corrupting state. Pattern: V1 has `(owner, totalSupply, balances)` at slots (0, 1, 2); V2 inserts `pauser` at slot 1, pushing `totalSupply` to read from the `balances` mapping slot. Also: changing a variable's type between versions (e.g. `uint128` to `uint256`) shifts slot boundaries.
- **FP:** New variables are only appended after all existing ones. `@openzeppelin/upgrades` storage layout validation is used in CI and confirms no slot shifts. Variable types are unchanged between versions.

**116. Missing `__gap` in Upgradeable Base Contracts**

- **Detect:** Upgradeable base contract inherited by other contracts has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts every derived contract's storage layout. Pattern: `contract GovernableV1 { address public governor; }` with no gap -- adding `pendingGov` in V2 shifts all child-contract slots.
- **FP:** EIP-7201 namespaced storage used for all variables in the base contract. `__gap` array present and sized correctly (reduced by 1 for each new variable). Single-contract (non-inherited) implementation where new variables can only be appended safely.

**117. Function Selector Clashing (Proxy Backdoor)**

- **Detect:** Proxy contract contains a function whose 4-byte selector collides with a function in the implementation. Two different function signatures can produce the same selector (e.g. `burn(uint256)` and `collate_propagate_storage(bytes16)` both = `0x42966c68`). When a user calls the implementation function, the proxy's function executes instead, silently running different logic. Pattern: proxy with any non-admin functions beyond `fallback()`/`receive()` -- check all selectors against implementation selectors for collisions.
- **FP:** Transparent proxy pattern used -- admin calls always route to the proxy admin and user calls always delegate, making selector clashes between proxy and implementation impossible. UUPS proxy with no custom functions in the proxy shell -- all calls delegate unconditionally.

**118. UUPS `_authorizeUpgrade` Missing Access Control**

- **Detect:** UUPS implementation overrides `_authorizeUpgrade()` but the override body is empty or has no access-control modifier (`onlyOwner`, `onlyRole`, etc.). Anyone can call `upgradeTo()` on the proxy and replace the implementation with arbitrary code. Pattern: `function _authorizeUpgrade(address) internal override {}` with no restriction. Real-world: CVE-2021-41264 -- >$50M at risk across KeeperDAO, Rivermen NFT, and others.
- **FP:** `_authorizeUpgrade()` has `onlyOwner` or equivalent modifier. OpenZeppelin `UUPSUpgradeable` base used, which forces the override. Multi-sig or governance controls the owner role.

**119. `selfdestruct` via Delegatecall Bricking**

- **Detect:** Implementation contract contains `selfdestruct`, or allows `delegatecall` to an arbitrary address that may contain `selfdestruct`. If an attacker gains execution in the implementation context (e.g. via uninitialized takeover), they can call `selfdestruct` which executes in the proxy's context, permanently bricking it. For UUPS, the upgrade logic is destroyed with the implementation -- no recovery. Pattern: `selfdestruct(...)` anywhere in implementation code, or `target.delegatecall(data)` where `target` is user-supplied. Real-world: Parity (2017), Wormhole (2022). Post-Dencun (EIP-6780): `selfdestruct` only fully deletes contracts created in the same transaction -- mitigates but does not fully eliminate this vector.
- **FP:** No `selfdestruct` opcode in implementation or any contract it delegatecalls to. No arbitrary delegatecall targets. `_disableInitializers()` called in constructor.

**120. Re-initialization Attack**

- **Detect:** Initialization guard is improperly implemented or reset during an upgrade, allowing `initialize()` to be called again to overwrite critical state (owner, token addresses, rates). Pattern: V2 uses `initializer` modifier instead of `reinitializer(2)` on its new init function; upgrade resets the initialized version counter; custom initialization flag uses a `bool` that gets storage-collided to `false`. Real-world: AllianceBlock (2024) -- upgrade reset `initialized` to false, attacker re-invoked initializer.
- **FP:** OpenZeppelin's `reinitializer(version)` used for V2+ initialization with correctly incrementing version numbers. `initializer` modifier on original init, `reinitializer(N)` on subsequent versions. Integration tests verify `initialize()` reverts after first call.

**121. Proxy Admin Key Compromise**

- **Detect:** Proxy admin (the address authorized to call `upgradeTo`) is a single EOA rather than a multisig or governance contract. A compromised private key allows instant upgrade to a malicious implementation that drains all funds. Pattern: `ProxyAdmin.owner()` returns an EOA; no timelock between upgrade proposal and execution. Real-world: PAID Network (2021) -- attacker obtained admin key, upgraded token proxy to mint unlimited tokens; Ankr (2022) -- compromised deployer key, minted 6 quadrillion aBNBc (~$5M loss).
- **FP:** Admin is a multisig (Gnosis Safe) with threshold >= 2. Timelock enforced (24-72h delay). Proxy admin role is separate from operational roles. Admin key rotation and monitoring in place.

**122. Beacon Proxy Single-Point-of-Failure Upgrade**

- **Detect:** Multiple proxies read their implementation address from a single Beacon contract. Compromising the Beacon owner upgrades all proxies simultaneously. Pattern: `UpgradeableBeacon` with `owner()` returning a single EOA; tens or hundreds of `BeaconProxy` instances pointing to it. A single `upgradeTo()` on the Beacon replaces logic for every proxy at once.
- **FP:** Beacon owner is a multisig + timelock. `Upgraded` events on the Beacon are monitored for unauthorized changes. Per-proxy upgrade authority used where risk tolerance requires isolation.

**123. Metamorphic Contract via CREATE2 + SELFDESTRUCT**

- **Detect:** Contract deployed via `CREATE2` from a factory where the deployer can `selfdestruct` the contract and redeploy different bytecode to the same address. Governance voters verify code at proposal time, but the code can be swapped before execution. Pattern: `create2(0, ..., salt)` deployment + `selfdestruct` in the deployed contract or an intermediate deployer that resets its nonce. Real-world: Tornado Cash Governance (May 2023) -- attacker proposed legitimate contract, `selfdestruct`-ed it, redeployed malicious code at same address, gained 1.2M governance votes, drained ~$2.17M. Post-Dencun (EIP-6780): largely killed for pre-existing contracts, but same-transaction create-destroy-recreate may still work.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless same transaction as creation. `EXTCODEHASH` verified at execution time, not just proposal time. Contract was not deployed via `CREATE2` from a mutable deployer.

**124. Immutable Variable Context Mismatch**

- **Detect:** Implementation contract uses `immutable` variables set in its constructor. These are embedded in bytecode, not storage -- so when a proxy `delegatecall`s, it gets the implementation's hardcoded values regardless of per-proxy configuration needs. If the implementation is shared across multiple proxies or chains, all proxies see the same immutable values. Pattern: `address public immutable WETH` in implementation constructor -- every proxy gets the same WETH address regardless of chain.
- **FP:** Immutable values are intentionally identical across all proxies (e.g. a protocol-wide constant). Per-proxy configuration uses storage variables set in `initialize()`. Implementation is purpose-deployed per proxy with correct constructor args.

**125. Diamond Proxy Facet Selector Collision**

- **Detect:** EIP-2535 Diamond proxy where two facets register functions with the same 4-byte selector. One facet silently shadows the other. A malicious facet added via `diamondCut` can hijack calls intended for critical functions like `withdraw()` or `transfer()`. Pattern: `diamondCut` adds a new facet whose function selectors overlap with existing facets without on-chain collision validation.
- **FP:** `diamondCut` implementation validates no selector collisions before adding/replacing facets. `DiamondLoupeFacet` used to enumerate and verify all selectors post-cut. Multisig + timelock required for `diamondCut` operations.

**126. Diamond Shared-Storage Cross-Facet Corruption**

- **Detect:** EIP-2535 Diamond proxy where facets declare storage variables without EIP-7201 namespaced storage structs -- each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, .... Different facets independently start at slot 0, so both write to the same slot. A compromised or buggy facet can corrupt the entire Diamond's state. Pattern: facet with top-level state variable declarations (no `DiamondStorage` struct at a namespaced slot).
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**127. Arbitrary `delegatecall` in Implementation**

- **Detect:** Implementation exposes a function that performs `delegatecall` to a user-supplied address, allowing arbitrary bytecode execution in the proxy's storage context -- overwriting owner, balances, or bricking the contract. Pattern: `function execute(address target, bytes calldata data) external { target.delegatecall(data); }` where `target` is not restricted. Real-world: Furucombo (2021, $14M stolen via unrestricted delegatecall to user-supplied handler addresses).
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment. Whitelist of approved delegatecall targets enforced. `call` used instead of `delegatecall` for external integrations.

**128. Governance Flash-Loan Upgrade Hijack**

- **Detect:** Proxy upgrades controlled by on-chain governance that uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block) for vote weight. Attacker flash-borrows governance tokens, self-delegates, votes to approve a malicious upgrade, and executes -- all within one transaction or block if no timelock. Pattern: Governor with no voting delay, no timelock, or snapshot at current block.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock of 24-72h between proposal and execution. Quorum thresholds high enough to resist flash loan manipulation. Staking lockup required before voting power is active.

**129. Transparent Proxy Admin Routing Confusion**

- **Detect:** Transparent proxy routes calls from the admin address to proxy admin functions, and all other calls to the implementation. If the admin address accidentally interacts with the protocol as a user (e.g. deposits, withdraws), the call hits proxy admin routing instead of being delegated -- silently failing or executing unintended logic. Pattern: admin EOA or contract also used for regular protocol interactions; `ProxyAdmin` contract doubles as treasury or operator.
- **FP:** Dedicated `ProxyAdmin` contract used exclusively for admin calls, never for protocol interaction. OpenZeppelin `TransparentUpgradeableProxy` pattern enforces separate admin contract. Admin address documented and known to never make user-facing calls.

**130. UUPS Upgrade Logic Removed in New Implementation**

- **Detect:** New UUPS implementation version does not inherit `UUPSUpgradeable` or removes `upgradeTo()`/`upgradeToAndCall()`. After upgrading, the proxy permanently loses upgrade capability -- no further upgrades possible, contract is bricked at current version. Pattern: V2 inherits `OwnableUpgradeable` but not `UUPSUpgradeable`; no `_authorizeUpgrade` override; `upgradeTo` function absent from V2 ABI.
- **FP:** Every implementation version inherits `UUPSUpgradeable`. Integration tests verify `upgradeTo` works after each upgrade. `@openzeppelin/upgrades` plugin upgrade safety checks used in CI.

**131. Minimal Proxy (EIP-1167) Implementation Destruction**

- **Detect:** EIP-1167 minimal proxies (clones) permanently `delegatecall` to a fixed implementation address with no upgrade mechanism. If the implementation is destroyed (`selfdestruct` pre-Dencun) or becomes non-functional, every clone is permanently bricked -- calls return success with no effect (empty code = no-op), funds are permanently locked. Pattern: `Clones.clone(implementation)` or `Clones.cloneDeterministic(...)` where the implementation contract has no protection against `selfdestruct` or is not initialized.
- **FP:** Implementation contract has no `selfdestruct` opcode and no path to one via delegatecall. `_disableInitializers()` called in implementation constructor. Post-Dencun (EIP-6780): `selfdestruct` no longer destroys pre-existing code. Beacon proxies used instead when future upgradeability is needed.

**132. Upgrade Race Condition / Front-Running**

- **Detect:** Upgrade transaction submitted to a public mempool, creating a window for front-running (exploit old implementation before upgrade lands) or back-running (exploit assumptions the new implementation breaks). Multi-step upgrades are especially dangerous: `upgradeTo(V2)` lands in block N but `setNewParams(...)` is still pending -- attacker sandwiches between them. Pattern: `upgradeTo()` and post-upgrade configuration calls are separate transactions; no private mempool or bundling used; V2 is not safe with V1's state parameters.
- **FP:** Upgrade + initialization bundled into a single `upgradeToAndCall()` invocation. Flashbots Protect or private mempool used for upgrade transactions. V2 designed to be safe with V1's state from block 0. Timelock makes execution block predictable and protectable.

**133. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **Detect:** Deployment script deploys a proxy in one transaction and calls `initialize()` in a separate one, creating a window where an attacker front-runs initialization and inserts a malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in the ERC-1967 slot after each delegatecall. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` followed by a separate `proxy.initialize(...)`. In Foundry: `new ERC1967Proxy(address(impl), "")` then a later `initialize()`. In Hardhat: two separate `await` calls for deploy and initialize.
- **FP:** Proxy constructor receives initialization calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used. `_disableInitializers()` called in implementation constructor.
