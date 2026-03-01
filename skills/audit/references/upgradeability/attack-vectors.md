# Upgradeability & Proxy Attack Vectors

21 attack vectors targeting Solidity upgradeability patterns and proxy contracts. For each: detection pattern (what to look for in code) and false-positive signals (what makes it NOT a vulnerability even if the pattern matches).

---

**1. Uninitialized Implementation Takeover**

- **Detect:** Implementation contract has an `initialize()` function but the constructor does not call `_disableInitializers()`. Anyone can call `initialize()` directly on the implementation (not the proxy), claim ownership, then call `upgradeTo()` to replace the implementation or `selfdestruct` via delegatecall. Pattern: UUPS/Transparent/Beacon implementation with `initializer` modifier but no `_disableInitializers()` in constructor. Real-world: Wormhole Bridge (2022), Parity Multisig Library (2017, ~$150M frozen).
- **FP:** Constructor calls `_disableInitializers()`. `initializer` modifier from OpenZeppelin `Initializable` is present and correctly gates the function. Implementation verifies it is being called through a proxy before executing any logic.

**2. Storage Layout Collision Between Proxy and Implementation**

- **Detect:** Proxy contract declares state variables (e.g. `address admin`, `address implementation`) at standard sequential slots (0, 1, ...) instead of EIP-1967 randomized slots. Implementation also declares variables starting at slot 0. Proxy's admin address is non-zero so implementation reads it as `initialized = true` (or vice versa), enabling re-initialization or corrupting owner. Pattern: custom proxy with `address public admin` at slot 0; no EIP-1967 compliance. Real-world: Audius Governance (2022, ~$6M stolen -- `proxyAdmin` added to proxy storage, shadowing `initialized` flag).
- **FP:** Proxy uses EIP-1967 slots (`keccak256("eip1967.proxy.implementation") - 1`). OpenZeppelin Transparent or UUPS proxy pattern used correctly. No state variables declared in the proxy contract itself.

**3. Storage Layout Shift on Upgrade**

- **Detect:** V2 implementation inserts a new state variable in the middle of the contract rather than appending it at the end. All subsequent variables shift to different storage slots, silently corrupting state. Pattern: V1 has `(owner, totalSupply, balances)` at slots (0, 1, 2); V2 inserts `pauser` at slot 1, pushing `totalSupply` to read from the `balances` mapping slot. Also: changing a variable's type between versions (e.g. `uint128` to `uint256`) shifts slot boundaries.
- **FP:** New variables are only appended after all existing ones. `@openzeppelin/upgrades` storage layout validation is used in CI and confirms no slot shifts. Variable types are unchanged between versions.

**4. Missing `__gap` in Upgradeable Base Contracts**

- **Detect:** Upgradeable base contract inherited by other contracts has no `uint256[N] private __gap;` at the end. A future version adding state variables to the base shifts every derived contract's storage layout. Pattern: `contract GovernableV1 { address public governor; }` with no gap -- adding `pendingGov` in V2 shifts all child-contract slots.
- **FP:** EIP-7201 namespaced storage used for all variables in the base contract. `__gap` array present and sized correctly (reduced by 1 for each new variable). Single-contract (non-inherited) implementation where new variables can only be appended safely.

**5. Function Selector Clashing (Proxy Backdoor)**

- **Detect:** Proxy contract contains a function whose 4-byte selector collides with a function in the implementation. Two different function signatures can produce the same selector (e.g. `burn(uint256)` and `collate_propagate_storage(bytes16)` both = `0x42966c68`). When a user calls the implementation function, the proxy's function executes instead, silently running different logic. Pattern: proxy with any non-admin functions beyond `fallback()`/`receive()` -- check all selectors against implementation selectors for collisions.
- **FP:** Transparent proxy pattern used -- admin calls always route to the proxy admin and user calls always delegate, making selector clashes between proxy and implementation impossible. UUPS proxy with no custom functions in the proxy shell -- all calls delegate unconditionally.

**6. UUPS `_authorizeUpgrade` Missing Access Control**

- **Detect:** UUPS implementation overrides `_authorizeUpgrade()` but the override body is empty or has no access-control modifier (`onlyOwner`, `onlyRole`, etc.). Anyone can call `upgradeTo()` on the proxy and replace the implementation with arbitrary code. Pattern: `function _authorizeUpgrade(address) internal override {}` with no restriction. Real-world: CVE-2021-41264 -- >$50M at risk across KeeperDAO, Rivermen NFT, and others.
- **FP:** `_authorizeUpgrade()` has `onlyOwner` or equivalent modifier. OpenZeppelin `UUPSUpgradeable` base used, which forces the override. Multi-sig or governance controls the owner role.

**7. `selfdestruct` via Delegatecall Bricking**

- **Detect:** Implementation contract contains `selfdestruct`, or allows `delegatecall` to an arbitrary address that may contain `selfdestruct`. If an attacker gains execution in the implementation context (e.g. via uninitialized takeover), they can call `selfdestruct` which executes in the proxy's context, permanently bricking it. For UUPS, the upgrade logic is destroyed with the implementation -- no recovery. Pattern: `selfdestruct(...)` anywhere in implementation code, or `target.delegatecall(data)` where `target` is user-supplied. Real-world: Parity (2017), Wormhole (2022). Post-Dencun (EIP-6780): `selfdestruct` only fully deletes contracts created in the same transaction -- mitigates but does not fully eliminate this vector.
- **FP:** No `selfdestruct` opcode in implementation or any contract it delegatecalls to. No arbitrary delegatecall targets. `_disableInitializers()` called in constructor.

**8. Re-initialization Attack**

- **Detect:** Initialization guard is improperly implemented or reset during an upgrade, allowing `initialize()` to be called again to overwrite critical state (owner, token addresses, rates). Pattern: V2 uses `initializer` modifier instead of `reinitializer(2)` on its new init function; upgrade resets the initialized version counter; custom initialization flag uses a `bool` that gets storage-collided to `false`. Real-world: AllianceBlock (2024) -- upgrade reset `initialized` to false, attacker re-invoked initializer.
- **FP:** OpenZeppelin's `reinitializer(version)` used for V2+ initialization with correctly incrementing version numbers. `initializer` modifier on original init, `reinitializer(N)` on subsequent versions. Integration tests verify `initialize()` reverts after first call.

**9. Proxy Admin Key Compromise**

- **Detect:** Proxy admin (the address authorized to call `upgradeTo`) is a single EOA rather than a multisig or governance contract. A compromised private key allows instant upgrade to a malicious implementation that drains all funds. Pattern: `ProxyAdmin.owner()` returns an EOA; no timelock between upgrade proposal and execution. Real-world: PAID Network (2021) -- attacker obtained admin key, upgraded token proxy to mint unlimited tokens; Ankr (2022) -- compromised deployer key, minted 6 quadrillion aBNBc (~$5M loss).
- **FP:** Admin is a multisig (Gnosis Safe) with threshold >= 2. Timelock enforced (24-72h delay). Proxy admin role is separate from operational roles. Admin key rotation and monitoring in place.

**10. Beacon Proxy Single-Point-of-Failure Upgrade**

- **Detect:** Multiple proxies read their implementation address from a single Beacon contract. Compromising the Beacon owner upgrades all proxies simultaneously. Pattern: `UpgradeableBeacon` with `owner()` returning a single EOA; tens or hundreds of `BeaconProxy` instances pointing to it. A single `upgradeTo()` on the Beacon replaces logic for every proxy at once.
- **FP:** Beacon owner is a multisig + timelock. `Upgraded` events on the Beacon are monitored for unauthorized changes. Per-proxy upgrade authority used where risk tolerance requires isolation.

**11. Metamorphic Contract via CREATE2 + SELFDESTRUCT**

- **Detect:** Contract deployed via `CREATE2` from a factory where the deployer can `selfdestruct` the contract and redeploy different bytecode to the same address. Governance voters verify code at proposal time, but the code can be swapped before execution. Pattern: `create2(0, ..., salt)` deployment + `selfdestruct` in the deployed contract or an intermediate deployer that resets its nonce. Real-world: Tornado Cash Governance (May 2023) -- attacker proposed legitimate contract, `selfdestruct`-ed it, redeployed malicious code at same address, gained 1.2M governance votes, drained ~$2.17M. Post-Dencun (EIP-6780): largely killed for pre-existing contracts, but same-transaction create-destroy-recreate may still work.
- **FP:** Post-Dencun (EIP-6780): `selfdestruct` no longer destroys code unless same transaction as creation. `EXTCODEHASH` verified at execution time, not just proposal time. Contract was not deployed via `CREATE2` from a mutable deployer.

**12. Immutable Variable Context Mismatch**

- **Detect:** Implementation contract uses `immutable` variables set in its constructor. These are embedded in bytecode, not storage -- so when a proxy `delegatecall`s, it gets the implementation's hardcoded values regardless of per-proxy configuration needs. If the implementation is shared across multiple proxies or chains, all proxies see the same immutable values. Pattern: `address public immutable WETH` in implementation constructor -- every proxy gets the same WETH address regardless of chain.
- **FP:** Immutable values are intentionally identical across all proxies (e.g. a protocol-wide constant). Per-proxy configuration uses storage variables set in `initialize()`. Implementation is purpose-deployed per proxy with correct constructor args.

**13. Diamond Proxy Facet Selector Collision**

- **Detect:** EIP-2535 Diamond proxy where two facets register functions with the same 4-byte selector. One facet silently shadows the other. A malicious facet added via `diamondCut` can hijack calls intended for critical functions like `withdraw()` or `transfer()`. Pattern: `diamondCut` adds a new facet whose function selectors overlap with existing facets without on-chain collision validation.
- **FP:** `diamondCut` implementation validates no selector collisions before adding/replacing facets. `DiamondLoupeFacet` used to enumerate and verify all selectors post-cut. Multisig + timelock required for `diamondCut` operations.

**14. Diamond Shared-Storage Cross-Facet Corruption**

- **Detect:** EIP-2535 Diamond proxy where facets declare storage variables without EIP-7201 namespaced storage structs -- each facet using plain `uint256 foo` or `mapping(...)` declarations that Solidity places at sequential storage slots 0, 1, 2, .... Different facets independently start at slot 0, so both write to the same slot. A compromised or buggy facet can corrupt the entire Diamond's state. Pattern: facet with top-level state variable declarations (no `DiamondStorage` struct at a namespaced slot).
- **FP:** All facets store state exclusively in a single `DiamondStorage` struct retrieved via `assembly { ds.slot := DIAMOND_STORAGE_POSITION }` using a namespaced position (EIP-7201 formula). No facet declares top-level state variables. OpenZeppelin's ERC-7201 `@custom:storage-location` pattern used correctly.

**15. Arbitrary `delegatecall` in Implementation**

- **Detect:** Implementation exposes a function that performs `delegatecall` to a user-supplied address, allowing arbitrary bytecode execution in the proxy's storage context -- overwriting owner, balances, or bricking the contract. Pattern: `function execute(address target, bytes calldata data) external { target.delegatecall(data); }` where `target` is not restricted. Real-world: Furucombo (2021, $14M stolen via unrestricted delegatecall to user-supplied handler addresses).
- **FP:** `target` is a hardcoded immutable verified library address that cannot be changed after deployment. Whitelist of approved delegatecall targets enforced. `call` used instead of `delegatecall` for external integrations.

**16. Governance Flash-Loan Upgrade Hijack**

- **Detect:** Proxy upgrades controlled by on-chain governance that uses `token.balanceOf(msg.sender)` or `getPastVotes(account, block.number)` (current block) for vote weight. Attacker flash-borrows governance tokens, self-delegates, votes to approve a malicious upgrade, and executes -- all within one transaction or block if no timelock. Pattern: Governor with no voting delay, no timelock, or snapshot at current block.
- **FP:** Uses `getPastVotes(account, block.number - 1)` (prior block, un-manipulable in current tx). Timelock of 24-72h between proposal and execution. Quorum thresholds high enough to resist flash loan manipulation. Staking lockup required before voting power is active.

**17. Transparent Proxy Admin Routing Confusion**

- **Detect:** Transparent proxy routes calls from the admin address to proxy admin functions, and all other calls to the implementation. If the admin address accidentally interacts with the protocol as a user (e.g. deposits, withdraws), the call hits proxy admin routing instead of being delegated -- silently failing or executing unintended logic. Pattern: admin EOA or contract also used for regular protocol interactions; `ProxyAdmin` contract doubles as treasury or operator.
- **FP:** Dedicated `ProxyAdmin` contract used exclusively for admin calls, never for protocol interaction. OpenZeppelin `TransparentUpgradeableProxy` pattern enforces separate admin contract. Admin address documented and known to never make user-facing calls.

**18. UUPS Upgrade Logic Removed in New Implementation**

- **Detect:** New UUPS implementation version does not inherit `UUPSUpgradeable` or removes `upgradeTo()`/`upgradeToAndCall()`. After upgrading, the proxy permanently loses upgrade capability -- no further upgrades possible, contract is bricked at current version. Pattern: V2 inherits `OwnableUpgradeable` but not `UUPSUpgradeable`; no `_authorizeUpgrade` override; `upgradeTo` function absent from V2 ABI.
- **FP:** Every implementation version inherits `UUPSUpgradeable`. Integration tests verify `upgradeTo` works after each upgrade. `@openzeppelin/upgrades` plugin upgrade safety checks used in CI.

**19. Minimal Proxy (EIP-1167) Implementation Destruction**

- **Detect:** EIP-1167 minimal proxies (clones) permanently `delegatecall` to a fixed implementation address with no upgrade mechanism. If the implementation is destroyed (`selfdestruct` pre-Dencun) or becomes non-functional, every clone is permanently bricked -- calls return success with no effect (empty code = no-op), funds are permanently locked. Pattern: `Clones.clone(implementation)` or `Clones.cloneDeterministic(...)` where the implementation contract has no protection against `selfdestruct` or is not initialized.
- **FP:** Implementation contract has no `selfdestruct` opcode and no path to one via delegatecall. `_disableInitializers()` called in implementation constructor. Post-Dencun (EIP-6780): `selfdestruct` no longer destroys pre-existing code. Beacon proxies used instead when future upgradeability is needed.

**20. Upgrade Race Condition / Front-Running**

- **Detect:** Upgrade transaction submitted to a public mempool, creating a window for front-running (exploit old implementation before upgrade lands) or back-running (exploit assumptions the new implementation breaks). Multi-step upgrades are especially dangerous: `upgradeTo(V2)` lands in block N but `setNewParams(...)` is still pending -- attacker sandwiches between them. Pattern: `upgradeTo()` and post-upgrade configuration calls are separate transactions; no private mempool or bundling used; V2 is not safe with V1's state parameters.
- **FP:** Upgrade + initialization bundled into a single `upgradeToAndCall()` invocation. Flashbots Protect or private mempool used for upgrade transactions. V2 designed to be safe with V1's state from block 0. Timelock makes execution block predictable and protectable.

**21. Non-Atomic Proxy Deployment Enabling CPIMP Takeover**

- **Detect:** Deployment script deploys a proxy in one transaction and calls `initialize()` in a separate one, creating a window where an attacker front-runs initialization and inserts a malicious middleman implementation (CPIMP) that persists across upgrades by restoring itself in the ERC-1967 slot after each delegatecall. Pattern: `new TransparentUpgradeableProxy(impl, admin, "")` with empty `data` followed by a separate `proxy.initialize(...)`. In Foundry: `new ERC1967Proxy(address(impl), "")` then a later `initialize()`. In Hardhat: two separate `await` calls for deploy and initialize.
- **FP:** Proxy constructor receives initialization calldata atomically: `new TransparentUpgradeableProxy(impl, admin, abi.encodeCall(Contract.initialize, (...)))`. OpenZeppelin `deployProxy()` helper used. `_disableInitializers()` called in implementation constructor.
