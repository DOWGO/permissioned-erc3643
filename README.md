# identityhook — ERC-3643 ↔ Uniswap v4 PermissionedPools bridge

This repository contains the on-chain glue that lets an [ERC-3643 (T-REX)](https://github.com/TokenySolutions/T-REX)
permissioned token trade inside a [Uniswap v4 PermissionedPools](https://github.com/Uniswap/v4-periphery)
pool. The bridge is a single contract, **`TREXAllowlistChecker`**, that translates ERC-3643 verification
into the v4 `PermissionFlag` model consumed by the Uniswap-official `PermissionsAdapter`.

## Repository contents

| Path | Notes |
|------|-------|
| `src/TREXAllowlistChecker.sol` | The ERC-3643 → `PermissionFlag` bridge. ~130 lines, no state, `view`-only. |
| `src/PermissionedDeployer.sol` | Import-only compilation shim: forces upstream PermissionedPools artifacts into `out/` for an off-chain SPA. Not deployable, no logic. |
| `lib/v4-core` | Uniswap v4 core, a git submodule pinned to public upstream. |
| `lib/v4-periphery` | Uniswap periphery (the PermissionedPools primitive), committed in-tree. Trust root. |
| `test/**` | Unit + integration + live-fork tests demonstrating the intended behavior. |

## What `TREXAllowlistChecker` does

`checkAllowlist(account, tokenAddress)` returns a `PermissionFlag`:

- **`SWAP_ALLOWED`** iff the token's `IdentityRegistry.isVerified(account)` is true. Full ERC-3643
  verification (all required claim topics, valid + non-revoked) is delegated to the registry.
- **`LIQUIDITY_ALLOWED`** additionally iff `account`'s OnchainID holds a **valid** claim on the
  configured `LP_CLAIM_TOPIC`. Validity is checked the same way ERC-3643's `IdentityRegistry.isVerified`
  does: the claim must come from an issuer in the token's `TrustedIssuersRegistry` and pass
  `IClaimIssuer.isClaimValid` (not merely exist). The claim body must additionally *name* the trusted
  issuer its claim id was derived from — validity is re-derived from the registry, never taken from the
  identity's self-reported record.

The contract holds no funds, has no owner/admin surface, and makes only `view` external calls into the
token's own registry-governed contracts.

### `checkAllowlist` never reverts

The checker runs **inside** the PoolManager's `beforeSwap` / `beforeAddLiquidity` callback. A revert
there is not a denial — it bricks the pool for everyone, including LPs trying to exit. `checkAllowlist`
is therefore a total function, and every failure degrades to a strictly lower-or-equal permission:

- The swap decision (`identityRegistry()`, `isVerified()`) is read through low-level staticcalls with a
  fixed 32-byte output buffer and an explicit `returndatasize` check. Oversized return data is never
  copied, a missing contract is detected, and there is no ABI decode left to fail — `try/catch` cannot
  guard a decode, since it runs in the caller's own frame.
- The LP decision runs in an isolated, gas-bounded self-staticcall (`probeLpClaim`). A reverting
  registry, a broken OnchainID, a malformed claim tuple, a return bomb or a gas-devouring issuer costs
  the liquidity flag and nothing else. **The two flags are decided independently: an LP-side failure
  can never destroy a verified user's swap right.**

`probeLpClaim` is public and side-effect free, so a denied liquidity flag stays diagnosable off-chain.

## Trust model

- **Gating is router-gated, not `tx.origin`-based.** The upstream `PermissionedHooks` reads the real
  trader via `IMsgSender(sender).msgSender()` and requires `sender` to be in the adapter's
  `allowedWrappers`. The single point of trust is the adapter owner who whitelists routers — only
  Uniswap's official Universal Router / `PermissionedPositionManager` should ever be allowed.
- **`LP_CLAIM_TOPIC`** is an immutable constructor argument (must be non-zero) — the checker is
  deployed once per intended LP claim topic.
- The checker's trust root is whatever `tokenAddress` reports as its `identityRegistry()` and, in turn,
  that registry's `issuersRegistry()`. Wrapping a hostile token is out of the checker's control (that is
  the adapter owner's responsibility); the checker degrades safely (returns `NONE`/`SWAP_ALLOWED`).
- The **OnchainID is untrusted**: it is user-controlled and may return a forged `issuer`/`signature`/
  `data` tuple, revert, or return unbounded data. Only the `TrustedIssuersRegistry` decides who may
  attest an LP claim.
- **Claim issuers are semi-trusted**: registry-curated, but arbitrary third-party contracts. One that
  reverts, returns a malformed answer or burns gas denies its own claim holders their liquidity flag —
  it cannot deny anyone their swap right, nor stall the pool.

## Official PermissionedPools deployment (Sepolia)

The bridge is designed against Uniswap's officially-deployed contracts:

| Contract | Address |
|----------|---------|
| `PermissionsAdapterFactory` | `0xEe258C31574fb59660C23534E76AF6497c2e5683` |
| `PermissionedHooks` | `0x8B0E8d467af81D9F5B49165e104a2fe1b98328C0` |
| `PoolManager` | `0xE03A1074c86CFeDd5C142C4F04F1a1536e203543` |

## Build & test

`lib/v4-periphery` is committed in-tree, but `lib/v4-core` is a submodule — **clone recursively or
`forge build` will fail**. Requires [Foundry](https://book.getfoundry.sh/) (solc 0.8.26,
`evm_version = cancun`, `via_ir = true`).

```bash
git submodule update --init --recursive   # or clone with --recursive
forge build
forge test          # unit + integration; the live-fork suite is skipped offline
forge fmt --check
```

The live-fork suite (`test/OfficialDeploymentFork.t.sol`) asserts the bridge against the **real** Sepolia
contracts above and runs only when `SEPOLIA_RPC_URL` is set:

```bash
SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com forge test --match-path test/OfficialDeploymentFork.t.sol
```

## License

[MIT](./LICENSE).
