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
| `lib/v4-core`, `lib/v4-periphery` | Vendored Uniswap contracts (the PermissionedPools primitive). Trust root. |
| `test/**` | Unit + integration + live-fork tests demonstrating the intended behavior. |

## What `TREXAllowlistChecker` does

`checkAllowlist(account, tokenAddress)` returns a `PermissionFlag`:

- **`SWAP_ALLOWED`** iff the token's `IdentityRegistry.isVerified(account)` is true. Full ERC-3643
  verification (all required claim topics, valid + non-revoked) is delegated to the registry.
- **`LIQUIDITY_ALLOWED`** additionally iff `account`'s OnchainID holds a **valid** claim on the
  configured `LP_CLAIM_TOPIC`. Validity is checked the same way ERC-3643's `IdentityRegistry.isVerified`
  does: the claim must come from an issuer in the token's `TrustedIssuersRegistry` and pass
  `IClaimIssuer.isClaimValid` (not merely exist). A hostile/broken issuer is tolerated via `try/catch`.

The contract holds no funds, has no owner/admin surface, and makes only `view` external calls into the
token's own registry-governed contracts.

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

## Official PermissionedPools deployment (Sepolia)

The bridge is designed against Uniswap's officially-deployed contracts:

| Contract | Address |
|----------|---------|
| `PermissionsAdapterFactory` | `0xEe258C31574fb59660C23534E76AF6497c2e5683` |
| `PermissionedHooks` | `0x8B0E8d467af81D9F5B49165e104a2fe1b98328C0` |
| `PoolManager` | `0xE03A1074c86CFeDd5C142C4F04F1a1536e203543` |

## Build & test

Vendored dependencies are committed under `lib/` — the repo is self-contained, no submodule init needed.
Requires [Foundry](https://book.getfoundry.sh/) (solc 0.8.26, `evm_version = cancun`, `via_ir = true`).

```bash
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
