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

- **`SWAP_ALLOWED`** iff the token's `IdentityRegistry.isVerified(account)` is true **and** the token's
  own emergency controls are readable and permit the account. Full ERC-3643 verification (all required
  claim topics, valid + non-revoked) is delegated to the registry; the emergency controls are read from
  the token, because they live in its storage and the registry knows nothing of them.
- **`LIQUIDITY_ALLOWED`** additionally iff `account`'s OnchainID holds a **valid** claim on the
  configured `LP_CLAIM_TOPIC`. Validity is checked the same way ERC-3643's `IdentityRegistry.isVerified`
  does: the claim must come from an issuer in the token's `TrustedIssuersRegistry` and pass
  `IClaimIssuer.isClaimValid` (not merely exist). The claim body must additionally *name* the trusted
  issuer its claim id was derived from — validity is re-derived from the registry, never taken from the
  identity's self-reported record.

The contract holds no funds, has no owner/admin surface, and makes only `view` external calls into the
token's own registry-governed contracts.

### Token emergency controls are part of the swap decision

`isVerified` stays `true` through a global pause and through an address freeze: both live in the
token's storage, not the registry's. That is normally backstopped by the token itself, since the
underlying moves whenever the adapter wraps on settle or unwraps on take. It is **not** backstopped
when the adapter is an *intermediate* currency: `V4Router` chains hops by assigning
`amountIn = amountOut`, so the adapter's deltas cancel inside the `PoolManager`, nothing is wrapped or
unwrapped, and the ERC-3643 token is never called. `checkAllowlist` therefore reads the controls
itself, through `probeTokenControls` — public and side-effect free, so a denial stays diagnosable
off-chain.

Denied: `paused()` and `isFrozen(account)`.

Deliberately **not** covered:

- **A partial freeze is not read, at any size — full immobilisation included.** `Token.transfer`
  applies `_frozenTokens[from]` to the sender only, while `setAddressFrozen` is tested on `_to` as
  well, so a fully immobilised holder can still receive on the token itself. A `PermissionFlag`
  carries no direction, so denying here would refuse an acquisition the asset permits. An agent that
  wants the account out of the venue entirely has `setAddressFrozen`, which is honoured.
  `freezePartialTokens` is a balance control, not an admission control, and has no venue-level
  effect — that is an operating rule for agents, not something the checker can enforce.
- **`ICompliance.canTransfer` and the counterparty's own verification** are outside the flag model:
  both are amount- and counterparty-dependent, and a `PermissionFlag` is neither.
- **The exit path is not permissioned at all** (no `beforeRemoveLiquidity` in the hook's permissions,
  and decrease/burn are intentionally left unchecked upstream so holders can always exit). A frozen
  holder with an existing position can still unwind it. A global pause contains that case, since the
  unwrap is a real transfer; an address freeze does not.

**This reader fails closed.** A token that stops answering either getter resolves to `NONE`
for every account — it halts that token's pools rather than defaulting to unpaused and unfrozen,
because a fail-open default would restore the bypass whenever the dependency misbehaves. A token that
does not implement the ERC-3643 `IToken` control surface at all cannot be wrapped; the adapter owner's
recovery path is `PermissionsAdapter::updateAllowListChecker`.

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
- **Token and registry governance are fully trusted, and that trust is total: they can grant, not
  only deny.** The trust root is re-read on every call and never pinned. A token owner who repoints
  `identityRegistry()`, or empties the required-topic set on the `ClaimTopicsRegistry`, obtains
  `SWAP_ALLOWED | LIQUIDITY_ALLOWED` for an arbitrary address — not merely denial. Vetting the token,
  its registry subtree and their governance keys before wrapping is the adapter owner's
  responsibility, as is checking that the required-topic set is non-empty: a suite deployed with zero
  claim topics is open by configuration, with no attacker involved.
- **What the checker guarantees is about malfunction, not malice.** A broken chain (revert, missing
  contract, malformed return data, return bomb, gas bomb) degrades to a strictly lower-or-equal
  permission — see [`checkAllowlist` never reverts](#checkallowlist-never-reverts) — never a higher one.
- The **OnchainID is untrusted**: it is user-controlled and may return a forged `issuer`/`signature`/
  `data` tuple, revert, or return unbounded data. Only the `TrustedIssuersRegistry` decides who may
  attest an LP claim — but only the *issuer binding* is re-derived there. The `signature` and `data`
  are whatever the identity returned, and ONCHAINID keys revocation on those exact bytes, so
  `ClaimIssuer::revokeClaim` is not binding against an identity that answers `getClaim` differently
  per caller. See [Issuer operations](#issuer-operations).
- **Claim issuers are semi-trusted**: registry-curated, but arbitrary third-party contracts. One that
  reverts, returns a malformed answer or burns gas denies its own claim holders their liquidity flag —
  it cannot deny anyone their swap right, nor stall the pool.

### Issuer operations

The non-revocation half of `LIQUIDITY_ALLOWED` is only as strong as the registered `ClaimIssuer`
implementation and how the claim was revoked.

ONCHAINID keys revocation on the exact signature blob, while its `getRecoveredAddress` normalises a
`v` below 27 and places no bound on `s` — so four byte strings recover the same signer, and revoking
one leaves three answering "not revoked". The checker therefore refuses a claim whose signature has
an equivalent revoked encoding, asking the issuer about the whole class rather than the blob the
identity happened to store. A signature that is not a 65-byte ECDSA encoding is left entirely to the
issuer's own semantics. The upstream fix ([`50b06f8`](https://github.com/onchain-id/solidity/commit/50b06f8a78215d309fff6828a23b2b35ff352059))
is on `main` and is in no published release — neither `2.2.1` (`latest`) nor `2.2.2-beta3` (`beta`)
carries it as of 2026-09-10 — so pin the issuer implementation deliberately rather than by range.

Operating rules:

- revoke with `revokeClaimBySignature` against the signature blob archived at issuance; treat
  `revokeClaim` as advisory, since it reads the bytes to revoke from the holder's own identity;
- confirm afterwards with `probeLpClaim(identityRegistry, account)` — it runs in the checker's frame,
  so a caller-discriminating identity cannot spoof the answer;
- `ClaimRevoked(bytes indexed signature)` indexes a dynamic type, so monitoring must compare
  `keccak256(archivedSignature)` against the log topic, not the blob itself;
- registry-agent fallbacks, if revocation cannot be made to bind: `IdentityRegistry::updateIdentity`
  repoints one holder at a canonical ONCHAINID; `deleteIdentity` removes the swap right too.

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
