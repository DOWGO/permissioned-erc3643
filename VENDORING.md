# Vendoring & provenance of `lib/`

`identityhook/lib/` is **mixed**: `v4-core` is a **git submodule** pinned to public Uniswap
upstream; `v4-periphery` remains **vendored** (flat, committed files) because it has no public
git ref (see below). This document records the exact provenance of each dependency so the tree
stays auditable, and explains **why the periphery layer cannot be a git-submodule import**.

Verified 2026-07-24 by diffing the trees byte-for-byte against the public Uniswap history
(all refs), and confirming the v4-core swap left every `out/` artifact's **bytecode and ABI
identical** (166/166 artifacts). Re-run the checks in [How to re-verify](#how-to-re-verify).

## Summary

| Dependency | Provenance | Public git ref? | Submodule-able? |
| --- | --- | --- | --- |
| `lib/v4-core` | Uniswap **public** upstream — **git submodule** | `Uniswap/v4-core@46c6834` (on `main`, v4.0.0-21) | **Done** — installed as submodule, bytecode/ABI identical |
| `lib/v4-periphery` | Uniswap **PermissionedPools feature branch** + private Swap patch (composite) | **None** — matches no public commit | **No** (see below) |
| `lib/v4-core/lib/forge-std` | Uniswap-pinned, standard upstream | forge-std 1.9.3 | Yes (transitive) |
| `lib/v4-core/lib/solmate` | standard upstream | solmate 6.2.0 | Yes (transitive) |
| `lib/v4-core/lib/openzeppelin-contracts` | standard upstream | OpenZeppelin 5.0.2 | Yes (transitive) |
| `lib/v4-periphery/lib/permit2` | standard upstream | Uniswap permit2 | Yes (transitive) |

Remappings (`remappings.txt`) consume `forge-std` / `solmate` / `openzeppelin` from
**`lib/v4-core/lib/*`** and `permit2` from **`lib/v4-periphery/lib/permit2`**.

## `lib/v4-core` — git submodule (public upstream)

`lib/v4-core` is a **git submodule** pinned to
`Uniswap/v4-core@46c6834698c48bc4a463a86d8420f4eb1d7f3b75`. Its `src/` tree (and its recursively
pinned sub-deps `forge-std` `1de6eec`, `openzeppelin-contracts` `dbb6104`, `solmate` `4b47a19`)
is **byte-for-byte identical** to the tree that was previously vendored.

**Why this commit:** the vendored snapshot matched `src` byte-for-byte at
`592c3e0d` (v1.0.2), but that commit lives only on the deletable feature branch
`chore/private-dep-confusion-fix`. `46c6834` is the newest commit **on `main`** carrying the
identical `src` subtree and the identical sub-dep gitlinks, so the pin is durable.

**Verification:** a clean A/B rebuild (vendored HEAD via `git worktree` vs the submodule) showed
**0 differences** in `bytecode`, `deployedBytecode`, and `abi` across all 166 `out/` artifacts —
so the swap changes nothing the SPA or on-chain deployments depend on.

After a fresh clone, build with:

```sh
git submodule update --init --recursive
```

## `lib/v4-periphery` — private Uniswap pre-launch build, **not importable from public git**

The vendored `lib/v4-periphery` is **not** any public Uniswap commit or `main`. It was pulled
from Uniswap's **PermissionedPools feature branch** (not from `main`, which never carried a
production `PermissionedHooks`), and is effectively a **composite** — see
[Which branch](#which-branch) below. The Uniswap team then shared an updated hook with Dowgo
directly (the Swap-event patch). Key evidence:

- `src/hooks/permissionedPools/PermissionedHooks.sol` (blob `c2bda23f`) exists in **zero**
  commits across the entire public `Uniswap/v4-periphery` history. In public upstream,
  `PermissionedHooks` survives only as a **test mock**
  (`test/hooks/permissionedPools/mocks/MockPermissionedHooks.sol`) and the production
  dependency was being *migrated out*. The vendored file is a real `src/` contract carrying a
  **custom `event Swap(...)`** emitted in `_afterSwap` — the volume-indexing event described in
  the provenance thread below.
- `src/PositionManager.sol` (blob `09a495e`) also matches **no** public commit.
- `src/V4Router.sol`, `src/libraries/Actions.sol`, `src/libraries/CalldataDecoder.sol`,
  `src/interfaces/IPositionManager.sol`, `src/interfaces/IV4Router.sol` all differ from public
  `main@363226d` (the "Permissioned Pools (#476)" commit).
- The vendored tree contains files **absent** from public `363226d`: `hooks/WETHHook.sol`,
  `hooks/WstETHHook.sol`, `hooks/WstETHRoutingHook.sol`, `interfaces/external/IWstETH.sol`,
  `base/hooks/`, `utils/`.
- Only `src/hooks/permissionedPools/PermissionsAdapter.sol` (and most of `permissionedPools/`)
  matches public `363226d`.

### Which branch

The vendored tree is a **composite of two public sources that never coexisted in a single
commit**, plus the private Swap patch:

- **Base periphery** (`PositionManager`, `V4Router`, WstETH hooks, `utils/`, `PermissionsAdapter`,
  `PermissionsAdapterFactory`, …) tracks roughly `main@363226d` — "Permissioned Pools (#476)".
- **PermissionedPools contracts** (`PermissionedHooks`, `PermissionedPositionManager`,
  `PermissionedV4Router`, their interfaces) come from Uniswap's **PermissionedPools feature
  branch**. The closest current public tip is
  `origin/socksnflops/eco-221-sc-l-10-unilateral-admin-transfer-authority-in` (~10 `src/` files
  apart); `origin/pp/match-univeral-router-interface` is a related but more divergent PP branch.
  These branches have since moved, so no current tip matches the vendored snapshot byte-for-byte.
- **The custom `Swap` event** on top of the above — delivered by Uniswap on 2026-06-30 (below)
  and present in no public commit at all.

### Provenance of the custom `PermissionedHooks` (Swap event)

**Source of authority:** Slack thread, Uniswap PermissionedPools team → Romain, 2026-06-30:
<https://dowgo.slack.com/archives/C0B9GBLEYCU/p1782854289919599>

> "Before we launch, we wanted to add a `Swap` event to the Hook to make it easier for
> integrators to index volume through permissioned pools. We updated the contract to include
> this new event."

Deployed addresses provided in that thread (Uniswap-operated; the SPA points at these — see
`deployer/src/services/uniswap-v4.ts`):

| Chain | `PermissionedHooks` |
| --- | --- |
| Mainnet | `0x69603ab16110Eb0bB5f5E9C8019749eE41A128C0` |
| Sepolia | `0x8B0E8d467af81D9F5B49165e104a2fe1b98328C0` |

`PermissionedPositionManager` (Sepolia): `0x68fC145BB20b388965bED184Df5ef912215bb3C7`
(`uniswap-v4.ts:41`). To switch a pool onto this hook, the adapter owner calls
`setAllowedHook(<permissionsAdapter>, <newHook>, true)` on the `PermissionedPositionManager`
(not on the adapter).

### Why this blocks a git-submodule import

Dowgo **deploys none of these upstream contracts** — the SPA uses the Uniswap-deployed hook /
posm / router addresses above and self-deploys only `src/TREXAllowlistChecker.sol` (project
code, outside `lib/`). But the SPA still consumes the periphery **ABIs from `out/`** (notably
the custom `Swap` event). Pointing `lib/v4-periphery` at any public Uniswap commit would drop
the custom `Swap` event (and the rest of this pre-launch build), breaking ABI compatibility
with the deployed contracts. Because the tree is a composite of two public sources that never
shared a commit (base `main` + PermissionedPools feature branch) plus a private patch, **no
single public ref reproduces it**, so it stays vendored until Uniswap publishes an equivalent
tagged release.

## How to re-verify

```sh
# v4-core submodule is pinned to a public main commit (expect the pinned SHA):
git submodule status lib/v4-core   # -> 46c6834698c48bc4a463a86d8420f4eb1d7f3b75

# It is public upstream (expect empty diff, tests excluded):
git clone https://github.com/Uniswap/v4-core.git /tmp/v4core
git -C /tmp/v4core checkout 46c6834
diff -rq lib/v4-core/src /tmp/v4core/src | grep -vE '/test/|\.t\.sol'

# v4-periphery: confirm the custom hook exists in NO public commit (expect no output):
git clone https://github.com/Uniswap/v4-periphery.git /tmp/v4peri
H=$(git hash-object lib/v4-periphery/src/hooks/permissionedPools/PermissionedHooks.sol)
git -C /tmp/v4peri rev-list --all | while read c; do
  git -C /tmp/v4peri ls-tree -r "$c" | grep -q "$H" && echo "PUBLIC MATCH $c"; done
```
