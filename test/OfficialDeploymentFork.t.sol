// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PermissionsAdapter} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapter.sol";
import {PermissionedHooks} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedHooks.sol";
import {
    IPermissionsAdapter
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IPermissionsAdapter.sol";
import {
    IPermissionsAdapterFactory
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IPermissionsAdapterFactory.sol";
import {IAllowlistChecker} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IAllowlistChecker.sol";

import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    MockTREXToken,
    MockIdentityRegistry,
    MockTrustedIssuersRegistry,
    MockClaimIssuer,
    MockIdentity,
    MockSender,
    ERC20Lite
} from "./PermissionedFlow.t.sol";

/// @notice End-to-end gating proof against Uniswap's REAL, officially-deployed PermissionedPools
///         contracts on Sepolia. We deploy a mock T-REX suite + our `TREXAllowlistChecker`, create an
///         adapter through the LIVE factory (which validates the checker via ERC165 — proving our bridge
///         is bytecode-compatible with the official deployment), then drive the LIVE hook to assert that
///         only authorized users (verified investors for swaps, LP-claim holders for liquidity) pass.
///
///         Runs only when SEPOLIA_RPC_URL is set, so the default `forge test` stays green offline:
///           SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com forge test --match-path test/OfficialDeploymentFork.t.sol -vv
contract OfficialDeploymentForkTest is Test {
    // Uniswap official PermissionedPools deployment — Sepolia
    address constant FACTORY = 0xEe258C31574fb59660C23534E76AF6497c2e5683;
    address constant HOOK = 0x8B0E8d467af81D9F5B49165e104a2fe1b98328C0;
    address constant POOL_MANAGER = 0xE03A1074c86CFeDd5C142C4F04F1a1536e203543;

    uint256 constant LP_TOPIC = 42;

    bool internal forked;

    MockTREXToken internal token;
    MockIdentityRegistry internal registry;
    MockTrustedIssuersRegistry internal trustedIssuersRegistry;
    MockClaimIssuer internal lpClaimIssuer;
    TREXAllowlistChecker internal checker;
    PermissionsAdapter internal adapter;
    PermissionedHooks internal hook;
    MockSender internal mockRouter;

    address internal issuer = address(this);
    address internal alice = makeAddr("alice"); // verified, no LP claim
    address internal bob = makeAddr("bob"); // verified + LP claim
    address internal carol = makeAddr("carol"); // not verified
    MockIdentity internal aliceId;
    MockIdentity internal bobId;
    address internal paymentToken;

    function setUp() public {
        string memory rpc = vm.envOr("SEPOLIA_RPC_URL", string(""));
        forked = bytes(rpc).length > 0;
        if (!forked) return;
        vm.createSelectFork(rpc);

        // Mock T-REX suite (the real token's compliance is irrelevant to the gating we prove here)
        registry = new MockIdentityRegistry();
        trustedIssuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(trustedIssuersRegistry));
        lpClaimIssuer = new MockClaimIssuer(true);
        trustedIssuersRegistry.addTrustedIssuer(LP_TOPIC, address(lpClaimIssuer));
        token = new MockTREXToken(address(registry));
        token.setAllowed(issuer, true);
        token.mint(issuer, 1_000_000e6);

        aliceId = new MockIdentity();
        bobId = new MockIdentity();
        bobId.addClaim(LP_TOPIC, address(lpClaimIssuer), hex"beef", hex"01");
        registry.setVerified(alice, true);
        registry.setIdentity(alice, address(aliceId));
        registry.setVerified(bob, true);
        registry.setIdentity(bob, address(bobId));

        // Our ERC-3643 bridge
        checker = new TREXAllowlistChecker(LP_TOPIC);

        // Create the adapter through the LIVE official factory. This call runs the deployed adapter's
        // constructor, which ERC165-validates our checker — if our IAllowlistChecker interfaceId didn't
        // match the deployed one, this would revert here and every test would fail.
        address adapterAddr = IPermissionsAdapterFactory(FACTORY)
            .createPermissionsAdapter(IERC20(address(token)), issuer, IAllowlistChecker(address(checker)));
        adapter = PermissionsAdapter(adapterAddr);

        // Whitelist the adapter on the token + seed 1 wei so the factory can verify it
        token.setAllowed(adapterAddr, true);
        token.transfer(adapterAddr, 1);
        IPermissionsAdapterFactory(FACTORY).verifyPermissionsAdapter(adapterAddr);

        // Trusted wrapper (stands in for the official UR/posm; reports the real user via msgSender())
        mockRouter = new MockSender();
        adapter.updateAllowedWrapper(address(mockRouter), true);
        adapter.updateSwappingEnabled(true);

        paymentToken = address(new ERC20Lite());
        hook = PermissionedHooks(HOOK);

        // Guard against address drift in the hardcoded trio. The hook gates via ITS OWN immutable
        // factory (PermissionedHooks._isAllowed) and onlyPoolManager checks the hook's own
        // poolManager. If either diverged from our constants, the adapter would look unverified to
        // the hook (_isAllowed early-returns), and the positive tests would pass WITHOUT exercising
        // any ERC-3643 gating. Asserting here makes that false-pass impossible.
        assertEq(address(hook.PERMISSIONS_ADAPTER_FACTORY()), FACTORY, "hook factory != FACTORY");
        assertEq(address(hook.poolManager()), POOL_MANAGER, "hook poolManager != POOL_MANAGER");
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _poolKey() internal view returns (PoolKey memory key) {
        (address c0, address c1) =
            address(adapter) < paymentToken ? (address(adapter), paymentToken) : (paymentToken, address(adapter));
        key = PoolKey({
            currency0: Currency.wrap(c0), currency1: Currency.wrap(c1), fee: 3000, tickSpacing: 60, hooks: IHooks(HOOK)
        });
    }

    function _swapParams() internal pure returns (SwapParams memory) {
        return SwapParams({zeroForOne: true, amountSpecified: -1e6, sqrtPriceLimitX96: 4295128740});
    }

    function _liquidityParams() internal pure returns (ModifyLiquidityParams memory) {
        return ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 1e18, salt: 0});
    }

    modifier onlyForked() {
        if (!forked) {
            vm.skip(true);
            return;
        }
        _;
    }

    // ── Tests against the LIVE official contracts ─────────────────────────────

    /// Proves our checker plugged into the LIVE factory and the adapter is verified on it.
    function test_live_factory_accepts_our_checker_and_verifies_adapter() public onlyForked {
        assertEq(address(adapter.allowListChecker()), address(checker), "checker not wired into adapter");
        assertEq(
            IPermissionsAdapterFactory(FACTORY).verifiedPermissionsAdapterOf(address(adapter)),
            address(token),
            "adapter not verified on the live factory"
        );
    }

    function test_live_hook_allows_verified_swapper() public onlyForked {
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        (bytes4 selector,,) = hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    function test_live_hook_blocks_unverified_swapper() public onlyForked {
        mockRouter.setMsgSender(carol);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
    }

    function test_live_hook_blocks_non_allowed_wrapper() public onlyForked {
        // alice is verified, but this router is NOT an allowedWrapper on the adapter
        MockSender rogue = new MockSender();
        rogue.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeSwap(address(rogue), key, _swapParams(), "");
    }

    function test_live_hook_blocks_swap_when_disabled() public onlyForked {
        adapter.updateSwappingEnabled(false);
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        vm.expectRevert(PermissionedHooks.SwappingDisabled.selector);
        hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
    }

    function test_live_hook_allows_LP_with_claim() public onlyForked {
        mockRouter.setMsgSender(bob);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        bytes4 selector = hook.beforeAddLiquidity(address(mockRouter), key, _liquidityParams(), "");
        assertEq(selector, IHooks.beforeAddLiquidity.selector);
    }

    function test_live_hook_blocks_LP_without_claim() public onlyForked {
        // alice is verified for swaps but holds no LP claim
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(POOL_MANAGER);
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeAddLiquidity(address(mockRouter), key, _liquidityParams(), "");
    }

    function test_live_only_allowed_wrappers_can_wrap() public onlyForked {
        address rogue = makeAddr("rogue");
        vm.prank(rogue);
        vm.expectRevert(abi.encodeWithSelector(IPermissionsAdapter.UnauthorizedWrapper.selector, rogue));
        adapter.wrapToPoolManager(1);
    }
}
