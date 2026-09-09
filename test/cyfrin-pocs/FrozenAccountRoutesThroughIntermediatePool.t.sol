// SPDX-License-Identifier: MIT
// Vendored from Cyfrin audit finding #5, https://github.com/Cyfrin/audit-2026-09-dowgo/issues/5
// Two edits, both stated in the mitigation commit:
//   1. the stand-in token's freeze surface is renamed to the real ERC-3643 IToken names
//      (`isFrozen`, `getFrozenTokens` -- IToken.sol:452,459); the PoC used `frozen`, which the
//      checker cannot read;
//   2. the two bypass assertions are inverted, so this file is a regression test for `fix(#5)`.
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";

import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PermissionsAdapter} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapter.sol";
import {
    PermissionsAdapterFactory
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapterFactory.sol";
import {PermissionedHooks} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedHooks.sol";
import {
    PermissionedV4Router
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedV4Router.sol";
import {
    IPermissionsAdapter
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IPermissionsAdapter.sol";
import {
    IPermissionsAdapterFactory
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IPermissionsAdapterFactory.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {IV4Router} from "@uniswap/v4-periphery/src/interfaces/IV4Router.sol";
import {PathKey} from "@uniswap/v4-periphery/src/libraries/PathKey.sol";
import {Actions} from "@uniswap/v4-periphery/src/libraries/Actions.sol";
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {TREXAllowlistChecker} from "../../src/TREXAllowlistChecker.sol";
import {
    MockIdentity,
    MockClaimIssuer,
    MockTrustedIssuersRegistry,
    MockIdentityRegistry
} from "../PermissionedFlow.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// What this file establishes
//
// The permissioned-pool design never lets the ERC-3643 token be a pool currency. The pool trades
// PermissionsAdapter, an ERC20 of the adapter's own, and the underlying moves only when the adapter
// wraps on settle or unwraps on take. Both of those are ordinary ERC-3643 transfers, so the token's
// own pause and address-freeze guards apply to them.
//
// V4Router::_swapExactInput chains hops by assigning amountIn = amountOut and never settles or takes
// an intermediate currency - only the first currency is settled and the last is taken. So on a route
// whose middle leg is the adapter, the adapter's delta nets to zero, no wrap or unwrap occurs, and
// the ERC-3643 token is never called. The only per-account gate left on that route is the hook,
// which asks TREXAllowlistChecker, which reads isVerified and nothing else.
//
// The underlying token here reverts on EVERY transfer while paused or while either party is frozen,
// so a route that completes in that state is proof that no underlying transfer took place.
// ─────────────────────────────────────────────────────────────────────────────

/// @dev ERC-3643-shaped token. Real T-REX puts these two guards on `transfer`/`transferFrom`
///      (Token.sol) and keeps `_frozen` in token storage (TokenStorage.sol) - the identity registry
///      has no knowledge of freeze at all, which is why `isVerified` stays true throughout. Placing
///      them on `_update` here is stricter than production ONLY as to where the pause and freeze
///      guards sit: it catches every transfer path into or out of the adapter, so nothing can slip
///      past unnoticed. It is not a fuller token - it omits the identity and modular-compliance
///      checks that real `transfer` also performs. Those omissions cannot matter on the route under
///      test, because no underlying transfer happens there at all. Mint and burn are excluded so
///      the fixture can be funded.
contract FreezableTREXToken is ERC20 {
    address public immutable identityRegistry;

    bool public paused;
    mapping(address => bool) public isFrozen;
    mapping(address => uint256) public getFrozenTokens;

    /// @dev Instrumentation: counts non-mint, non-burn transfers of the underlying.
    uint256 public transferCount;

    constructor(address registry) ERC20("Freezable TREX Token", "FTRX") {
        identityRegistry = registry;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setPaused(bool p) external {
        paused = p;
    }

    function setAddressFrozen(address account, bool f) external {
        isFrozen[account] = f;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            require(!paused, "Pausable: paused");
            require(!isFrozen[from] && !isFrozen[to], "wallet is frozen");
            transferCount++;
        }
        super._update(from, to, value);
    }
}

contract PlainToken is ERC20 {
    constructor(string memory n) ERC20(n, n) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev Concrete PermissionedV4Router. This checkout ships only the abstract contract - upstream's
///      own tests load a concrete artifact that is not vendored here - so the two payment hooks are
///      implemented as the upstream router documents them. Nothing else is overridden: the routing
///      logic under test (V4Router::_swapExactInput) and the payment dispatcher
///      (PermissionedV4Router::_pay) are both inherited verbatim. The point of the test is precisely
///      that neither payment hook below is reached for the intermediate currency.
///
///      msgSender() resolves to the EOA that called executeActions, exactly as the official router
///      resolves it from its own locker - the subject is never a caller-supplied argument.
contract TestPermissionedRouter is PermissionedV4Router {
    address internal locker;

    /// @dev Instrumentation: counts payment-hook entries, per currency kind.
    uint256 public standardPayCount;
    uint256 public permissionedPayCount;

    constructor(IPoolManager pm, IPermissionsAdapterFactory f) PermissionedV4Router(pm, f) {}

    function executeActions(bytes calldata unlockData) external {
        locker = msg.sender;
        _executeActions(unlockData);
        locker = address(0);
    }

    function msgSender() public view override returns (address) {
        return locker;
    }

    function _payStandard(Currency currency, address payer, uint256 amount) internal override {
        standardPayCount++;
        if (payer == address(this)) {
            IERC20(Currency.unwrap(currency)).transfer(address(poolManager), amount);
        } else {
            IERC20(Currency.unwrap(currency)).transferFrom(payer, address(poolManager), amount);
        }
    }

    function _payPermissionedFromPayer(
        address payer,
        IPermissionsAdapter permissionsAdapter,
        address permissionedToken,
        uint256 amount
    ) internal override {
        permissionedPayCount++;
        IERC20(permissionedToken).transferFrom(payer, address(permissionsAdapter), amount);
        permissionsAdapter.wrapToPoolManager(amount);
    }
}

/// @dev Minimal liquidity provider. Implements IMsgSender because PermissionedHooks reads the real
///      LP off the calling router, and is registered as an allowed wrapper so it may wrap on settle.
contract LiquidityRouter is IUnlockCallback {
    IPoolManager internal immutable MANAGER;
    PermissionsAdapter internal immutable ADAPTER;
    IERC20 internal immutable UNDERLYING;

    address internal locker;

    constructor(IPoolManager m, PermissionsAdapter a, IERC20 u) {
        MANAGER = m;
        ADAPTER = a;
        UNDERLYING = u;
    }

    function msgSender() external view returns (address) {
        return locker;
    }

    function addLiquidity(PoolKey calldata key, ModifyLiquidityParams calldata params, address lp) external {
        locker = lp;
        MANAGER.unlock(abi.encode(key, params));
        locker = address(0);
    }

    function unlockCallback(bytes calldata data) external override returns (bytes memory) {
        require(msg.sender == address(MANAGER), "only manager");
        (PoolKey memory key, ModifyLiquidityParams memory params) = abi.decode(data, (PoolKey, ModifyLiquidityParams));

        (BalanceDelta delta,) = MANAGER.modifyLiquidity(key, params, "");

        _settle(key.currency0, delta.amount0());
        _settle(key.currency1, delta.amount1());
        return "";
    }

    function _settle(Currency currency, int128 amount) internal {
        if (amount >= 0) return;
        uint256 owed = uint256(uint128(-amount));

        MANAGER.sync(currency);
        if (Currency.unwrap(currency) == address(ADAPTER)) {
            // Settling the adapter currency is a wrap: underlying in, adapter minted to the manager.
            UNDERLYING.transfer(address(ADAPTER), owed);
            ADAPTER.wrapToPoolManager(owed);
        } else {
            IERC20(Currency.unwrap(currency)).transfer(address(MANAGER), owed);
        }
        MANAGER.settle();
    }
}

contract FrozenAccountRoutesThroughIntermediatePoolTest is Test {
    uint256 internal constant LP_TOPIC = 42;
    uint160 internal constant SQRT_PRICE_1_1 = 79228162514264337593543950336;
    int24 internal constant TICK_LOWER = -60000;
    int24 internal constant TICK_UPPER = 60000;

    PoolManager internal manager;
    MockIdentityRegistry internal registry;
    MockTrustedIssuersRegistry internal issuersRegistry;
    MockClaimIssuer internal lpIssuer;
    FreezableTREXToken internal underlying;
    TREXAllowlistChecker internal checker;
    PermissionsAdapterFactory internal factory;
    PermissionsAdapter internal adapter;
    PermissionedHooks internal hook;
    TestPermissionedRouter internal router;
    LiquidityRouter internal lpRouter;

    PlainToken internal tokenA;
    PlainToken internal tokenB;

    PoolKey internal poolAAdapter;
    PoolKey internal poolAdapterB;

    address internal deployer = address(this);
    address internal lp = makeAddr("lp");
    address internal trader = makeAddr("trader");

    function setUp() public {
        manager = new PoolManager(deployer);

        // ── T-REX side ──────────────────────────────────────────────────────
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        lpIssuer = new MockClaimIssuer(true);
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(lpIssuer));

        underlying = new FreezableTREXToken(address(registry));
        underlying.mint(deployer, 1_000_000e18);

        // The LP holds a valid LP claim; the trader is merely verified, which is all a swap needs.
        MockIdentity lpId = new MockIdentity();
        lpId.addClaim(LP_TOPIC, address(lpIssuer), hex"beef", hex"01");
        registry.setVerified(lp, true);
        registry.setIdentity(lp, address(lpId));

        MockIdentity traderId = new MockIdentity();
        registry.setVerified(trader, true);
        registry.setIdentity(trader, address(traderId));

        checker = new TREXAllowlistChecker(LP_TOPIC);

        // ── Adapter ─────────────────────────────────────────────────────────
        factory = new PermissionsAdapterFactory(address(manager));
        adapter = PermissionsAdapter(factory.createPermissionsAdapter(IERC20(address(underlying)), deployer, checker));
        underlying.transfer(address(adapter), 1); // proves control of the token to the factory
        factory.verifyPermissionsAdapter(address(adapter));
        adapter.updateSwappingEnabled(true);

        // ── Hook ────────────────────────────────────────────────────────────
        uint160 flags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG
                | Hooks.AFTER_SWAP_FLAG
        );
        bytes memory args = abi.encode(IPoolManager(address(manager)), IPermissionsAdapterFactory(address(factory)));
        (address hookAddr, bytes32 salt) = HookMiner.find(deployer, flags, type(PermissionedHooks).creationCode, args);
        hook = new PermissionedHooks{salt: salt}(
            IPoolManager(address(manager)), IPermissionsAdapterFactory(address(factory))
        );
        require(address(hook) == hookAddr, "hook address mismatch");

        // ── Routers ─────────────────────────────────────────────────────────
        router = new TestPermissionedRouter(IPoolManager(address(manager)), IPermissionsAdapterFactory(address(factory)));
        lpRouter = new LiquidityRouter(IPoolManager(address(manager)), adapter, IERC20(address(underlying)));
        adapter.updateAllowedWrapper(address(router), true);
        adapter.updateAllowedWrapper(address(lpRouter), true);

        // ── Two pools sharing the adapter ───────────────────────────────────
        tokenA = new PlainToken("A");
        tokenB = new PlainToken("B");

        poolAAdapter = _key(address(tokenA), address(adapter));
        poolAdapterB = _key(address(adapter), address(tokenB));
        manager.initialize(poolAAdapter, SQRT_PRICE_1_1);
        manager.initialize(poolAdapterB, SQRT_PRICE_1_1);

        // ── Liquidity, added while nothing is frozen or paused ──────────────
        tokenA.mint(address(lpRouter), 1_000_000e18);
        tokenB.mint(address(lpRouter), 1_000_000e18);
        underlying.transfer(address(lpRouter), 500_000e18);

        ModifyLiquidityParams memory add =
            ModifyLiquidityParams({tickLower: TICK_LOWER, tickUpper: TICK_UPPER, liquidityDelta: 1e18, salt: 0});
        lpRouter.addLiquidity(poolAAdapter, add, lp);
        lpRouter.addLiquidity(poolAdapterB, add, lp);

        // ── Trader funding: only the plain input currency ───────────────────
        tokenA.mint(trader, 1_000e18);
        vm.prank(trader);
        tokenA.approve(address(router), type(uint256).max);
    }

    function _key(address x, address y) internal view returns (PoolKey memory) {
        (address c0, address c1) = x < y ? (x, y) : (y, x);
        return PoolKey({
            currency0: Currency.wrap(c0),
            currency1: Currency.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
    }

    /// @dev Route: tokenA -> adapter -> tokenB. The adapter is the intermediate currency.
    function _multiHopPlan(uint128 amountIn) internal view returns (bytes memory) {
        PathKey[] memory path = new PathKey[](2);
        path[0] = PathKey(Currency.wrap(address(adapter)), 3000, 60, IHooks(address(hook)), bytes(""));
        path[1] = PathKey(Currency.wrap(address(tokenB)), 3000, 60, IHooks(address(hook)), bytes(""));

        IV4Router.ExactInputParams memory params = IV4Router.ExactInputParams({
            currencyIn: Currency.wrap(address(tokenA)),
            path: path,
            amountIn: amountIn,
            amountOutMinimum: 0
        });

        bytes memory actions =
            abi.encodePacked(uint8(Actions.SWAP_EXACT_IN), uint8(Actions.SETTLE_ALL), uint8(Actions.TAKE_ALL));
        bytes[] memory p = new bytes[](3);
        p[0] = abi.encode(params);
        p[1] = abi.encode(Currency.wrap(address(tokenA)), uint256(amountIn));
        p[2] = abi.encode(Currency.wrap(address(tokenB)), uint256(0));
        return abi.encode(actions, p);
    }

    /// @dev Route: tokenA -> adapter. The adapter is the OUTPUT currency, so it must be unwrapped.
    function _singleHopPlan(uint128 amountIn) internal view returns (bytes memory) {
        PathKey[] memory path = new PathKey[](1);
        path[0] = PathKey(Currency.wrap(address(adapter)), 3000, 60, IHooks(address(hook)), bytes(""));

        IV4Router.ExactInputParams memory params = IV4Router.ExactInputParams({
            currencyIn: Currency.wrap(address(tokenA)),
            path: path,
            amountIn: amountIn,
            amountOutMinimum: 0
        });

        bytes memory actions =
            abi.encodePacked(uint8(Actions.SWAP_EXACT_IN), uint8(Actions.SETTLE_ALL), uint8(Actions.TAKE_ALL));
        bytes[] memory p = new bytes[](3);
        p[0] = abi.encode(params);
        p[1] = abi.encode(Currency.wrap(address(tokenA)), uint256(amountIn));
        p[2] = abi.encode(Currency.wrap(address(adapter)), uint256(0));
        return abi.encode(actions, p);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // The finding
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice A frozen account, with the token additionally paused, completes a swap that routes
    ///         through the permissioned pool because the adapter is only an intermediate currency.
    function test_PoC_FrozenAccountRoutesThroughPermissionedPoolAsIntermediateCurrency() public {
        // The compliance officer freezes the trader and pauses the token outright.
        underlying.setAddressFrozen(trader, true);
        underlying.setPaused(true);

        // The checker now reads the token's own control surface, so it denies outright. Before the
        // mitigation it granted SWAP_ALLOWED here, because isVerified knows nothing of freeze.
        PermissionFlag flags = checker.checkAllowlist(trader, address(underlying));
        assertTrue(
            flags == PermissionFlags.NONE,
            "REGRESSION: checker grants a frozen account of a paused token"
        );

        uint256 balanceBefore = tokenB.balanceOf(trader);

        // The route that never touches the underlying — and so never reaches the token's own pause
        // and freeze guards — is now stopped at the hook instead.
        vm.prank(trader);
        vm.expectRevert();
        router.executeActions(_multiHopPlan(1e15));

        assertEq(tokenB.balanceOf(trader), balanceBefore, "REGRESSION: frozen trader received output currency");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Controls
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Control. The same trader, same freeze, taking the adapter as OUTPUT is stopped - the
    ///         unwrap is a real ERC-3643 transfer. This is the backstop that the route above avoids.
    function test_PoC_FrozenAccountIsStoppedWhenTheAdapterIsTheOutputCurrency() public {
        underlying.setAddressFrozen(trader, true);

        // The guard that bites: the unwrap the take would perform is refused outright.
        vm.prank(address(adapter));
        vm.expectRevert("wallet is frozen");
        underlying.transfer(trader, 1);

        // And so the whole route reverts. (The router wraps the inner reason, so the outer
        // expectation is unqualified; the assertion above pins which guard fired.)
        vm.expectRevert();
        vm.prank(trader);
        router.executeActions(_singleHopPlan(1e15));
    }

    /// @notice Control. Pausing alone also stops the direct route, so the token's guards do work
    ///         wherever the underlying actually moves.
    function test_PoC_PausedTokenStopsTheDirectRouteButNotTheIntermediateRoute() public {
        underlying.setPaused(true);

        // The guard that bites on the direct route.
        vm.prank(address(adapter));
        vm.expectRevert("Pausable: paused");
        underlying.transfer(trader, 1);

        vm.expectRevert();
        vm.prank(trader);
        router.executeActions(_singleHopPlan(1e15));

        // The same paused state now also stops the intermediate route. Before the mitigation it did
        // not: the adapter's deltas cancel inside the PoolManager, so the underlying is never
        // transferred and the guard asserted above is never reached.
        uint256 balanceBefore = tokenB.balanceOf(trader);
        vm.prank(trader);
        vm.expectRevert();
        router.executeActions(_multiHopPlan(1e15));
        assertEq(
            tokenB.balanceOf(trader), balanceBefore, "REGRESSION: intermediate route completes while paused"
        );
    }

    /// @notice Control. The hook gate is live on the multi-hop route: revoking verification blocks
    ///         it. So the bypass above is specifically freeze and pause being invisible to the
    ///         checker, not the permission check being absent.
    function test_PoC_UnverifiedAccountIsRejectedOnTheIntermediateRoute() public {
        registry.setVerified(trader, false);

        vm.expectRevert();
        vm.prank(trader);
        router.executeActions(_multiHopPlan(1e15));
    }

    /// @notice Control. With nothing frozen and nothing paused, the route is an ordinary swap.
    function test_PoC_HonestTraderRoutesThroughTheSamePools() public {
        uint256 balanceBefore = tokenB.balanceOf(trader);
        uint256 transfersBefore = underlying.transferCount();
        vm.prank(trader);
        router.executeActions(_multiHopPlan(1e15));
        assertGt(tokenB.balanceOf(trader), balanceBefore, "honest trader routes through the same pools");
        assertEq(underlying.transferCount(), transfersBefore, "still no underlying transfer on an intermediate route");
    }
}