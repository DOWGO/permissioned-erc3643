// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {PoolManager} from "@uniswap/v4-core/src/PoolManager.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PermissionsAdapter} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapter.sol";
import {
    PermissionsAdapterFactory
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapterFactory.sol";
import {PermissionedHooks} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedHooks.sol";
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
import {HookMiner} from "@uniswap/v4-periphery/src/utils/HookMiner.sol";

import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {RevertingTrustedIssuersRegistry, RevertingIdentity} from "./TREXAllowlistCheckerHardening.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────────────

contract MockIdentity {
    struct Claim {
        uint256 topic;
        address issuer;
        bytes signature;
        bytes data;
    }

    mapping(bytes32 => Claim) private claims;

    /// @dev claimId is keccak256(abi.encode(issuer, topic)), the canonical ERC-3643 id.
    function addClaim(uint256 topic, address issuer, bytes memory signature, bytes memory data) external {
        claims[keccak256(abi.encode(issuer, topic))] = Claim(topic, issuer, signature, data);
    }

    function getClaim(bytes32 claimId)
        external
        view
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            bytes memory data,
            string memory uri
        )
    {
        Claim memory c = claims[claimId];
        return (c.topic, 1, c.issuer, c.signature, c.data, "");
    }
}

contract MockClaimIssuer {
    bool public valid;

    constructor(bool _valid) {
        valid = _valid;
    }

    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external view returns (bool) {
        return valid;
    }
}

contract MockTrustedIssuersRegistry {
    mapping(uint256 => address[]) private issuersByTopic;

    function addTrustedIssuer(uint256 topic, address issuer) external {
        issuersByTopic[topic].push(issuer);
    }

    function getTrustedIssuersForClaimTopic(uint256 topic) external view returns (address[] memory) {
        return issuersByTopic[topic];
    }
}

contract MockIdentityRegistry {
    mapping(address => bool) public verified;
    mapping(address => address) public identityOf;
    address public issuersRegistry;

    function setVerified(address user, bool v) external {
        verified[user] = v;
    }

    function setIdentity(address user, address id) external {
        identityOf[user] = id;
    }

    function setIssuersRegistry(address reg) external {
        issuersRegistry = reg;
    }

    function isVerified(address user) external view returns (bool) {
        return verified[user];
    }

    function identity(address user) external view returns (address) {
        return identityOf[user];
    }
}

/// @notice Mock T-REX-shaped token: exposes identityRegistry() and enforces a binary
///         allowlist on transfer destinations. Real T-REX gates via Compliance + Identity
///         Registry — this mock is enough to prove the wrapper architecture works.
contract MockTREXToken is ERC20 {
    address public immutable identityRegistry;
    mapping(address => bool) public allowed;

    error Unauthorized();

    constructor(address registry) ERC20("Mock TREX Token", "MTRX") {
        identityRegistry = registry;
    }

    function setAllowed(address account, bool isAllowed) external {
        allowed[account] = isAllowed;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 amount) internal override {
        if (to != address(0) && !allowed[to]) revert Unauthorized();
        super._update(from, to, amount);
    }
}

/// @notice Implements IMsgSender so the hook can read msgSender() off it.
///         Stands in for PermissionedV4Router in tests where we don't need the
///         full Permit2/wrap flow.
contract MockSender {
    address public _msgSender;

    function setMsgSender(address user) external {
        _msgSender = user;
    }

    function msgSender() external view returns (address) {
        return _msgSender;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

contract PermissionedFlowTest is Test {
    uint256 constant LP_TOPIC = 42;

    PoolManager public poolManager;
    MockTREXToken public token;
    MockIdentityRegistry public registry;
    MockTrustedIssuersRegistry public trustedIssuersRegistry;
    MockClaimIssuer public lpClaimIssuer;
    TREXAllowlistChecker public checker;
    PermissionsAdapterFactory public factory;
    PermissionsAdapter public adapter;
    PermissionedHooks public hook;
    MockSender public mockRouter;

    address public issuer = address(this);
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    address public carol = makeAddr("carol");
    MockIdentity public aliceId;
    MockIdentity public bobId;

    // Plain ERC20 used as the second pool currency (e.g. payment token)
    address public paymentToken;

    function setUp() public {
        // 1. PoolManager
        poolManager = new PoolManager(issuer);

        // 2. Mock TREX token + registry (+ trusted issuers registry for LP claim validation)
        registry = new MockIdentityRegistry();
        trustedIssuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(trustedIssuersRegistry));
        lpClaimIssuer = new MockClaimIssuer(true);
        trustedIssuersRegistry.addTrustedIssuer(LP_TOPIC, address(lpClaimIssuer));
        token = new MockTREXToken(address(registry));
        token.setAllowed(issuer, true);
        token.mint(issuer, 1_000_000e6);

        // 3. Investors — bob holds a VALID LP claim from a trusted issuer; alice does not
        aliceId = new MockIdentity();
        bobId = new MockIdentity();
        bobId.addClaim(LP_TOPIC, address(lpClaimIssuer), hex"beef", hex"01");

        registry.setVerified(alice, true);
        registry.setIdentity(alice, address(aliceId));
        registry.setVerified(bob, true);
        registry.setIdentity(bob, address(bobId));
        // carol: no verification

        // 4. Allowlist checker (T-REX glue)
        checker = new TREXAllowlistChecker(LP_TOPIC);

        // 5. Adapter factory
        factory = new PermissionsAdapterFactory(address(poolManager));

        // 6. Create adapter
        address adapterAddr = factory.createPermissionsAdapter(IERC20(address(token)), issuer, checker);
        adapter = PermissionsAdapter(adapterAddr);

        // 7. Whitelist adapter on the token (so the issuer can transfer to it)
        token.setAllowed(adapterAddr, true);

        // 8. Issuer transfers 1 wei to adapter — this proves to the factory the adapter is on the T-REX allowlist
        token.transfer(adapterAddr, 1);

        // 9. Verify adapter on the factory
        factory.verifyPermissionsAdapter(adapterAddr);

        // 10. Mock router with IMsgSender — whitelist as allowedWrapper
        mockRouter = new MockSender();
        adapter.updateAllowedWrapper(address(mockRouter), true);

        // 11. CREATE2-mine + deploy the hook
        bytes memory creationCode = type(PermissionedHooks).creationCode;
        bytes memory args = abi.encode(IPoolManager(address(poolManager)), IPermissionsAdapterFactory(address(factory)));
        uint160 flags = uint160(
            Hooks.BEFORE_INITIALIZE_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_SWAP_FLAG
                | Hooks.AFTER_SWAP_FLAG
        );
        (address hookAddr, bytes32 salt) = HookMiner.find(address(this), flags, creationCode, args);
        hook = new PermissionedHooks{salt: salt}(
            IPoolManager(address(poolManager)), IPermissionsAdapterFactory(address(factory))
        );
        require(address(hook) == hookAddr, "hook address mismatch");

        // 12. Enable swapping
        adapter.updateSwappingEnabled(true);

        // 13. Plain ERC20 paymentToken (any non-zero address that's not a verified adapter)
        paymentToken = address(new ERC20Lite());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    function _poolKey() internal view returns (PoolKey memory key) {
        (address c0, address c1) =
            address(adapter) < paymentToken ? (address(adapter), paymentToken) : (paymentToken, address(adapter));
        key = PoolKey({
            currency0: Currency.wrap(c0),
            currency1: Currency.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
    }

    function _swapParams() internal pure returns (SwapParams memory) {
        return SwapParams({zeroForOne: true, amountSpecified: -1e6, sqrtPriceLimitX96: 4295128740});
    }

    function _liquidityParams() internal pure returns (ModifyLiquidityParams memory) {
        return ModifyLiquidityParams({tickLower: -60, tickUpper: 60, liquidityDelta: 1e18, salt: 0});
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    function test_initialize_succeeds_with_verified_adapter() public {
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        bytes4 selector = hook.beforeInitialize(address(0), key, 0);
        assertEq(selector, IHooks.beforeInitialize.selector);
    }

    function test_initialize_reverts_without_verified_adapter() public {
        // both currencies are vanilla ERC20s, neither is a verified adapter
        address otherToken = address(new ERC20Lite());
        (address c0, address c1) = otherToken < paymentToken ? (otherToken, paymentToken) : (paymentToken, otherToken);
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(c0),
            currency1: Currency.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.NoVerifiedAdapter.selector);
        hook.beforeInitialize(address(0), key, 0);
    }

    /// @dev A pool pairing a verified adapter with an adapter that exists but was never verified.
    ///      The earlier hook accepted this — one verified currency was enough — which let an
    ///      unvetted permissioned token into a pool through the other side.
    function test_initialize_reverts_when_one_adapter_is_unverified() public {
        MockTREXToken otherToken = new MockTREXToken(address(registry));
        address unverified = factory.createPermissionsAdapter(IERC20(address(otherToken)), issuer, checker);
        // deliberately no verifyPermissionsAdapter(unverified)

        (address c0, address c1) =
            address(adapter) < unverified ? (address(adapter), unverified) : (unverified, address(adapter));
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(c0),
            currency1: Currency.wrap(c1),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.UnverifiedAdapter.selector);
        hook.beforeInitialize(address(0), key, 0);
    }

    function test_beforeSwap_succeeds_for_verified_user() public {
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        (bytes4 selector,,) = hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    function test_beforeSwap_reverts_for_unverified_user() public {
        mockRouter.setMsgSender(carol);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
    }

    function test_beforeSwap_reverts_when_swapping_disabled() public {
        adapter.updateSwappingEnabled(false);
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.SwappingDisabled.selector);
        hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
    }

    function test_beforeSwap_reverts_for_non_whitelisted_router() public {
        // alice is verified, but the calling router is NOT in allowedWrappers
        MockSender rogueRouter = new MockSender();
        rogueRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeSwap(address(rogueRouter), key, _swapParams(), "");
    }

    function test_beforeAddLiquidity_succeeds_for_user_with_LP_claim() public {
        mockRouter.setMsgSender(bob);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        bytes4 selector = hook.beforeAddLiquidity(address(mockRouter), key, _liquidityParams(), "");
        assertEq(selector, IHooks.beforeAddLiquidity.selector);
    }

    function test_beforeAddLiquidity_reverts_for_user_without_LP_claim() public {
        // alice is verified for swap but has no LP claim
        mockRouter.setMsgSender(alice);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeAddLiquidity(address(mockRouter), key, _liquidityParams(), "");
    }

    // ── fail-closed degradation, exercised through the real hook callbacks ───

    /// @dev A token-wide TrustedIssuersRegistry outage is reached by the LP probe on EVERY swap,
    ///      even though the swap gate only depends on isVerified. It must not freeze the pool.
    function test_beforeSwap_survives_issuers_registry_outage() public {
        registry.setIssuersRegistry(address(new RevertingTrustedIssuersRegistry()));
        assertTrue(registry.isVerified(bob), "precondition: bob is still KYC-verified");

        mockRouter.setMsgSender(bob);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        (bytes4 selector,,) = hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    /// @dev The same outage denies liquidity — but as a clean Unauthorized, not as an opaque revert
    ///      propagated out of the checker.
    function test_beforeAddLiquidity_denies_cleanly_on_issuers_registry_outage() public {
        registry.setIssuersRegistry(address(new RevertingTrustedIssuersRegistry()));

        mockRouter.setMsgSender(bob);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        vm.expectRevert(PermissionedHooks.Unauthorized.selector);
        hook.beforeAddLiquidity(address(mockRouter), key, _liquidityParams(), "");
    }

    /// @dev A user-deployed ONCHAINID that reverts is an Untrusted dependency on the LP path only;
    ///      its owner must keep the swap right the registry granted them.
    function test_beforeSwap_survives_broken_onchainid() public {
        registry.setIdentity(bob, address(new RevertingIdentity()));
        assertTrue(registry.isVerified(bob), "precondition: bob is still KYC-verified");

        mockRouter.setMsgSender(bob);
        PoolKey memory key = _poolKey();
        vm.prank(address(poolManager));
        (bytes4 selector,,) = hook.beforeSwap(address(mockRouter), key, _swapParams(), "");
        assertEq(selector, IHooks.beforeSwap.selector);
    }

    function test_only_allowed_wrappers_can_wrap() public {
        // a non-allowedWrapper attempting to wrap should revert
        address rogue = makeAddr("rogue");
        vm.prank(rogue);
        vm.expectRevert(abi.encodeWithSelector(IPermissionsAdapter.UnauthorizedWrapper.selector, rogue));
        adapter.wrapToPoolManager(1);
    }

    function test_adapter_only_holdable_by_pool_manager() public {
        // direct ERC20 transfer from non-PM address must revert (only-PM-holds invariant)
        // Since the adapter has no balance for `address(this)` and the deposit-wrap path is
        // gated behind allowedWrappers, attempting a plain transfer reverts.
        vm.expectRevert(abi.encodeWithSelector(IPermissionsAdapter.InvalidTransfer.selector, address(this), alice));
        adapter.transfer(alice, 1);
    }
}

// Plain ERC20 used as the "payment" side of the pool
contract ERC20Lite is ERC20 {
    constructor() ERC20("Payment", "PAY") {
        _mint(msg.sender, 1_000_000e6);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }
}
