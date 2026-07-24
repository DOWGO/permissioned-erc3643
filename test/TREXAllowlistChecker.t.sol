// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {IAllowlistChecker} from "@uniswap/v4-periphery/src/hooks/permissionedPools/interfaces/IAllowlistChecker.sol";

/// @dev Minimal OnchainID mock: stores ERC-735-style claims keyed by claimId, the way a real
///      OnchainID does. The checker fetches claims via getClaim(claimId) — mirroring how the
///      T-REX IdentityRegistry validates claims — so a mere claim *existence* is not enough.
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
        bytes32 claimId = keccak256(abi.encode(issuer, topic));
        claims[claimId] = Claim(topic, issuer, signature, data);
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

/// @dev Claim issuer whose validity verdict is configurable, so tests can model a revoked or
///      otherwise-invalid claim (isClaimValid == false) as well as a reverting issuer.
contract MockClaimIssuer {
    bool public valid;
    bool public shouldRevert;

    constructor(bool _valid) {
        valid = _valid;
    }

    function setValid(bool v) external {
        valid = v;
    }

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external view returns (bool) {
        require(!shouldRevert, "issuer boom");
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

contract MockToken {
    address public identityRegistry;

    constructor(address reg) {
        identityRegistry = reg;
    }
}

contract TREXAllowlistCheckerTest is Test {
    uint256 constant LP_TOPIC = 42;
    bytes constant SIG = hex"beef";
    bytes constant DATA = hex"01";

    TREXAllowlistChecker checker;
    MockToken token;
    MockIdentityRegistry registry;
    MockTrustedIssuersRegistry issuersRegistry;
    MockClaimIssuer trustedIssuer;
    MockIdentity aliceId;
    MockIdentity bobId;

    address alice = address(0xA);
    address bob = address(0xB);
    address carol = address(0xC);

    function setUp() public {
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));
        checker = new TREXAllowlistChecker(LP_TOPIC);

        trustedIssuer = new MockClaimIssuer(true);
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(trustedIssuer));

        aliceId = new MockIdentity();
        bobId = new MockIdentity();
        registry.setIdentity(alice, address(aliceId));
        registry.setIdentity(bob, address(bobId));
    }

    // --- swap gate ---

    function test_unverified_returns_NONE() public view {
        // alice has an identity, but is not verified in the registry
        PermissionFlag flags = checker.checkAllowlist(alice, address(token));
        assertTrue(flags == PermissionFlags.NONE);
    }

    function test_verified_no_lp_claim_returns_SWAP_only() public {
        registry.setVerified(alice, true);
        _assertSwapOnly(checker.checkAllowlist(alice, address(token)));
    }

    function test_no_identity_attached_returns_SWAP_only() public {
        // carol is verified by registry decree but has no OnchainID attached
        registry.setVerified(carol, true);
        _assertSwapOnly(checker.checkAllowlist(carol, address(token)));
    }

    // --- LP gate: the claim must be VALID, not merely present ---

    function test_verified_with_valid_trusted_claim_returns_SWAP_and_LIQUIDITY() public {
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC, address(trustedIssuer), SIG, DATA);
        _assertSwapAndLiquidity(checker.checkAllowlist(bob, address(token)));
    }

    function test_lp_claim_on_wrong_topic_returns_SWAP_only() public {
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC + 1, address(trustedIssuer), SIG, DATA);
        _assertSwapOnly(checker.checkAllowlist(bob, address(token)));
    }

    function test_lp_claim_from_untrusted_issuer_returns_SWAP_only() public {
        // A self-issued claim on the right topic, but the issuer is not in the trusted registry.
        MockClaimIssuer rogue = new MockClaimIssuer(true);
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC, address(rogue), SIG, DATA);
        _assertSwapOnly(checker.checkAllowlist(bob, address(token)));
    }

    function test_revoked_lp_claim_returns_SWAP_only() public {
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC, address(trustedIssuer), SIG, DATA);
        trustedIssuer.setValid(false); // claim revoked / no longer valid
        _assertSwapOnly(checker.checkAllowlist(bob, address(token)));
    }

    function test_issuer_isClaimValid_reverts_returns_SWAP_only() public {
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC, address(trustedIssuer), SIG, DATA);
        trustedIssuer.setShouldRevert(true); // hostile / broken issuer must not brick the checker
        _assertSwapOnly(checker.checkAllowlist(bob, address(token)));
    }

    function test_valid_claim_among_multiple_trusted_issuers_grants_LIQUIDITY() public {
        // First trusted issuer has no matching claim; second one does and is valid.
        MockClaimIssuer second = new MockClaimIssuer(true);
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(second));
        registry.setVerified(bob, true);
        bobId.addClaim(LP_TOPIC, address(second), SIG, DATA);
        _assertSwapAndLiquidity(checker.checkAllowlist(bob, address(token)));
    }

    // --- constructor / interface ---

    function test_constructor_rejects_zero_topic() public {
        vm.expectRevert(TREXAllowlistChecker.ZeroClaimTopic.selector);
        new TREXAllowlistChecker(0);
    }

    function test_supports_IAllowlistChecker_interface() public view {
        assertTrue(checker.supportsInterface(type(IAllowlistChecker).interfaceId));
    }

    function test_lp_topic_immutable_value() public view {
        assertEq(checker.LP_CLAIM_TOPIC(), LP_TOPIC);
    }

    // --- fuzz ---

    function testFuzz_unverified_account_never_gets_flags(address account) public view {
        // No account is verified in a fresh registry, so nothing is ever granted.
        vm.assume(account != address(0));
        assertTrue(checker.checkAllowlist(account, address(token)) == PermissionFlags.NONE);
    }

    function testFuzz_valid_claim_grants_liquidity_regardless_of_account(address account) public {
        vm.assume(account != address(0));
        MockIdentity id = new MockIdentity();
        registry.setIdentity(account, address(id));
        registry.setVerified(account, true);
        id.addClaim(LP_TOPIC, address(trustedIssuer), SIG, DATA);
        _assertSwapAndLiquidity(checker.checkAllowlist(account, address(token)));
    }

    // --- helpers ---

    function _assertSwapOnly(PermissionFlag flags) internal pure {
        assertTrue((flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED, "swap expected");
        assertTrue((flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.NONE, "liquidity not expected");
    }

    function _assertSwapAndLiquidity(PermissionFlag flags) internal pure {
        assertTrue((flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED, "swap expected");
        assertTrue(
            (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED, "liquidity expected"
        );
    }
}
