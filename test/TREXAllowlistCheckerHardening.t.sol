// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {MockIdentity, MockClaimIssuer, MockTrustedIssuersRegistry, MockToken} from "./TREXAllowlistChecker.t.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Hostile / broken dependencies.
//
// checkAllowlist runs inside the PoolManager's beforeSwap callback, so a revert
// here is not a denial — it bricks the pool. Every contract below models one of
// the documented SemiTrusted/Untrusted failure modes of the T-REX chain.
// ─────────────────────────────────────────────────────────────────────────────

/// @dev ERC-3643 token whose identityRegistry() reverts (proxy mid-upgrade).
contract RevertingToken {
    function identityRegistry() external pure returns (address) {
        revert("token boom");
    }
}

/// @dev Answers every call successfully with a truncated 16-byte buffer, so the
///      caller's ABI decode — not the call itself — is what fails.
contract ShortReturner {
    fallback() external {
        assembly {
            return(0, 16)
        }
    }
}

/// @dev IdentityRegistry with individually switchable failure modes.
contract HostileIdentityRegistry {
    mapping(address => bool) public verified;
    mapping(address => address) public identityOf;
    address internal _issuersRegistry;

    bool public revertIsVerified;
    bool public revertIdentity;
    bool public revertIssuersRegistry;

    function setVerified(address user, bool v) external {
        verified[user] = v;
    }

    function setIdentity(address user, address id) external {
        identityOf[user] = id;
    }

    function setIssuersRegistry(address reg) external {
        _issuersRegistry = reg;
    }

    function setRevertIsVerified(bool v) external {
        revertIsVerified = v;
    }

    function setRevertIdentity(bool v) external {
        revertIdentity = v;
    }

    function setRevertIssuersRegistry(bool v) external {
        revertIssuersRegistry = v;
    }

    function isVerified(address user) external view returns (bool) {
        require(!revertIsVerified, "isVerified boom");
        return verified[user];
    }

    function identity(address user) external view returns (address) {
        require(!revertIdentity, "identity boom");
        return identityOf[user];
    }

    function issuersRegistry() external view returns (address) {
        require(!revertIssuersRegistry, "issuersRegistry boom");
        return _issuersRegistry;
    }
}

/// @dev Token-wide registry failure: upgrade in progress, migration, unset proxy.
contract RevertingTrustedIssuersRegistry {
    function getTrustedIssuersForClaimTopic(uint256) external pure returns (address[] memory) {
        revert("issuers registry down");
    }
}

/// @dev User-deployed ONCHAINID whose getClaim reverts.
contract RevertingIdentity {
    function getClaim(bytes32)
        external
        pure
        returns (uint256, uint256, address, bytes memory, bytes memory, string memory)
    {
        revert("identity boom");
    }
}

/// @dev User-deployed ONCHAINID returning megabytes of claim payload (return bomb).
contract ReturnBombIdentity {
    uint256 private constant BOMB_BYTES = 300_000;

    function getClaim(bytes32)
        external
        pure
        returns (uint256, uint256, address, bytes memory, bytes memory, string memory)
    {
        bytes memory bomb = new bytes(BOMB_BYTES);
        // issuer == address(0): the outcome is SWAP-only whether the probe survives or runs out of gas
        return (0, 1, address(0), bomb, bomb, "");
    }
}

/// @dev ONCHAINID storing a claim under keccak(keyIssuer, topic) while reporting a
///      DIFFERENT issuer in the tuple body — the forged-issuer primitive.
contract SpoofingIdentity {
    struct Claim {
        uint256 topic;
        address issuer;
        bytes signature;
        bytes data;
    }

    mapping(bytes32 => Claim) private claims;

    function addClaimWithSpoofedIssuer(
        address keyIssuer,
        uint256 topic,
        address reportedIssuer,
        bytes memory signature,
        bytes memory data
    ) external {
        claims[keccak256(abi.encode(keyIssuer, topic))] = Claim(topic, reportedIssuer, signature, data);
    }

    function getClaim(bytes32 claimId)
        external
        view
        returns (uint256, uint256, address, bytes memory, bytes memory, string memory)
    {
        Claim memory c = claims[claimId];
        return (c.topic, 1, c.issuer, c.signature, c.data, "");
    }
}

/// @dev Registered claim issuer that always attests validity.
contract AlwaysValidIssuer {
    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Registered claim issuer that burns every unit of gas it is handed.
contract GasBombIssuer {
    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external pure returns (bool) {
        uint256 x = 1;
        for (uint256 i = 0; i < type(uint256).max; i++) {
            x = uint256(keccak256(abi.encode(x, i)));
        }
        return x != 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// @title Fail-closed hardening suite
/// @notice Every test asserts the *absence of a revert* first: checkAllowlist must be a total
///         function, degrading to a lower-or-equal permission instead of bricking the callback.
contract TREXAllowlistCheckerHardeningTest is Test {
    uint256 constant LP_TOPIC = 42;
    bytes constant SIG = hex"beef";
    bytes constant DATA = hex"01";

    /// @dev Ceiling for a single gated check, hostile dependencies included.
    uint256 constant HOT_PATH_GAS_CEILING = 400_000;

    TREXAllowlistChecker checker;
    HostileIdentityRegistry registry;
    MockTrustedIssuersRegistry issuersRegistry;
    MockClaimIssuer trustedIssuer;
    MockToken token;
    MockIdentity bobId;

    address bob = address(0xB0B);

    function setUp() public {
        checker = new TREXAllowlistChecker(LP_TOPIC);

        registry = new HostileIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));

        trustedIssuer = new MockClaimIssuer(true);
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(trustedIssuer));

        token = new MockToken(address(registry));

        bobId = new MockIdentity();
        registry.setIdentity(bob, address(bobId));
        registry.setVerified(bob, true);
    }

    // ── swap gate: any failure resolving the registry must deny, never revert ──

    function test_token_identityRegistry_reverts_returns_NONE() public {
        _assertNone(_checkNoRevert(bob, address(new RevertingToken())), "reverting token");
    }

    function test_token_identityRegistry_returns_short_data_returns_NONE() public {
        _assertNone(_checkNoRevert(bob, address(new ShortReturner())), "short-returning token");
    }

    function test_token_without_code_returns_NONE() public view {
        _assertNone(_checkNoRevert(bob, address(0xDEAD)), "codeless token");
    }

    function test_registry_is_zero_address_returns_NONE() public {
        _assertNone(_checkNoRevert(bob, address(new MockToken(address(0)))), "zero registry");
    }

    function test_registry_without_code_returns_NONE() public {
        _assertNone(_checkNoRevert(bob, address(new MockToken(address(0xDEAD)))), "codeless registry");
    }

    function test_isVerified_reverts_returns_NONE() public {
        registry.setRevertIsVerified(true);
        _assertNone(_checkNoRevert(bob, address(token)), "reverting isVerified");
    }

    // ── LP gate: a failure on the LP path must never destroy the swap right ──

    function test_identity_reverts_returns_SWAP_only() public {
        registry.setRevertIdentity(true);
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "reverting identity()");
    }

    function test_issuersRegistry_reverts_returns_SWAP_only() public {
        registry.setRevertIssuersRegistry(true);
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "reverting issuersRegistry()");
    }

    /// @dev The core of the High finding: a token-wide registry outage must not freeze the pool.
    function test_trustedIssuersRegistry_reverts_returns_SWAP_only() public {
        registry.setIssuersRegistry(address(new RevertingTrustedIssuersRegistry()));
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "reverting getTrustedIssuersForClaimTopic()");
    }

    function test_getClaim_reverts_returns_SWAP_only() public {
        registry.setIdentity(bob, address(new RevertingIdentity()));
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "reverting getClaim()");
    }

    function test_getClaim_returns_short_data_returns_SWAP_only() public {
        registry.setIdentity(bob, address(new ShortReturner()));
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "short-returning getClaim()");
    }

    function test_identity_return_bomb_is_gas_bounded_and_returns_SWAP_only() public {
        registry.setIdentity(bob, address(new ReturnBombIdentity()));
        (PermissionFlag flags, uint256 gasUsed) = _checkMeasured(bob, address(token));
        _assertSwapOnly(flags, "return-bomb identity");
        assertLt(gasUsed, HOT_PATH_GAS_CEILING, "return bomb must stay bounded");
    }

    // ── LP gate: hostile *registered* issuers (the issuer binding holds, the issuer misbehaves) ──

    /// @dev The 16-byte answer is a *successful* staticcall, so try/catch cannot see it: only an
    ///      explicit length check or an isolated frame keeps checkAllowlist alive.
    function test_short_returning_trusted_issuer_returns_SWAP_only() public {
        address badIssuer = address(new ShortReturner());
        issuersRegistry.addTrustedIssuer(LP_TOPIC, badIssuer);
        bobId.addClaim(LP_TOPIC, badIssuer, SIG, DATA);
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "short-returning issuer");
    }

    function test_codeless_trusted_issuer_returns_SWAP_only() public {
        address codeless = address(0xDEAD);
        assertEq(codeless.code.length, 0, "precondition: issuer must be codeless");
        issuersRegistry.addTrustedIssuer(LP_TOPIC, codeless);
        bobId.addClaim(LP_TOPIC, codeless, SIG, DATA);
        _assertSwapOnly(_checkNoRevert(bob, address(token)), "codeless issuer");
    }

    function test_gas_bomb_trusted_issuer_is_bounded_and_returns_SWAP_only() public {
        address bomb = address(new GasBombIssuer());
        issuersRegistry.addTrustedIssuer(LP_TOPIC, bomb);
        bobId.addClaim(LP_TOPIC, bomb, SIG, DATA);

        (PermissionFlag flags, uint256 gasUsed) = _checkMeasured(bob, address(token));
        _assertSwapOnly(flags, "gas-bomb issuer");
        assertLt(gasUsed, HOT_PATH_GAS_CEILING, "gas bomb must stay bounded");
    }

    /// @dev A long registry-curated issuer list must not scale the swap hot path without bound.
    function test_many_trusted_issuers_stay_gas_bounded() public {
        for (uint256 i = 0; i < 200; i++) {
            issuersRegistry.addTrustedIssuer(LP_TOPIC, address(new MockClaimIssuer(false)));
        }
        (, uint256 gasUsed) = _checkMeasured(bob, address(token));
        assertLt(gasUsed, HOT_PATH_GAS_CEILING, "issuer list must not scale the hot path");
    }

    // ── LP gate: forged issuer must not confer liquidity ──

    /// @dev The claim is stored under the TRUSTED issuer's key but names an accomplice in its body.
    ///      Validity must be re-derived from the trusted issuers registry, never from the identity's
    ///      own claim record.
    function test_spoofed_issuer_does_not_grant_LIQUIDITY() public {
        SpoofingIdentity evilId = new SpoofingIdentity();
        AlwaysValidIssuer accomplice = new AlwaysValidIssuer();
        evilId.addClaimWithSpoofedIssuer(address(trustedIssuer), LP_TOPIC, address(accomplice), SIG, DATA);
        registry.setIdentity(bob, address(evilId));

        _assertSwapOnly(_checkNoRevert(bob, address(token)), "spoofed issuer");
    }

    // ── the happy path still works after hardening ──

    function test_valid_claim_still_grants_LIQUIDITY() public {
        bobId.addClaim(LP_TOPIC, address(trustedIssuer), SIG, DATA);
        PermissionFlag flags = _checkNoRevert(bob, address(token));
        assertTrue((flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED, "swap expected");
        assertTrue(
            (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED, "liquidity expected"
        );
    }

    // ── helpers ──

    /// @dev Calls checkAllowlist through a low-level staticcall so a propagated revert surfaces as a
    ///      readable assertion failure instead of an opaque test revert.
    function _checkNoRevert(address account, address tokenAddress) internal view returns (PermissionFlag) {
        (bool ok, bytes memory ret) = address(checker)
            .staticcall(abi.encodeWithSelector(TREXAllowlistChecker.checkAllowlist.selector, account, tokenAddress));
        assertTrue(ok, "VULNERABLE: checkAllowlist reverted instead of degrading");
        return PermissionFlag.wrap(abi.decode(ret, (bytes2)));
    }

    function _checkMeasured(address account, address tokenAddress)
        internal
        view
        returns (PermissionFlag flags, uint256 gasUsed)
    {
        uint256 before = gasleft();
        flags = _checkNoRevert(account, tokenAddress);
        gasUsed = before - gasleft();
    }

    function _assertNone(PermissionFlag flags, string memory ctx) internal pure {
        assertTrue(flags == PermissionFlags.NONE, string.concat("expected NONE: ", ctx));
    }

    function _assertSwapOnly(PermissionFlag flags, string memory ctx) internal pure {
        assertTrue(
            (flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED,
            string.concat("swap expected: ", ctx)
        );
        assertTrue(
            (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.NONE,
            string.concat("liquidity not expected: ", ctx)
        );
    }
}
