// SPDX-License-Identifier: MIT
// Vendored verbatim from Cyfrin audit finding #11..#6 reproduction, with ONE edit: the assertion
// that documented the vulnerability is inverted, so this file is now a regression test for
// `fix(#6)`. Source: https://github.com/Cyfrin/audit-2026-09-dowgo/issues/6
//
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXAllowlistChecker} from "../../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {
    MockIdentity,
    MockClaimIssuer,
    MockTrustedIssuersRegistry,
    MockIdentityRegistry,
    MockToken
} from "../TREXAllowlistChecker.t.sol";
import {GasBombIssuer} from "../TREXAllowlistCheckerHardening.t.sol";

interface IBoolIssuer {
    function isClaimValid(address identity, uint256 topic, bytes calldata sig, bytes calldata data)
        external
        view
        returns (bool);
}

/// @notice `probeLpClaim`'s per-issuer `try/catch` isolates a trusted issuer that REVERTS, but not
///         one that consumes the probe's gas. The call at the issuer carries no `{gas:}` modifier,
///         so a single issuer receives 63/64 of the probe's remaining budget; the surviving 1/64
///         is then spent by the NEXT iteration's unguarded `getClaim`, whose out-of-gas is inside
///         no `try/catch` and reverts the whole probe. Every trusted issuer below the burner loses
///         its turn, so a holder's independently valid claim from an honest issuer is destroyed
contract GasBurningIssuerDeniesLaterIssuersTest is Test {
    uint256 constant LP_TOPIC = 42;
    bytes constant SIG = hex"beef";
    bytes constant DATA = hex"01";

    TREXAllowlistChecker checker;
    MockIdentityRegistry registry;
    MockTrustedIssuersRegistry issuersRegistry;
    MockToken token;
    MockIdentity bobId;

    address bob = address(0xB0B);

    /// @dev Bob holds a valid LP claim from an honest registry-trusted issuer AND a claim from a
    ///      gas-burning one, which is the ordinary shape of an LP carrying redundant
    ///      attestations. `burnerFirst` chooses only the order the registry returns them in
    function _world(bool burnerFirst) internal {
        checker = new TREXAllowlistChecker(LP_TOPIC);
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));

        bobId = new MockIdentity();
        registry.setIdentity(bob, address(bobId));
        registry.setVerified(bob, true);

        address burner = address(new GasBombIssuer());
        address honest = address(new MockClaimIssuer(true));

        if (burnerFirst) {
            issuersRegistry.addTrustedIssuer(LP_TOPIC, burner);
            issuersRegistry.addTrustedIssuer(LP_TOPIC, honest);
        } else {
            issuersRegistry.addTrustedIssuer(LP_TOPIC, honest);
            issuersRegistry.addTrustedIssuer(LP_TOPIC, burner);
        }

        bobId.addClaim(LP_TOPIC, burner, SIG, DATA);
        bobId.addClaim(LP_TOPIC, honest, SIG, DATA);
    }

    function _flags() internal view returns (PermissionFlag) {
        (bool ok, bytes memory ret) = address(checker).staticcall(
            abi.encodeWithSelector(TREXAllowlistChecker.checkAllowlist.selector, bob, address(token))
        );
        assertTrue(ok, "checkAllowlist must stay total and never propagate a revert");
        return PermissionFlag.wrap(abi.decode(ret, (bytes2)));
    }

    function _hasLiquidity() internal view returns (bool) {
        PermissionFlag flags = _flags();
        assertTrue(
            (flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED,
            "the swap right is not at stake on this path in either ordering"
        );
        return (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED;
    }

    function test_PoC_GasBurningIssuerDeniesLaterIssuers() public {
        // The honest issuer is reached before the burner, so its valid claim is honoured
        _world(false);
        assertTrue(_hasLiquidity(), "control: the honest issuer's claim grants liquidity when reached first");

        // Same two issuers, same two claims, same validity - only the registry's order differs
        _world(true);
        assertTrue(
            _hasLiquidity(),
            "REGRESSION: a gas-burning issuer destroyed an honest issuer's independently valid claim"
        );
    }

    /// @dev A trusted issuer that REVERTS is correctly confined to itself, which is what the
    ///      per-issuer catch was written for. Isolating this case shows the defect above is the
    ///      missing gas bound, not a missing catch
    function test_PoC_RevertingIssuerStaysConfined() public {
        checker = new TREXAllowlistChecker(LP_TOPIC);
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));

        bobId = new MockIdentity();
        registry.setIdentity(bob, address(bobId));
        registry.setVerified(bob, true);

        MockClaimIssuer reverting = new MockClaimIssuer(true);
        reverting.setShouldRevert(true);
        address honest = address(new MockClaimIssuer(true));

        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(reverting));
        issuersRegistry.addTrustedIssuer(LP_TOPIC, honest);
        bobId.addClaim(LP_TOPIC, address(reverting), SIG, DATA);
        bobId.addClaim(LP_TOPIC, honest, SIG, DATA);

        assertTrue(_hasLiquidity(), "a reverting issuer at index 0 does not deny the honest issuer its turn");
    }
}
