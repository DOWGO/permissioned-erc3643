// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {MockToken} from "./TREXAllowlistChecker.t.sol";
import {DeployedShape, IIdentityProxy} from "./fixtures/DeployedShape.sol";

/// @notice Pins the fixture itself, so a test built on it exercises the shape the deployer ships.
contract DeployedShapeTest is DeployedShape {
    uint256 constant LP_TOPIC = 42;

    address holder = makeAddr("holder");
    address holderKey = makeAddr("holderKey");

    function test_fixture_builds_a_verified_holder_whose_lp_claim_is_honoured() public {
        TrexSuite memory suite = _newTrexSuite();
        address identity = _newIdentity(holderKey);
        _registerVerified(suite, holder, identity, holderKey);
        ClaimIssuerFixture memory lpIssuer = _newClaimIssuer();
        _trust(suite, lpIssuer.issuer, LP_TOPIC);
        _addClaim(identity, holderKey, lpIssuer.issuer, LP_TOPIC, _signClaim(lpIssuer, identity, LP_TOPIC), 0);

        assertTrue(IIdentityProxy(identity).implementationAuthority() != address(0), "identity behind IdentityProxy");
        assertTrue(vm.addr(lpIssuer.signingKey) != lpIssuer.manager, "claims signed by a non-management key");

        TREXAllowlistChecker checker = new TREXAllowlistChecker(LP_TOPIC);
        PermissionFlag flags = checker.checkAllowlist(holder, address(new MockToken(suite.identityRegistry)));
        assertTrue(
            flags == PermissionFlags.SWAP_ALLOWED | PermissionFlags.LIQUIDITY_ALLOWED,
            "a verified holder with a valid LP claim gets both flags"
        );
    }
}
