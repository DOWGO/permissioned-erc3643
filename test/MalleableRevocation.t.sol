// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {MockIdentity, MockTrustedIssuersRegistry, MockIdentityRegistry, MockToken} from "./TREXAllowlistChecker.t.sol";

/// @dev Reproduces the ONCHAINID `ClaimIssuer` semantics that matter here: revocation is keyed on the
///      exact signature blob, while signature RECOVERY normalises a v below 27 and places no bound on
///      s. Four byte strings therefore recover the same signer, and revoking one leaves three valid.
contract ByteKeyedClaimIssuer {
    mapping(bytes32 => bool) private revoked;

    function revoke(bytes memory sig) external {
        revoked[keccak256(sig)] = true;
    }

    function isClaimRevoked(bytes calldata sig) external view returns (bool) {
        return revoked[keccak256(sig)];
    }

    /// @dev Mirrors ClaimIssuer: valid unless THESE bytes are revoked. It never sees the other three.
    function isClaimValid(address, uint256, bytes calldata sig, bytes calldata) external view returns (bool) {
        return !revoked[keccak256(sig)];
    }
}

/// @dev An issuer whose revocation lookup is expensive on every blob EXCEPT the one it revoked. The
///      checker queries the canonical encoding first, so revoking only the last candidate makes the
///      first three burn before the fourth answers "revoked" — and the loop then has to `continue`
///      to the next trusted issuer on whatever is left.
contract GasBurningRevocationIssuer {
    bytes32 private immutable revokedHash;

    constructor(bytes memory revokedSig) {
        revokedHash = keccak256(revokedSig);
    }

    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }

    function isClaimRevoked(bytes calldata sig) external view returns (bool) {
        if (keccak256(sig) == revokedHash) return true;
        // Consume whatever stipend this call was given.
        uint256 x;
        while (true) {
            x = uint256(keccak256(abi.encode(x)));
        }
        return false;
    }
}

contract MalleableRevocationTest is Test {
    uint256 constant LP_TOPIC = 42;
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes constant DATA = hex"01";

    address bob = address(0xB0B);

    TREXAllowlistChecker checker;
    MockIdentityRegistry registry;
    MockTrustedIssuersRegistry issuersRegistry;
    MockToken token;
    ByteKeyedClaimIssuer issuer;

    bytes32 sigR;
    bytes32 sigS;
    uint8 sigV;

    function setUp() public {
        (, uint256 pk) = makeAddrAndKey("issuerKey");
        (sigV, sigR, sigS) = vm.sign(pk, keccak256("lp-claim"));
        // vm.sign returns the low-s form, so the complement below is the high-s one.
        assertLt(uint256(sigS), SECP256K1_N / 2, "precondition: vm.sign must return low-s");
    }

    /// @dev The four byte strings ONCHAINID's getRecoveredAddress accepts for one signature:
    ///      canonical, raw v (v-27), and the s-complement of each.
    function _encodings() internal view returns (bytes[4] memory out) {
        bytes32 sFlip = bytes32(SECP256K1_N - uint256(sigS));
        uint8 vFlip = sigV == 27 ? 28 : 27;
        out[0] = abi.encodePacked(sigR, sigS, sigV);
        out[1] = abi.encodePacked(sigR, sigS, uint8(sigV - 27));
        out[2] = abi.encodePacked(sigR, sFlip, vFlip);
        out[3] = abi.encodePacked(sigR, sFlip, uint8(vFlip - 27));
    }

    /// @dev A fresh world each time: the holder's identity carries `installed`, and the issuer has
    ///      revoked `revokedEncoding` (skipped when empty).
    function _world(bytes memory installed, bytes memory revokedEncoding) internal {
        checker = new TREXAllowlistChecker(LP_TOPIC);
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));

        issuer = new ByteKeyedClaimIssuer();
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(issuer));

        MockIdentity id = new MockIdentity();
        id.addClaim(LP_TOPIC, address(issuer), installed, DATA);
        registry.setIdentity(bob, address(id));
        registry.setVerified(bob, true);

        if (revokedEncoding.length != 0) issuer.revoke(revokedEncoding);
    }

    function _hasLiquidity() internal view returns (bool) {
        PermissionFlag flags = checker.checkAllowlist(bob, address(token));
        assertTrue(
            (flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED,
            "the swap right is not at stake on this path"
        );
        return (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED;
    }

    /// @notice Revoking ANY single encoding must close all four. Before the guard, the issuer's
    ///         revocation only bound the blob it named, so the holder re-installed the claim under a
    ///         re-encoding and the flag came back — up to four times.
    function test_revoking_any_encoding_closes_all_four() public {
        bytes[4] memory e = _encodings();
        for (uint256 revokedIdx = 0; revokedIdx < 4; revokedIdx++) {
            for (uint256 installedIdx = 0; installedIdx < 4; installedIdx++) {
                _world(e[installedIdx], e[revokedIdx]);
                assertFalse(
                    _hasLiquidity(),
                    string.concat(
                        "REGRESSION: revoked encoding ",
                        vm.toString(revokedIdx),
                        " did not close installed encoding ",
                        vm.toString(installedIdx)
                    )
                );
            }
        }
    }

    /// @notice The guard must not deny a claim that was never revoked, whichever encoding the issuer
    ///         happened to sign with — otherwise it becomes a denial-of-service on honest LPs.
    function test_no_false_negative_when_nothing_is_revoked() public {
        bytes[4] memory e = _encodings();
        for (uint256 i = 0; i < 4; i++) {
            _world(e[i], "");
            assertTrue(_hasLiquidity(), string.concat("honest claim denied under encoding ", vm.toString(i)));
        }
    }

    /// @notice A blob that is not a 65-byte ECDSA encoding is left entirely to the issuer's own
    ///         semantics: the checker enumerates nothing and denies nothing.
    function test_non_ecdsa_signature_is_left_to_the_issuer() public {
        _world(hex"beef", "");
        assertTrue(_hasLiquidity(), "a non-ECDSA blob must not be denied by the encoding guard");

        _world(hex"beef", hex"beef");
        assertFalse(_hasLiquidity(), "the issuer's own revocation of that blob must still bind");
    }

    /// @notice The four revocation reads are gas-bounded for the same reason the validity read is.
    ///         This path can `continue`, and the next iteration's `getClaim` sits in no guarded
    ///         frame — so an issuer allowed to burn the probe here would destroy a later honest
    ///         issuer's independently valid claim, which is the defect the per-issuer bound closes.
    function test_gas_burning_revocation_lookup_does_not_starve_the_next_issuer() public {
        bytes[4] memory e = _encodings();

        checker = new TREXAllowlistChecker(LP_TOPIC);
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));

        // Index 0: revoked, and expensive to ask about anything but the revoked blob.
        address burner = address(new GasBurningRevocationIssuer(e[3]));
        // Index 1: an honest issuer holding this LP's genuinely valid claim.
        ByteKeyedClaimIssuer honest = new ByteKeyedClaimIssuer();

        issuersRegistry.addTrustedIssuer(LP_TOPIC, burner);
        issuersRegistry.addTrustedIssuer(LP_TOPIC, address(honest));

        MockIdentity id = new MockIdentity();
        id.addClaim(LP_TOPIC, burner, e[0], DATA);
        id.addClaim(LP_TOPIC, address(honest), e[0], DATA);
        registry.setIdentity(bob, address(id));
        registry.setVerified(bob, true);

        assertTrue(
            _hasLiquidity(), "REGRESSION: a gas-burning revocation lookup destroyed a later honest issuer's claim"
        );
    }

    /// @notice Control: the same burner alone still denies, so the test above is not passing because
    ///         the burner was skipped for an unrelated reason.
    function test_control_gas_burning_issuer_alone_is_still_revoked() public {
        bytes[4] memory e = _encodings();

        checker = new TREXAllowlistChecker(LP_TOPIC);
        registry = new MockIdentityRegistry();
        issuersRegistry = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuersRegistry));
        token = new MockToken(address(registry));

        address burner = address(new GasBurningRevocationIssuer(e[3]));
        issuersRegistry.addTrustedIssuer(LP_TOPIC, burner);

        MockIdentity id = new MockIdentity();
        id.addClaim(LP_TOPIC, burner, e[0], DATA);
        registry.setIdentity(bob, address(id));
        registry.setVerified(bob, true);

        assertFalse(_hasLiquidity(), "the revoked encoding must still deny when it is the only issuer");
    }
}
