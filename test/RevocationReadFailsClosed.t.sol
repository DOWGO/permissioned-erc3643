// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {MockIdentityRegistry, MockTrustedIssuersRegistry, MockToken} from "./TREXAllowlistChecker.t.sol";
import {DeployedShape, IOnchainId} from "./fixtures/DeployedShape.sol";

/// @dev A trusted issuer that vouches for every claim and has no `isClaimRevoked`, so it cannot say
///      whether an equivalent encoding of a signature was revoked.
contract NoRevocationLookupIssuer {
    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice A revocation read that does not answer must count as revoked. The holder decides how much
///         gas is left when the read runs: every byte of the unsigned `uri` is spent in `getClaim`
///         first. Read as "not revoked", a starved read of the revoked encoding grants it back.
///
///         Two tests guard two things. The `uri` sweeps guard how the reads are funded: budgeted as
///         a share of what is left, they starve at `uri` lengths the frame can otherwise still
///         afford, so a fail-open read grants there. The sweeps cover every length up to the point
///         where the frame no longer affords the unrevoked claim itself, whatever the cap. The
///         no-lookup issuer guards the polarity: with a fixed stipend, a read only starves as the
///         frame dies, so that test alone fails if an unanswered read stops counting as revoked.
contract RevocationReadFailsClosedTest is DeployedShape {
    uint256 constant LP_TOPIC = 42;
    uint256 constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @dev Narrower than any window at which a starved read used to grant: 48 bytes at a 200k cap
    ///      (0.7KB to 1.4KB), a few hundred at 400k (3.5KB to 4.4KB).
    uint256 constant URI_STEP = 32;
    /// @dev Granularity of the search for the length past which the frame denies even an unrevoked
    ///      claim, and the distance swept beyond it.
    uint256 constant EDGE_STEP = 64;
    uint256 constant SWEEP_MARGIN = 512;

    address holder = makeAddr("holder");
    address holderKey = makeAddr("holderKey");

    TREXAllowlistChecker checker;
    MockTrustedIssuersRegistry issuers;
    MockToken token;
    address identity;

    function setUp() public {
        checker = new TREXAllowlistChecker(LP_TOPIC);
    }

    /// @notice The issuer revokes the canonical encoding; the holder re-installs each equivalent
    ///         re-encoding with every `uri` length. The re-installs succeed — `addClaim` asks the
    ///         issuer, which keys revocation on the exact bytes — so only the checker's own revocation
    ///         reads stand between the holder and the flag. One test per number of trusted issuers
    ///         after the revoking one, since each moves the gas left when those reads run.
    function test_padded_uri_cannot_revive_a_revoked_claim_with_no_issuer_after() public {
        _assertNoUriLengthRevivesARevokedClaim(0);
    }

    function test_padded_uri_cannot_revive_a_revoked_claim_with_one_issuer_after() public {
        _assertNoUriLengthRevivesARevokedClaim(1);
    }

    function test_padded_uri_cannot_revive_a_revoked_claim_with_two_issuers_after() public {
        _assertNoUriLengthRevivesARevokedClaim(2);
    }

    function test_padded_uri_cannot_revive_a_revoked_claim_with_three_issuers_after() public {
        _assertNoUriLengthRevivesARevokedClaim(3);
    }

    /// @notice An issuer that cannot answer the revocation question cannot grant a claim whose
    ///         signature has revocable equivalents.
    function test_issuer_without_revocation_lookup_cannot_grant_an_ecdsa_claim() public {
        _world();
        address issuer = address(new NoRevocationLookupIssuer());
        issuers.addTrustedIssuer(LP_TOPIC, issuer);
        (, uint256 anyKey) = makeAddrAndKey("anyKey");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(anyKey, keccak256("any claim"));
        _addClaim(identity, holderKey, issuer, LP_TOPIC, abi.encodePacked(r, s, v), 0);

        assertFalse(_hasLiquidity(), "an unanswered revocation read must deny a 65-byte claim");
    }

    /// @notice A blob that is not a 65-byte ECDSA encoding is never enumerated, so the same issuer
    ///         keeps deciding it alone.
    function test_issuer_without_revocation_lookup_keeps_a_non_ecdsa_claim() public {
        _world();
        address issuer = address(new NoRevocationLookupIssuer());
        issuers.addTrustedIssuer(LP_TOPIC, issuer);
        _addClaim(identity, holderKey, issuer, LP_TOPIC, hex"beef", 0);

        assertTrue(_hasLiquidity(), "a non-ECDSA blob is left to the issuer's own isClaimValid");
    }

    function _assertNoUriLengthRevivesARevokedClaim(uint256 trailing) internal {
        ClaimIssuerFixture memory issuer = _world();
        issuers.addTrustedIssuer(LP_TOPIC, issuer.issuer);
        for (uint256 i = 0; i < trailing; i++) {
            issuers.addTrustedIssuer(LP_TOPIC, address(uint160(0x1000 + i)));
        }

        bytes[4] memory encodings = _encodings(_signClaim(issuer, identity, LP_TOPIC));
        _addClaim(identity, holderKey, issuer.issuer, LP_TOPIC, encodings[0], 0);
        assertTrue(_hasLiquidity(), "control: the claim grants before it is revoked");
        uint256 sweepEnd = _frameEdge(issuer.issuer, encodings[0]) + SWEEP_MARGIN;

        vm.prank(issuer.manager);
        IOnchainId(issuer.issuer).revokeClaimBySignature(encodings[0]);

        for (uint256 e = 1; e < 4; e++) {
            for (uint256 uriLength = 0; uriLength <= sweepEnd; uriLength += URI_STEP) {
                _addClaim(identity, holderKey, issuer.issuer, LP_TOPIC, encodings[e], uriLength);
                assertFalse(
                    _hasLiquidity(),
                    string.concat(
                        "revoked claim granted: re-encoding ",
                        vm.toString(e),
                        ", uri length ",
                        vm.toString(uriLength),
                        ", issuers after the revoking one ",
                        vm.toString(trailing)
                    )
                );
            }
        }
    }

    /// @dev The first `uri` length at which the frame denies the still-valid canonical claim: past
    ///      it no read runs at all, so no starved read can grant anything.
    function _frameEdge(address issuer, bytes memory canonical) internal returns (uint256 uriLength) {
        for (uriLength = EDGE_STEP;; uriLength += EDGE_STEP) {
            _addClaim(identity, holderKey, issuer, LP_TOPIC, canonical, uriLength);
            if (!_hasLiquidity()) return uriLength;
        }
    }

    /// @dev A verified holder whose identity sits behind IdentityProxy, with an empty issuer list
    ///      and a fresh `ClaimIssuer` for the caller to place in it.
    function _world() internal returns (ClaimIssuerFixture memory issuer) {
        MockIdentityRegistry registry = new MockIdentityRegistry();
        issuers = new MockTrustedIssuersRegistry();
        registry.setIssuersRegistry(address(issuers));
        token = new MockToken(address(registry));
        identity = _newIdentity(holderKey);
        registry.setIdentity(holder, identity);
        registry.setVerified(holder, true);
        issuer = _newClaimIssuer();
    }

    /// @dev The four byte strings ONCHAINID's getRecoveredAddress accepts for one signature:
    ///      canonical, raw v (v - 27), and the s-complement of each.
    function _encodings(bytes memory canonical) internal pure returns (bytes[4] memory out) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(canonical, 32))
            s := mload(add(canonical, 64))
            v := byte(0, mload(add(canonical, 96)))
        }
        bytes32 sFlip = bytes32(SECP256K1_N - uint256(s));
        uint8 vFlip = v == 27 ? 28 : 27;
        out[0] = canonical;
        out[1] = abi.encodePacked(r, s, v - 27);
        out[2] = abi.encodePacked(r, sFlip, vFlip);
        out[3] = abi.encodePacked(r, sFlip, vFlip - 27);
    }

    function _hasLiquidity() internal view returns (bool) {
        (bool ok, bytes memory ret) = address(checker)
            .staticcall(abi.encodeWithSelector(TREXAllowlistChecker.checkAllowlist.selector, holder, address(token)));
        assertTrue(ok, "checkAllowlist must never revert");
        PermissionFlag flags = PermissionFlag.wrap(abi.decode(ret, (bytes2)));
        assertTrue((flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED, "swap is not at stake");
        return (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED;
    }
}
