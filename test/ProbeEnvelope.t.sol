// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TREXAllowlistChecker} from "../src/TREXAllowlistChecker.sol";
import {LpListShape, ProbeMeter} from "./IssuerStipends.t.sol";

/// @notice The probe cap is sized for a documented envelope on the deployed shape — ten LP-topic
///         entries, the holder holding a claim from only one of them, a 1KB payload — and fails
///         closed beyond it.
contract ProbeEnvelopeTest is LpListShape {
    uint256 constant ENVELOPE_ENTRIES = 10;
    uint256 constant ENVELOPE_URI_LENGTH = 1024;
    uint256 constant ENVELOPE_DATA_LENGTH = 1024;
    /// @dev Enough for any claim below to be granted, so a denial through `checkAllowlist` is the cap.
    uint256 constant UNCAPPED_BUDGET = 2_000_000;

    TREXAllowlistChecker checker;
    ProbeMeter meter;

    function setUp() public {
        checker = new TREXAllowlistChecker(LP_TOPIC);
        meter = new ProbeMeter();
    }

    /// @notice The envelope's edge: nothing hostile, no other claim of the holder in the list, the
    ///         valid claim at the last entry, a 1KB `uri`.
    function test_envelope_edge_is_granted() public {
        address token = _lpList(_list(ENVELOPE_ENTRIES, ENVELOPE_ENTRIES - 1), ENVELOPE_URI_LENGTH);
        assertTrue(_hasLiquidity(checker, token), "the envelope's edge must be granted");
    }

    /// @notice Past the envelope, on any axis — more entries, a larger payload, or other claims of the
    ///         holder that no longer validate — the liquidity flag is denied and the swap flag kept,
    ///         without a revert, although the claim itself is valid.
    function test_claim_beyond_the_envelope_fails_closed() public {
        _assertFailsClosed(_lpList(_list(16, 15), ENVELOPE_URI_LENGTH), "sixteen entries, 1KB uri");
        _assertFailsClosed(_lpList(_list(ENVELOPE_ENTRIES, ENVELOPE_ENTRIES - 1), 3072), "ten entries, 3KB uri");
        Entry[] memory twoRevokedAhead = _list(ENVELOPE_ENTRIES, ENVELOPE_ENTRIES - 1);
        twoRevokedAhead[0] = Entry.Revoked;
        twoRevokedAhead[1] = Entry.Revoked;
        _assertFailsClosed(
            _lpList(twoRevokedAhead, ENVELOPE_URI_LENGTH),
            "ten entries, two revoked claims of the holder ahead, 1KB uri"
        );
    }

    /// @notice The stipend covers a signing key holding seven purposes in the costliest order — CLAIM
    ///         stored last — on a claim carrying the envelope's 1KB payload in `data`, which
    ///         `isClaimValid` hashes, at the envelope's edge. A key holding eight cannot grant
    ///         liquidity on such a claim whatever the budget; the seven-purpose grant, on a heavier
    ///         list, is the control that the purpose count alone denies the eight.
    function test_signing_key_purposes_the_stipend_covers() public {
        honestSigningKeyPurposes = 7;
        honestClaimData = new bytes(ENVELOPE_DATA_LENGTH);
        address token = _lpList(_list(ENVELOPE_ENTRIES, ENVELOPE_ENTRIES - 1), 0);
        assertTrue(_hasLiquidity(checker, token), "seven purposes at the envelope's edge must be granted");

        honestSigningKeyPurposes = 8;
        token = _lpList(_list(1, 0), 0);
        (bool grantedUncapped,) = meter.probe(checker, token, holder, UNCAPPED_BUDGET);
        assertFalse(grantedUncapped, "eight purposes exceed the stipend whatever the budget");
        assertFalse(_hasLiquidity(checker, token), "eight purposes must deny");
    }

    /// @notice End to end through the cap: a hostile issuer at index 0 that burns every stipend does
    ///         not cost the honest issuer behind it the flag, and is not granted on its own.
    function test_hostile_head_does_not_deny_the_next_issuer() public {
        Entry[] memory entries = _list(2, 1);
        entries[0] = Entry.Burner;
        assertTrue(_hasLiquidity(checker, _lpList(entries, 0)), "the honest issuer behind a burner must grant");

        Entry[] memory burnerOnly = new Entry[](1);
        burnerOnly[0] = Entry.Burner;
        assertFalse(_hasLiquidity(checker, _lpList(burnerOnly, 0)), "control: the burner alone must not grant");
    }

    function _assertFailsClosed(address token, string memory shape) internal view {
        (bool grantedUncapped,) = meter.probe(checker, token, holder, UNCAPPED_BUDGET);
        assertTrue(grantedUncapped, string.concat("control: the claim is valid given the gas, ", shape));
        assertFalse(_hasLiquidity(checker, token), string.concat("beyond the envelope must deny, ", shape));
    }
}
