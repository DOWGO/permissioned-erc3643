// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TREXAllowlistChecker, ITREXToken, ITREXIdentityRegistry} from "../src/TREXAllowlistChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";
import {MockToken} from "./TREXAllowlistChecker.t.sol";
import {DeployedShape} from "./fixtures/DeployedShape.sol";

/// @dev A trusted issuer that spends almost all of every stipend it is handed and still answers, so
///      each of its reads costs the checker the whole stipend. It vouches for its holder's claim, so
///      the checker goes on to ask it all four revocation reads. Armed after the holder's `addClaim`,
///      which asks it for validity with the transaction's full gas.
contract StipendBurningIssuer {
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    /// @dev Left unspent so the answer is still returned.
    uint256 private constant ANSWER_GAS = 2_000;

    bool private armed;

    function arm() external {
        armed = true;
    }

    function isClaimValid(address, uint256, bytes calldata, bytes calldata) external view returns (bool) {
        if (!armed) return true;
        _burn();
        return true;
    }

    /// @dev "Not revoked" for the first three encodings the checker asks about and "revoked" for the
    ///      last one (high s, raw v), so the burner is asked all four and still denied.
    function isClaimRevoked(bytes calldata signature) external view returns (bool) {
        _burn();
        return uint8(signature[64]) < 27 && uint256(bytes32(signature[32:64])) > HALF_N;
    }

    function _burn() private view {
        while (gasleft() > ANSWER_GAS) {}
    }
}

/// @dev Runs `probeLpClaim` the way `checkAllowlist` does — after the same swap-side reads, so it
///      finds the same state warm — with a chosen budget, and reports what the probe spent.
contract ProbeMeter {
    function probe(TREXAllowlistChecker checker, address token, address account, uint256 budget)
        external
        view
        returns (bool granted, uint256 spent)
    {
        address registry = ITREXToken(token).identityRegistry();
        ITREXIdentityRegistry(registry).isVerified(account);
        checker.probeTokenControls(token, account);

        uint256 before = gasleft();
        try checker.probeLpClaim{gas: budget}(registry, account) returns (bool hasClaim) {
            granted = hasClaim;
        } catch {}
        spent = before - gasleft();
    }
}

/// @notice A holder on the deployed shape whose LP-topic list is laid out entry by entry.
abstract contract LpListShape is DeployedShape {
    uint256 internal constant LP_TOPIC = 42;
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    enum Entry {
        Filler,
        Honest,
        Burner
    }

    address internal holder = makeAddr("holder");
    address internal holderKey = makeAddr("holderKey");

    /// @notice A verified holder on a fresh T-REX suite whose LP-topic list holds `entries` in order:
    ///         a trusted address the holder holds no claim from, a `ClaimIssuer` that signed the
    ///         holder's claim with a `uri` of `uriLength` bytes, or a burner the holder also holds a
    ///         claim from.
    /// @return token A token governed by that suite.
    function _lpList(Entry[] memory entries, uint256 uriLength) internal returns (address token) {
        TrexSuite memory suite = _newTrexSuite();
        address identity = _newIdentity(holderKey);
        _registerVerified(suite, holder, identity, holderKey);
        for (uint256 i = 0; i < entries.length; i++) {
            _trust(suite, _entry(entries[i], identity, uriLength, i), LP_TOPIC);
        }
        token = address(new MockToken(suite.identityRegistry));
    }

    /// @notice `length` fillers, with the honest issuer at `honestIndex`.
    function _list(uint256 length, uint256 honestIndex) internal pure returns (Entry[] memory entries) {
        entries = new Entry[](length);
        entries[honestIndex] = Entry.Honest;
    }

    function _entry(Entry kind, address identity, uint256 uriLength, uint256 index) private returns (address) {
        if (kind == Entry.Filler) return address(uint160(0x1000 + index));
        if (kind == Entry.Honest) {
            ClaimIssuerFixture memory issuer = _newClaimIssuer();
            bytes memory signature = _signClaim(issuer, identity, LP_TOPIC);
            _addClaim(identity, holderKey, issuer.issuer, LP_TOPIC, signature, uriLength);
            return issuer.issuer;
        }
        StipendBurningIssuer burner = new StipendBurningIssuer();
        (, uint256 anyKey) = makeAddrAndKey("burnerClaimKey");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(anyKey, keccak256(abi.encode("burner claim", index)));
        require(uint256(s) <= HALF_N, "the burner's revoked encoding must be the high-s, raw-v one");
        _addClaim(identity, holderKey, address(burner), LP_TOPIC, abi.encodePacked(r, s, v), 0);
        burner.arm();
        return address(burner);
    }

    function _hasLiquidity(TREXAllowlistChecker checker, address token) internal view returns (bool) {
        (bool ok, bytes memory ret) = address(checker)
            .staticcall(abi.encodeWithSelector(TREXAllowlistChecker.checkAllowlist.selector, holder, token));
        assertTrue(ok, "checkAllowlist must never revert");
        PermissionFlag flags = PermissionFlag.wrap(abi.decode(ret, (bytes2)));
        assertTrue((flags & PermissionFlags.SWAP_ALLOWED) == PermissionFlags.SWAP_ALLOWED, "swap is not at stake");
        return (flags & PermissionFlags.LIQUIDITY_ALLOWED) == PermissionFlags.LIQUIDITY_ALLOWED;
    }
}

/// @notice `isClaimValid` carries a fixed stipend. A share of what is left shrinks as the list grows,
///         until it no longer covers an honest issuer near the head of a long list, and grows with the
///         budget, so a burning issuer took more the more gas the caller supplied.
contract IssuerStipendsTest is LpListShape {
    uint256 constant LIST_LENGTH = 10;

    /// @dev What a hostile entry may cost over a filler in its place: the five stipends it can spend
    ///      (40,000 + 4 x 10,000) plus reading its claim and calling it. Measured at about 86,300.
    uint256 constant HOSTILE_TAKE_CEILING = 110_000;

    TREXAllowlistChecker checker;
    ProbeMeter meter;

    function setUp() public {
        checker = new TREXAllowlistChecker(LP_TOPIC);
        meter = new ProbeMeter();
    }

    /// @notice Nothing hostile anywhere, and the valid claim is the first entry the scan reaches.
    function test_honest_claim_at_the_head_of_a_ten_entry_list_is_granted() public {
        address token = _lpList(_list(LIST_LENGTH, 0), 0);
        assertTrue(_hasLiquidity(checker, token), "an honest claim at index 0 of ten entries must be granted");
    }

    /// @notice A hostile issuer at index 0 that burns its validity read, vouches, and burns all four
    ///         revocation reads takes the same bounded amount whatever the budget, and the honest
    ///         issuer behind it is still reached. Measured against a filler at index 0, which the scan
    ///         walks past without calling.
    function test_hostile_issuer_takes_a_bounded_constant_and_the_next_issuer_is_reached() public {
        Entry[] memory entries = _list(2, 1);
        address filler = _lpList(entries, 0);
        entries[0] = Entry.Burner;
        address hostile = _lpList(entries, 0);
        uint256[2] memory budgets = [uint256(1_000_000), 4_000_000];
        for (uint256 b = 0; b < budgets.length; b++) {
            (bool hostileGranted, uint256 hostileSpent) = meter.probe(checker, hostile, holder, budgets[b]);
            (bool fillerGranted, uint256 fillerSpent) = meter.probe(checker, filler, holder, budgets[b]);
            string memory budget = vm.toString(budgets[b]);
            assertTrue(
                fillerGranted, string.concat("control: the honest issuer grants behind a filler, budget ", budget)
            );
            assertTrue(hostileGranted, string.concat("the honest issuer must be reached, budget ", budget));
            assertLt(
                hostileSpent - fillerSpent,
                HOSTILE_TAKE_CEILING,
                string.concat("a hostile entry must take a bounded constant, budget ", budget)
            );
        }
    }

    /// @notice Control: the same hostile issuer alone is never granted, so the grant above is the
    ///         honest issuer's and not the burner's own claim surviving a starved read.
    function test_control_hostile_issuer_alone_is_not_granted() public {
        Entry[] memory burnerOnly = new Entry[](1);
        burnerOnly[0] = Entry.Burner;
        address alone = _lpList(burnerOnly, 0);
        uint256[4] memory budgets = [uint256(100_000), 400_000, 1_000_000, 4_000_000];
        for (uint256 b = 0; b < budgets.length; b++) {
            (bool granted,) = meter.probe(checker, alone, holder, budgets[b]);
            assertFalse(granted, string.concat("the burner's own claim granted, budget ", vm.toString(budgets[b])));
        }
        assertFalse(_hasLiquidity(checker, alone), "the burner's own claim granted through checkAllowlist");
    }
}
