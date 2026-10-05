// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {BaseAllowlistChecker} from "@uniswap/v4-periphery/src/hooks/permissionedPools/BaseAllowListChecker.sol";
import {
    PermissionFlag,
    PermissionFlags
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/libraries/PermissionFlags.sol";

/// @notice Minimal slice of the ERC-3643 token surface used by the checker.
interface ITREXToken {
    /// @return The IdentityRegistry governing this token's holders.
    function identityRegistry() external view returns (address);
    /// @return True while an agent has paused all transfers of this token.
    function paused() external view returns (bool);
    /// @return True while an agent has frozen this wallet outright.
    function isFrozen(address _userAddress) external view returns (bool);
}

/// @notice Minimal slice of the ERC-3643 IdentityRegistry surface used by the checker.
interface ITREXIdentityRegistry {
    /// @notice Full ERC-3643 verification: all required claim topics present and valid.
    function isVerified(address _userAddress) external view returns (bool);
    /// @notice The OnchainID contract bound to `_userAddress` (address(0) if none).
    function identity(address _userAddress) external view returns (address);
    /// @notice The TrustedIssuersRegistry this registry trusts for claim validation.
    function issuersRegistry() external view returns (address);
}

/// @notice Minimal slice of the ERC-3643 TrustedIssuersRegistry surface used by the checker.
interface ITREXTrustedIssuersRegistry {
    /// @return The claim issuers trusted to attest `claimTopic`.
    function getTrustedIssuersForClaimTopic(uint256 claimTopic) external view returns (address[] memory);
}

/// @notice Minimal slice of the OnchainID (ERC-735) surface used by the checker.
interface ITREXIdentity {
    /// @dev Returns (topic, scheme, issuer, signature, data, uri) of the claim `_claimId`.
    function getClaim(bytes32 _claimId)
        external
        view
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            bytes memory data,
            string memory uri
        );
}

/// @notice Minimal slice of the ERC-3643 ClaimIssuer surface used by the checker.
interface ITREXClaimIssuer {
    /// @return True if the claim is currently valid (signed by the issuer and not revoked).
    function isClaimValid(address _identity, uint256 _claimTopic, bytes calldata _sig, bytes calldata _data)
        external
        view
        returns (bool);
    /// @return True if this exact signature blob has been revoked by the issuer.
    function isClaimRevoked(bytes calldata _sig) external view returns (bool);
}

/// @title TREXAllowlistChecker
/// @notice Maps ERC-3643 (T-REX) verification + a valid LP claim topic to a v4 PermissionFlag
///         for use with a PermissionsAdapter.
/// @dev    - isVerified() => SWAP_ALLOWED, exactly as strong as the deployed registry's verification.
///           The ERC-3643 4.x reference registry does not bind a claim body to the trusted issuer its id
///           was derived from, so this holds only for identities registered through a canonicity check.
///         - isVerified() && a VALID claim of `LP_CLAIM_TOPIC` from a trusted issuer => + LIQUIDITY_ALLOWED.
///         LP validation follows ERC-3643 IdentityRegistry.isVerified — claim ids derived from each
///         trusted issuer, isClaimValid required (not revoked) — and additionally binds the claim to that issuer.
///
///         `checkAllowlist` is a TOTAL function: it runs inside the PoolManager's beforeSwap /
///         beforeAddLiquidity callback, where a revert does not deny the caller — it bricks the pool
///         for everyone. Every failure mode of the T-REX chain (revert, missing contract, malformed
///         return data, return bomb, gas bomb) therefore degrades to a strictly lower-or-equal
///         permission instead of propagating.
contract TREXAllowlistChecker is BaseAllowlistChecker {
    /// @notice The OnchainID claim topic that gates liquidity provision.
    uint256 public immutable LP_CLAIM_TOPIC;

    /// @dev Gas handed to the isolated LP probe, and the only bound on its scan: the issuer list is
    ///      never truncated at an entry count. Sized for the documented envelope — ten entries in the
    ///      LP topic's trusted-issuer list, the holder holding a claim from only one of them, `uri`
    ///      and `data` together at most 1KB — whose edge, that claim at the last entry with a 1KB
    ///      payload, needs about 364k on the deployed shape (T-REX 4.1.6 registries and ONCHAINID
    ///      2.2.1 identities behind their proxies): about 23k per entry walked past and 70 per
    ///      payload byte. A claim the holder still holds from another entry, no longer valid, costs
    ///      about 30k more than an entry walked past, plus its own payload. Beyond the envelope the
    ///      probe fails closed, costing the liquidity flag only; `probeLpClaim` is public so the
    ///      cause stays diagnosable off-chain.
    ///
    ///      The envelope assumes each trusted issuer is registered with unique topics — T-REX's
    ///      `addTrustedIssuer` pushes the issuer once per topic entry without deduplicating, so a
    ///      duplicate takes an entry and its gas — and that every issuer is ONCHAINID 2.2.1's
    ///      `ClaimIssuer` deployed directly, not behind a proxy. A hostile entry costs up to about
    ///      86k on top of a walked one (49k if it only burns the validity read), additively,
    ///      duplicates included; the cap carries no headroom for one at the envelope's edge.
    ///
    ///      This bounds hostile behaviour, but it is not a bound on the cost of ordinary use, and it
    ///      is per call rather than per transaction. `IAllowlistChecker` carries no requested
    ///      permission — `PermissionsAdapter.isAllowed` receives one and masks only after the call
    ///      returns — so `beforeSwap` resolves the liquidity flag too and the hook discards it.
    ///      `PermissionedHooks._verifyAllowlist` asks once per permissioned pool currency, and a
    ///      pool may pair two; `PermissionedV4Router._pay` asks again when the currency being
    ///      settled is the adapter. Every ordinary swap therefore pays for the LP scan — twice per
    ///      permissioned pool on its route plus once more, three times for a single hop — and that
    ///      cost grows with the trusted-issuer count for a topic the swap decision does not use.
    uint256 private constant LP_PROBE_GAS = 400_000;

    /// @dev Gas the `isClaimValid` read may spend. ONCHAINID 2.2.1's `ClaimIssuer`, deployed
    ///      directly, answers in about 20.2k; the rest is headroom.
    uint256 private constant VALIDITY_READ_GAS = 40_000;

    /// @dev Gas each `isClaimRevoked` read may spend. ONCHAINID 2.2.1's `ClaimIssuer` answers in
    ///      2.0k to 4.0k — a byte-keyed mapping read. Fixed rather than a share of what is left, so a
    ///      read is funded the same however long the issuer list or large the claim: a read that
    ///      does not answer denies, so an honest one must never be starved.
    uint256 private constant REVOCATION_READ_GAS = 10_000;

    /// @dev secp256k1 group order, used to enumerate the s-complement encodings ONCHAINID accepts.
    uint256 private constant _SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice Thrown when the checker is deployed with an unset (zero) LP claim topic.
    error ZeroClaimTopic();

    /// @param lpClaimTopic The OnchainID claim topic required to be granted LIQUIDITY_ALLOWED.
    constructor(uint256 lpClaimTopic) {
        if (lpClaimTopic == 0) revert ZeroClaimTopic();
        LP_CLAIM_TOPIC = lpClaimTopic;
    }

    /// @inheritdoc BaseAllowlistChecker
    /// @param account The trader/LP whose permissions are being resolved.
    /// @param tokenAddress The ERC-3643 token exposing identityRegistry(); its registry is the trust root.
    /// @return The permission flags granted to `account` for the pool wrapping `tokenAddress`.
    /// @dev Never reverts. The swap decision reads the registry through length-validated staticcalls;
    ///      the LP decision runs in its own gas-bounded frame, so an LP-side failure costs the
    ///      liquidity flag and nothing else — the two flags are decided independently.
    function checkAllowlist(address account, address tokenAddress) public view override returns (PermissionFlag) {
        (bool registryOk, address idReg) = _staticAddress(tokenAddress, abi.encodeCall(ITREXToken.identityRegistry, ()));
        if (!registryOk || idReg == address(0)) return PermissionFlags.NONE;

        (bool verifiedOk, bool verified) =
            _staticBool(idReg, abi.encodeCall(ITREXIdentityRegistry.isVerified, (account)));
        if (!verifiedOk || !verified) return PermissionFlags.NONE;

        // ERC-3643's emergency controls live in the TOKEN, not the registry: isVerified stays true
        // through a global pause and through a freeze. The token's own transfer guards normally
        // backstop that, because the underlying moves whenever the adapter wraps on settle or
        // unwraps on take. They do not bind a route where the adapter is an INTERMEDIATE currency:
        // V4Router chains hops by assigning amountIn = amountOut, so the adapter's deltas cancel
        // inside the PoolManager, nothing is wrapped or unwrapped, and the token is never called.
        // Reading the controls here is what makes them bind pool trading on every route.
        (bool controlsOk, bool halted) = probeTokenControls(tokenAddress, account);
        if (!controlsOk || halted) return PermissionFlags.NONE;

        PermissionFlag flags = PermissionFlags.SWAP_ALLOWED;

        try this.probeLpClaim{gas: LP_PROBE_GAS}(idReg, account) returns (bool hasClaim) {
            if (hasClaim) flags = flags | PermissionFlags.LIQUIDITY_ALLOWED;
        } catch {
            // Any LP-path failure — revert, malformed return data, return bomb, out-of-gas — is
            // absorbed here rather than propagating into the hook callback.
        }

        return flags;
    }

    /// @notice Whether `tokenAddress` answers its ERC-3643 control surface, and whether that surface
    ///         currently denies `account` any pool permission.
    /// @param tokenAddress The ERC-3643 token whose pause and freeze state gate the pool.
    /// @param account The trader/LP whose immobilisation is being resolved.
    /// @return readable False when the token does not answer the IToken control surface at all.
    /// @return halted True when the token is paused, or the account frozen or fully immobilised.
    /// @dev Public and side-effect free, mirroring `probeLpClaim`: a denial stays diagnosable
    ///      off-chain, where an unreadable surface is otherwise indistinguishable from a genuine
    ///      halt. Fails closed — a getter that stops answering denies rather than defaulting to
    ///      unpaused and unfrozen, or the bypass returns whenever the dependency misbehaves.
    ///      No bounded frame is needed: `_staticWord` cannot revert, cannot decode and cannot be
    ///      return-bombed, and `identityRegistry()` is already read full-gas from this same address.
    function probeTokenControls(address tokenAddress, address account)
        public
        view
        returns (bool readable, bool halted)
    {
        (bool pausedOk, bool isPaused) = _staticBool(tokenAddress, abi.encodeCall(ITREXToken.paused, ()));
        if (!pausedOk) return (false, true);
        if (isPaused) return (true, true);

        (bool frozenOk, bool walletFrozen) = _staticBool(tokenAddress, abi.encodeCall(ITREXToken.isFrozen, (account)));
        if (!frozenOk) return (false, true);
        if (walletFrozen) return (true, true);

        // A partial freeze is NOT read here, at any size. `Token.transfer` applies
        // `_frozenTokens[from]` to the SENDER only, while `setAddressFrozen` is tested on `_to` as
        // well — so a fully immobilised holder can still receive on the token itself. A
        // PermissionFlag carries no direction, so denying on full immobilisation would refuse an
        // acquisition the asset permits. An agent wanting the account out of the venue entirely has
        // setAddressFrozen, which is honoured above.
        return (true, false);
    }

    /// @notice Whether `account` holds a valid LP_CLAIM_TOPIC claim under `identityRegistry`.
    /// @dev External so that `checkAllowlist` can invoke it as a gas-bounded self-staticcall: the
    ///      whole untrusted-dependency chain (OnchainID, TrustedIssuersRegistry, claim issuers) is
    ///      confined to a frame whose failure the caller can catch. Permissionless and side-effect
    ///      free — exposed for off-chain diagnosis of a denied liquidity flag.
    ///
    ///      Replicates ERC-3643 claim validation for LP_CLAIM_TOPIC: for each trusted issuer of the
    ///      topic, look up the canonical claim id, confirm the stored claim matches, and ask the
    ///      issuer whether it is still valid. Existence alone is never sufficient.
    ///
    ///      Each issuer is read through length-validated staticcalls carrying a fixed stipend, so
    ///      neither a malformed answer nor an exhausted stipend can cost the remaining trusted
    ///      issuers their turn, and what one issuer can take does not grow with the list or the
    ///      budget. An issuer that fails, answers malformedly or burns costs the scan that bounded
    ///      amount and the scan moves on. Only holders of a claim it attests pay it, and they lose
    ///      the flag only when that cost, added to the entries ahead, pushes a later issuer's valid
    ///      claim past the frame: the frame carries no headroom for hostile entries.
    function probeLpClaim(address identityRegistry, address account) external view returns (bool) {
        ITREXIdentityRegistry idReg = ITREXIdentityRegistry(identityRegistry);

        address id = idReg.identity(account);
        if (id == address(0)) return false;

        address issuersRegistry = idReg.issuersRegistry();
        if (issuersRegistry == address(0)) return false;

        address[] memory trustedIssuers =
            ITREXTrustedIssuersRegistry(issuersRegistry).getTrustedIssuersForClaimTopic(LP_CLAIM_TOPIC);

        uint256 issuerCount = trustedIssuers.length;
        for (uint256 i = 0; i < issuerCount; i++) {
            address trustedIssuer = trustedIssuers[i];
            bytes32 claimId = keccak256(abi.encode(trustedIssuer, LP_CLAIM_TOPIC));
            (uint256 topic,, address issuer, bytes memory sig, bytes memory data,) = ITREXIdentity(id).getClaim(claimId);

            // The tuple comes from the user's own OnchainID, so the claim body must name the very
            // issuer its id was derived from: the ISSUER BINDING is re-derived from the
            // TrustedIssuersRegistry, never from the identity's self-reported record. The code check
            // keeps a de-registered or not-yet-deployed issuer from answering as an empty-returndata
            // "yes".
            //
            // `sig` and `data` are NOT re-derived — they are whatever the untrusted OnchainID
            // returned, and ONCHAINID keys revocation on those exact bytes. An identity that answers
            // getClaim differently per caller therefore defeats ClaimIssuer::revokeClaim, which reads
            // the bytes to revoke from that same identity. Issuers must revoke with
            // revokeClaimBySignature against an archived blob and confirm with probeLpClaim; against
            // a non-canonical identity, revokeClaim is advisory.
            if (topic != LP_CLAIM_TOPIC || issuer != trustedIssuer || issuer.code.length == 0) continue;

            // Read the issuer's verdict the way the swap path reads the registry's: a length- and
            // shape-validated word. try/catch guards the call but NOT the ABI decode of its result,
            // which runs in this frame — so an issuer that SUCCEEDS with zero-length returndata, a
            // short word or a non-canonical bool would revert probeLpClaim uncaught and deny the
            // remaining trusted issuers their turn. An explicit returndatasize check has no decode
            // left to fail, so a malformed issuer now costs only its own claim.
            // Bound what this issuer may spend. Unbounded, EIP-150 hands it 63/64 of everything
            // left, and its out-of-gas — absorbed here — leaves the NEXT iteration's `getClaim` to
            // die on the surviving sixty-fourth. That one sits in no guarded frame, so it aborts
            // the whole scan and destroys a later honest issuer's independently valid claim.
            // A fixed stipend, not a share of what is left: a share shrinks as the list grows,
            // until it no longer covers an honest issuer near the head of a long list, and grows
            // with the budget, so a burning issuer takes more the more the caller supplies.
            (bool answered, bool valid) = _staticBool(
                issuer,
                abi.encodeCall(ITREXClaimIssuer.isClaimValid, (id, LP_CLAIM_TOPIC, sig, data)),
                VALIDITY_READ_GAS
            );
            if (!answered || !valid) continue;

            // The issuer vouched for the exact bytes the identity stored. That is not the question
            // that decides revocation: ONCHAINID keys revocation on those bytes, while its
            // getRecoveredAddress accepts four encodings of the same signature (a v below 27 is
            // normalised by adding 27, and s carries no low-half bound). Revoking one leaves the
            // other three answering "not revoked", and the holder re-installs the claim under a
            // re-encoding. Ask the issuer about the whole equivalence class instead.
            // Bounded for the same reason the validity read is: this path can `continue`, and a
            // gas-burning answer here would leave the next iteration's unguarded `getClaim` to die
            // on the remainder. A fixed stipend, not a share of what is left: the holder sets what
            // is left, since every byte of the unsigned `uri` is spent in `getClaim` first.
            if (_equivalentEncodingRevoked(issuer, sig, REVOCATION_READ_GAS)) {
                continue;
            }

            return true;
        }
        return false;
    }

    /// @dev True if the issuer has revoked ANY byte encoding of the ECDSA signature `sig` that its own
    ///      `getRecoveredAddress` would accept. A blob that is not a 65-byte ECDSA encoding is left
    ///      entirely to the issuer's semantics and is never denied here, so a trusted issuer using a
    ///      different signature scheme is unaffected.
    function _equivalentEncodingRevoked(address issuer, bytes memory sig, uint256 gasPerCandidate)
        private
        view
        returns (bool)
    {
        if (sig.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Mirror ONCHAINID's own normalisation, so the enumerated class is exactly the set it accepts.
        unchecked {
            if (v < 27) v += 27;
        }
        if (v != 27 && v != 28) return false;

        uint256 su = uint256(s);
        if (su == 0 || su >= _SECP256K1_N) return false;

        bytes32 sFlip = bytes32(_SECP256K1_N - su);
        uint8 vFlip = v == 27 ? 28 : 27;

        unchecked {
            if (_revoked(issuer, abi.encodePacked(r, s, v), gasPerCandidate)) return true;
            if (_revoked(issuer, abi.encodePacked(r, s, uint8(v - 27)), gasPerCandidate)) return true;
            if (_revoked(issuer, abi.encodePacked(r, sFlip, vFlip), gasPerCandidate)) return true;
            if (_revoked(issuer, abi.encodePacked(r, sFlip, uint8(vFlip - 27)), gasPerCandidate)) return true;
        }
        return false;
    }

    /// @dev A read that does not answer — the call fails, exceeds its stipend, answers unparseably,
    ///      or the issuer does not implement `isClaimRevoked` — counts as revoked. Read as "nothing
    ///      revoked", a read the holder can starve answers for the holder: padding the `uri` of a
    ///      re-encoded claim until the read of the revoked encoding runs dry granted it back. An
    ///      issuer that cannot answer within the stipend therefore cannot grant on a 65-byte ECDSA
    ///      claim; any other blob never reaches this read. Never reverts.
    function _revoked(address issuer, bytes memory candidate, uint256 gasLimit) private view returns (bool) {
        (bool ok, bool value) =
            _staticBool(issuer, abi.encodeCall(ITREXClaimIssuer.isClaimRevoked, (candidate)), gasLimit);
        return !ok || value;
    }

    /// @dev Staticcall reading exactly one word, with no path that can revert in this frame.
    ///      The output buffer is a fixed 32 bytes of scratch space, so oversized return data is never
    ///      copied (return-bomb proof), and the explicit `returndatasize` check replaces an ABI decode
    ///      — which Solidity's try/catch cannot guard, since it runs in the caller's own frame.
    ///      Gas is forwarded in full: `IdentityRegistry` may sit behind a deep proxy, and a stipend
    ///      tight enough to matter would break legitimate deployments. The full forward is also what
    ///      preserves the caller's ability to overprovision past a gas-burning issuer inside the
    ///      registry's own verification loop, whose next `getClaim` after a caught out-of-gas is
    ///      unguarded. A capped forward hands the callee the cap and never more, so a later valid
    ///      claim would become unreachable at any transaction gas limit — the denial would stop
    ///      being a toll and become a wall. See README, "Trust model".
    function _staticWord(address target, bytes memory callData) private view returns (bool ok, bytes32 word) {
        // type(uint256).max is the "forward everything" idiom: EIP-150 caps the callee at 63/64 of
        // what remains, exactly as `gas()` did.
        return _staticWord(target, callData, type(uint256).max);
    }

    /// @dev As `_staticWord`, capping what the callee may spend. A stipend the callee exceeds costs
    ///      only `ok == false` — the out-of-gas dies in the callee's frame, never in this one.
    function _staticWord(address target, bytes memory callData, uint256 gasLimit)
        private
        view
        returns (bool ok, bytes32 word)
    {
        if (target.code.length == 0) return (false, bytes32(0));

        assembly ("memory-safe") {
            let success := staticcall(gasLimit, target, add(callData, 0x20), mload(callData), 0x00, 0x20)
            if and(success, eq(returndatasize(), 0x20)) {
                ok := 1
                word := mload(0x00)
            }
        }
    }

    /// @dev As `_staticWord`, rejecting a word whose high 96 bits are dirty (not a clean address).
    function _staticAddress(address target, bytes memory callData) private view returns (bool ok, address value) {
        bytes32 word;
        (ok, word) = _staticWord(target, callData);
        if (!ok || uint256(word) > type(uint160).max) return (false, address(0));
        value = address(uint160(uint256(word)));
    }

    /// @dev As `_staticWord`, rejecting a word that is not a canonical boolean.
    function _staticBool(address target, bytes memory callData) private view returns (bool ok, bool value) {
        return _staticBool(target, callData, type(uint256).max);
    }

    /// @dev As `_staticBool`, capping what the callee may spend.
    function _staticBool(address target, bytes memory callData, uint256 gasLimit)
        private
        view
        returns (bool ok, bool value)
    {
        bytes32 word;
        (ok, word) = _staticWord(target, callData, gasLimit);
        if (!ok || uint256(word) > 1) return (false, false);
        value = uint256(word) == 1;
    }
}
