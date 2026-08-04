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
}

/// @title TREXAllowlistChecker
/// @notice Maps ERC-3643 (T-REX) verification + a valid LP claim topic to a v4 PermissionFlag
///         for use with a PermissionsAdapter.
/// @dev    - isVerified() => SWAP_ALLOWED (registry enforces all required topics + claim validity).
///         - isVerified() && a VALID claim of `LP_CLAIM_TOPIC` from a trusted issuer => + LIQUIDITY_ALLOWED.
///         LP validation mirrors ERC-3643 IdentityRegistry.isVerified: it does not trust mere claim
///         existence — the claim must come from a trusted issuer and pass isClaimValid (not revoked).
///
///         `checkAllowlist` is a TOTAL function: it runs inside the PoolManager's beforeSwap /
///         beforeAddLiquidity callback, where a revert does not deny the caller — it bricks the pool
///         for everyone. Every failure mode of the T-REX chain (revert, missing contract, malformed
///         return data, return bomb, gas bomb) therefore degrades to a strictly lower-or-equal
///         permission instead of propagating.
contract TREXAllowlistChecker is BaseAllowlistChecker {
    /// @notice The OnchainID claim topic that gates liquidity provision.
    uint256 public immutable LP_CLAIM_TOPIC;

    /// @dev Gas handed to the isolated LP probe. Sized well above a realistic deployment (a claim
    ///      lookup plus an ecrecover-backed isClaimValid runs ≈15k per trusted issuer, and issuer sets
    ///      are typically 1–3) while capping what a hostile identity or issuer can burn on the swap
    ///      hot path. Exceeding it costs the liquidity flag only; `probeLpClaim` is public so the
    ///      cause stays diagnosable off-chain.
    uint256 private constant LP_PROBE_GAS = 200_000;

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

        PermissionFlag flags = PermissionFlags.SWAP_ALLOWED;

        try this.probeLpClaim{gas: LP_PROBE_GAS}(idReg, account) returns (bool hasClaim) {
            if (hasClaim) flags = flags | PermissionFlags.LIQUIDITY_ALLOWED;
        } catch {
            // Any LP-path failure — revert, malformed return data, return bomb, out-of-gas — is
            // absorbed here rather than propagating into the hook callback.
        }

        return flags;
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
    function probeLpClaim(address identityRegistry, address account) external view returns (bool) {
        ITREXIdentityRegistry idReg = ITREXIdentityRegistry(identityRegistry);

        address id = idReg.identity(account);
        if (id == address(0)) return false;

        address issuersRegistry = idReg.issuersRegistry();
        if (issuersRegistry == address(0)) return false;

        address[] memory trustedIssuers =
            ITREXTrustedIssuersRegistry(issuersRegistry).getTrustedIssuersForClaimTopic(LP_CLAIM_TOPIC);

        for (uint256 i = 0; i < trustedIssuers.length; i++) {
            address trustedIssuer = trustedIssuers[i];
            bytes32 claimId = keccak256(abi.encode(trustedIssuer, LP_CLAIM_TOPIC));
            (uint256 topic,, address issuer, bytes memory sig, bytes memory data,) = ITREXIdentity(id).getClaim(claimId);

            // The tuple comes from the user's own OnchainID, so the claim body must name the very
            // issuer its id was derived from — validity is re-derived from the TrustedIssuersRegistry,
            // never from the identity's self-reported record. The code check keeps a de-registered or
            // not-yet-deployed issuer from answering as an empty-returndata "yes".
            if (topic != LP_CLAIM_TOPIC || issuer != trustedIssuer || issuer.code.length == 0) continue;

            try ITREXClaimIssuer(issuer).isClaimValid(id, LP_CLAIM_TOPIC, sig, data) returns (bool valid) {
                if (valid) return true;
            } catch {
                // A broken or hostile issuer must not deny the remaining trusted issuers their turn.
            }
        }
        return false;
    }

    /// @dev Staticcall reading exactly one word, with no path that can revert in this frame.
    ///      The output buffer is a fixed 32 bytes of scratch space, so oversized return data is never
    ///      copied (return-bomb proof), and the explicit `returndatasize` check replaces an ABI decode
    ///      — which Solidity's try/catch cannot guard, since it runs in the caller's own frame.
    ///      Gas is forwarded in full: `IdentityRegistry` may sit behind a deep proxy, and a stipend
    ///      tight enough to matter would break legitimate deployments.
    function _staticWord(address target, bytes memory callData) private view returns (bool ok, bytes32 word) {
        if (target.code.length == 0) return (false, bytes32(0));

        assembly ("memory-safe") {
            let success := staticcall(gas(), target, add(callData, 0x20), mload(callData), 0x00, 0x20)
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
        bytes32 word;
        (ok, word) = _staticWord(target, callData);
        if (!ok || uint256(word) > 1) return (false, false);
        value = uint256(word) == 1;
    }
}
