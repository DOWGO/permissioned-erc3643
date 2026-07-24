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
contract TREXAllowlistChecker is BaseAllowlistChecker {
    /// @notice The OnchainID claim topic that gates liquidity provision.
    uint256 public immutable LP_CLAIM_TOPIC;

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
    /// @dev View-only; all external calls target the token's own (registry-governed) contracts, and the
    ///      LP path bounds work to the trusted-issuer set and tolerates a hostile issuer via try/catch.
    function checkAllowlist(address account, address tokenAddress) public view override returns (PermissionFlag) {
        ITREXIdentityRegistry idReg = ITREXIdentityRegistry(ITREXToken(tokenAddress).identityRegistry());
        if (!idReg.isVerified(account)) return PermissionFlags.NONE;

        PermissionFlag flags = PermissionFlags.SWAP_ALLOWED;

        if (_hasValidLpClaim(idReg, account)) {
            flags = flags | PermissionFlags.LIQUIDITY_ALLOWED;
        }
        return flags;
    }

    /// @dev Replicates ERC-3643 claim validation for LP_CLAIM_TOPIC: for each trusted issuer of the
    ///      topic, look up the canonical claim id, confirm the stored claim matches the topic, and ask
    ///      the issuer whether it is still valid. Existence alone is never sufficient.
    function _hasValidLpClaim(ITREXIdentityRegistry idReg, address account) private view returns (bool) {
        address id = idReg.identity(account);
        if (id == address(0)) return false;

        address issuersRegistry = idReg.issuersRegistry();
        if (issuersRegistry == address(0)) return false;

        address[] memory trustedIssuers =
            ITREXTrustedIssuersRegistry(issuersRegistry).getTrustedIssuersForClaimTopic(LP_CLAIM_TOPIC);

        for (uint256 i = 0; i < trustedIssuers.length; i++) {
            bytes32 claimId = keccak256(abi.encode(trustedIssuers[i], LP_CLAIM_TOPIC));
            (uint256 topic,, address issuer, bytes memory sig, bytes memory data,) = ITREXIdentity(id).getClaim(claimId);
            if (topic != LP_CLAIM_TOPIC) continue;

            try ITREXClaimIssuer(issuer).isClaimValid(id, LP_CLAIM_TOPIC, sig, data) returns (bool valid) {
                if (valid) return true;
            } catch {
                // A broken or hostile issuer must not brick the checker; treat as no valid claim.
            }
        }
        return false;
    }
}
