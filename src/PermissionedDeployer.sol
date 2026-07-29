// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Trivial re-export shim to force compilation of upstream PermissionedPools contracts
///         from the lib/v4-periphery PR branch, so that ABIs and bytecode end up in `out/`
///         where the deployer/ SPA can consume them.
import {PermissionsAdapter} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapter.sol";
import {
    PermissionsAdapterFactory
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionsAdapterFactory.sol";
import {PermissionedHooks} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedHooks.sol";
import {
    PermissionedPositionManager
} from "@uniswap/v4-periphery/src/hooks/permissionedPools/PermissionedPositionManager.sol";
