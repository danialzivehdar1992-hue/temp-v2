// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// solhint-disable no-console, private-vars-leading-underscore, state-visibility, func-name-mixedcase, namechain/ordering, one-contract-per-file

import {
    PermissionedRegistry,
    IRegistryMetadata,
    IHCAFactoryBasic
} from "~src/registry/PermissionedRegistry.sol";

/**
 * @title MockPermissionedRegistry
 * @dev Test contract that extends PermissionedRegistry to expose internal methods
 *      for testing purposes. This allows tests to access getResourceFromTokenId and
 *      getTokenIdFromResource without them being part of the main interface.
 */
contract MockPermissionedRegistry is PermissionedRegistry {
    // Pass through all constructor arguments
    constructor(
        IHCAFactoryBasic hcaFactory,
        IRegistryMetadata metadata,
        address ownerAddress,
        uint256 ownerRoles
    ) PermissionedRegistry(hcaFactory, metadata, ownerAddress, ownerRoles) {}

    // /**
    //  * @dev Test helper that bypasses admin role restrictions - for testing only
    //  */
    // function grantRolesDirect(
    //     uint256 resource,
    //     uint256 roleBitmap,
    //     address account
    // ) external returns (bool) {
    //     return _grantRoles(resource, roleBitmap, account, false);
    // }

    // /**
    //  * @dev Test helper that bypasses admin role restrictions - for testing only
    //  */
    // function revokeRolesDirect(
    //     uint256 resource,
    //     uint256 roleBitmap,
    //     address account
    // ) external returns (bool) {
    //     return _revokeRoles(resource, roleBitmap, account, false);
    // }

    function getEacVersionId(uint256 anyId) external view returns (uint32) {
        return _entry(anyId).eacVersionId;
    }

    function getTokenVersionId(uint256 anyId) external view returns (uint32) {
        return _entry(anyId).tokenVersionId;
    }
}
