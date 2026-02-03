// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {IPermissionedRegistry} from "./IPermissionedRegistry.sol";

/// @dev Size of `abi.encode(Data({...}))`.
uint256 constant DATA_SIZE = 5 * 32;

/// @dev Interface for a registry that manages a locked NameWrapper name.
interface IWrapperRegistry is IPermissionedRegistry {
    ////////////////////////////////////////////////////////////////////////
    // Types
    ////////////////////////////////////////////////////////////////////////

    /// @dev Typed arguments for `initialize()`.
    struct ConstructorArgs {
        bytes32 node;
        address owner;
        uint256 ownerRoles;
        address registrar;
    }

    struct Data {
        bytes32 node;
        address owner;
        address resolver;
        address registrar;
        uint256 salt;
    }

    ////////////////////////////////////////////////////////////////////////
    // Functions
    ////////////////////////////////////////////////////////////////////////

    function initialize(ConstructorArgs calldata args) external;

    function parentName() external view returns (bytes memory);
}
