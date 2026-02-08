// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {IEnhancedAccessControl} from "../../access-control/interfaces/IEnhancedAccessControl.sol";

import {ITokenRegistry, IRegistry} from "./ITokenRegistry.sol";

interface IPermissionedRegistry is ITokenRegistry, IEnhancedAccessControl {
    ////////////////////////////////////////////////////////////////////////
    // Types
    ////////////////////////////////////////////////////////////////////////
    struct State {
        bool available;
        uint64 expiry;
        address owner;
        uint256 tokenId;
        uint256 resource;
    }

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    /// @notice Token was regenerated with a new token ID.
    /// @dev Occurs when roles are granted or revoked to maintain ERC1155 compliance.
    event TokenRegenerated(
        uint256 indexed oldTokenId,
        uint256 indexed newTokenId,
        uint256 resource
    );

    ////////////////////////////////////////////////////////////////////////
    // Functions
    ////////////////////////////////////////////////////////////////////////

    /// @notice Prevent subdomain registration until expiry or registrant has `ROLE_RESERVE`.
    /// @param label The subdomain to reserve.
    /// @param expiry The time when the subdomain can be registered again.
    function reserve(string calldata label, uint64 expiry) external;

    /// @notice Get subdomain `State` from `anyId`.
    /// @param anyId The labelhash, token ID, or resource.
    /// @return The datastore entry.
    function getState(uint256 anyId) external view returns (State memory);

    /// @notice Get `resource` from `anyId`.
    /// @param anyId The labelhash, token ID, or resource.
    /// @return The resource.
    function getResource(uint256 anyId) external view returns (uint256);

    /// @notice Get `tokenId` from `anyId`.
    /// @param anyId The labelhash, token ID, or resource.
    /// @return The token ID.
    function getTokenId(uint256 anyId) external view returns (uint256);
}
