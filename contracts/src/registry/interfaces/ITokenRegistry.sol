// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {IERC1155Singleton} from "../../erc1155/interfaces/IERC1155Singleton.sol";

import {IRegistry} from "./IRegistry.sol";

/// @notice Interface for a tokenized registry.
interface ITokenRegistry is IRegistry, IERC1155Singleton {
    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    event LabelRevealed(uint256 indexed tokenId, string label);

    /// @notice Expiry was changed.
    event ExpiryUpdated(uint256 indexed tokenId, uint64 newExpiry, address indexed by);

    /// @notice Subregistry was changed.
    event SubregistryUpdated(uint256 indexed tokenId, IRegistry subregistry, address indexed by);

    /// @notice Resolver was changed.
    event ResolverUpdated(uint256 indexed tokenId, address resolver, address indexed by);

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Error emitted when a name is already registered.
     */
    error NameNotAvailable(string label);

    /**
     * @dev Error emitted when a name has expired.
     */
    error NameExpired(uint256 tokenId);

    /**
     * @dev Error emitted when a name cannot be reduced in expiration.
     */
    error CannotReduceExpiration(uint64 oldExpiration, uint64 newExpiration);

    /**
     * @dev Error emitted when a name cannot be set to a past expiration.
     */
    error CannotSetPastExpiration(uint64 expiry);

    /**
     * @dev Error emitted when a transfer is not allowed due to missing transfer admin role.
     */
    error TransferDisallowed(uint256 tokenId, address from);

    ////////////////////////////////////////////////////////////////////////
    // Functions
    ////////////////////////////////////////////////////////////////////////

    /// @notice Registers a new name.
    /// @param label The label to register.
    /// @param owner The address of the owner of the name.
    /// @param registry The registry to set as the name.
    /// @param resolver The resolver to set for the name.
    /// @param roleBitmap The role bitmap to set for the name.
    /// @param expires The expiration date of the name.
    function register(
        string calldata label,
        address owner,
        IRegistry registry,
        address resolver,
        uint256 roleBitmap,
        uint64 expires
    ) external returns (uint256 tokenId);

    /// @notice Renew a subdomain.
    /// @param anyId The labelhash, token ID, or resource.
    /// @param newExpiry The new expiration.
    function renew(uint256 anyId, uint64 newExpiry) external;

    /// @notice Delete a subdomain.
    /// @param anyId The labelhash, token ID, or resource.
    /// @param release If true, the subdomain should be available for registration.
    function unregister(uint256 anyId, bool release) external;

    /// @notice Change the registry of a subdomain.
    /// @param anyId The labelhash, token ID, or resource.
    /// @param registry The new registry.
    function setSubregistry(uint256 anyId, IRegistry registry) external;

    /// @notice Change the resolver of a subdomain.
    /// @param anyId The labelhash, token ID, or resource.
    /// @param resolver The new resolver.
    function setResolver(uint256 anyId, address resolver) external;

    //function isAvailable(string calldata label) external view returns (bool);

    // function getChild(
    //     uint256 anyId
    // ) external view returns (IRegistry subregistry, address resolver);

    /// @notice Get expiry of a subdomain.
    /// @param anyId The labelhash, token ID, or resource.
    /// @return The expiry for name.
    function getExpiry(uint256 anyId) external view returns (uint64);

    function findTokenId(string calldata label) external view returns (uint256 tokenId);

    /// @notice Get the latest owner of a token.
    /// @param tokenId The token ID to query.
    /// @return The latest owner address.
    function latestOwnerOf(uint256 tokenId) external view returns (address);
}
