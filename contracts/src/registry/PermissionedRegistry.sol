// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {EnhancedAccessControl} from "../access-control/EnhancedAccessControl.sol";
import {IEnhancedAccessControl} from "../access-control/interfaces/IEnhancedAccessControl.sol";
import {EACBaseRolesLib} from "../access-control/libraries/EACBaseRolesLib.sol";
import {ERC1155Singleton} from "../erc1155/ERC1155Singleton.sol";
import {IERC1155Singleton} from "../erc1155/interfaces/IERC1155Singleton.sol";
import {HCAEquivalence} from "../hca/HCAEquivalence.sol";
import {IHCAFactoryBasic} from "../hca/interfaces/IHCAFactoryBasic.sol";

import {BaseRegistry} from "./BaseRegistry.sol";
import {
    IPermissionedRegistry,
    ITokenRegistry,
    IRegistry
} from "./interfaces/IPermissionedRegistry.sol";
import {IRegistryMetadata} from "./interfaces/IRegistryMetadata.sol";
import {RegistryRolesLib} from "./libraries/RegistryRolesLib.sol";
import {MetadataMixin} from "./MetadataMixin.sol";

contract PermissionedRegistry is
    BaseRegistry,
    EnhancedAccessControl,
    IPermissionedRegistry,
    MetadataMixin
{
    ////////////////////////////////////////////////////////////////////////
    // Types
    ////////////////////////////////////////////////////////////////////////

    struct Entry {
        uint32 eacVersionId;
        uint32 tokenVersionId;
        IRegistry subregistry;
        uint64 expiry;
        address resolver;
    }

    ////////////////////////////////////////////////////////////////////////
    // Storage
    ////////////////////////////////////////////////////////////////////////

    mapping(uint256 canonicalId => Entry entry) internal _entries;
    IRegistry internal _parent;
    string internal _childLabel;

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    constructor(
        IHCAFactoryBasic hcaFactory,
        IRegistryMetadata metadata,
        address ownerAddress,
        uint256 ownerRoles
    ) HCAEquivalence(hcaFactory) MetadataMixin(metadata) {
        _grantRoles(ROOT_RESOURCE, ownerRoles, ownerAddress, false);
    }

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(IERC165, BaseRegistry, EnhancedAccessControl) returns (bool) {
        return
            interfaceId == type(IPermissionedRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    ////////////////////////////////////////////////////////////////////////
    // Implementation
    ////////////////////////////////////////////////////////////////////////

    /// @inheritdoc IPermissionedRegistry
    function reserve(
        string calldata label,
        uint64 until
    ) external onlyRootRoles(RegistryRolesLib.ROLE_RESERVE) {
        NameCoder.assertLabelSize(label);
        if (_isExpired(until)) {
            revert CannotSetPastExpiration(until);
        }
        NameCoder.assertLabelSize(label);
        uint256 tokenId = _labelhash(label);
        emit LabelRevealed(tokenId, label);
        Entry storage entry = _entry(tokenId);
        tokenId = _constructTokenId(tokenId, entry);
        address prevOwner = super.ownerOf(tokenId);
        if (prevOwner != address(0)) {
            if (_isExpired(entry.expiry)) {
                tokenId = _destroy(prevOwner, tokenId, entry);
            } else {
                revert NameNotAvailable(label);
            }
        }
        entry.expiry = until;
        emit ExpiryUpdated(tokenId, until, _msgSender());
    }

    /// @inheritdoc ITokenRegistry
    function unregister(uint256 anyId, bool release) external override {
        (uint256 tokenId, Entry storage entry) = _checkExpiryAndTokenRoles(
            anyId,
            RegistryRolesLib.ROLE_UNREGISTER
        );
        if (release) {
            uint64 expiry = uint64(block.timestamp);
            entry.expiry = expiry;
            emit ExpiryUpdated(tokenId, expiry, _msgSender());
        }
        _destroy(super.ownerOf(tokenId), tokenId, entry);
    }

    function setSubregistry(uint256 anyId, IRegistry registry) external override {
        (uint256 tokenId, Entry storage entry) = _checkExpiryAndTokenRoles(
            anyId,
            RegistryRolesLib.ROLE_SET_SUBREGISTRY
        );
        entry.subregistry = registry;
        emit SubregistryUpdated(tokenId, registry, _msgSender());
    }

    function setResolver(uint256 anyId, address resolver) external override {
        (uint256 tokenId, Entry storage entry) = _checkExpiryAndTokenRoles(
            anyId,
            RegistryRolesLib.ROLE_SET_RESOLVER
        );
        entry.resolver = resolver;
        emit ResolverUpdated(tokenId, resolver, _msgSender());
    }

    function setParent(
        IRegistry parent,
        string memory label
    ) external onlyRootRoles(RegistryRolesLib.ROLE_SET_PARENT) {
        _parent = parent;
        _childLabel = label;
        emit ParentChanged(parent, label);
    }

    /// @inheritdoc ITokenRegistry
    function register(
        string calldata label,
        address owner,
        IRegistry registry,
        address resolver,
        uint256 roleBitmap,
        uint64 expires
    )
        public
        virtual
        override
        onlyRootRoles(RegistryRolesLib.ROLE_REGISTRAR)
        returns (uint256 tokenId)
    {
        return _register(label, owner, registry, resolver, roleBitmap, expires);
    }

    /// @inheritdoc ITokenRegistry
    function renew(uint256 anyId, uint64 newExpiry) public override {
        (uint256 tokenId, Entry storage entry) = _checkExpiryAndTokenRoles(
            anyId,
            RegistryRolesLib.ROLE_RENEW
        );
        if (newExpiry < entry.expiry) {
            revert CannotReduceExpiration(entry.expiry, newExpiry);
        }
        entry.expiry = newExpiry;
        emit ExpiryUpdated(tokenId, newExpiry, _msgSender());
    }

    /// @inheritdoc IEnhancedAccessControl
    function grantRoles(
        uint256 anyId,
        uint256 roleBitmap,
        address account
    ) public override(EnhancedAccessControl, IEnhancedAccessControl) returns (bool) {
        return super.grantRoles(getResource(anyId), roleBitmap, account);
    }

    /// @inheritdoc IEnhancedAccessControl
    function revokeRoles(
        uint256 anyId,
        uint256 roleBitmap,
        address account
    ) public override(EnhancedAccessControl, IEnhancedAccessControl) returns (bool) {
        return super.revokeRoles(getResource(anyId), roleBitmap, account);
    }

    /// @inheritdoc ITokenRegistry
    function getExpiry(uint256 anyId) external view returns (uint64) {
        return _entry(anyId).expiry;
    }

    /// @inheritdoc ITokenRegistry
    function findTokenId(string calldata label) external view returns (uint256) {
        uint256 anyId = _labelhash(label);
        return _constructTokenId(anyId, _entry(anyId));
    }

    /// @inheritdoc ERC1155Singleton
    function uri(uint256 tokenId) public view override returns (string memory) {
        return _tokenURI(tokenId);
    }

    /// @inheritdoc IRegistry
    function findChild(
        string memory label
    ) public view virtual returns (IRegistry subregistry, address resolver) {
        Entry storage entry = _entry(_labelhash(label));
        if (!_isExpired(entry.expiry)) {
            resolver = entry.resolver;
            subregistry = entry.subregistry;
        }
    }

    /// @inheritdoc IRegistry
    function getParent() external view returns (IRegistry parent, string memory label) {
        return (_parent, _childLabel);
    }

    /// @inheritdoc ITokenRegistry
    function latestOwnerOf(uint256 tokenId) public view virtual returns (address) {
        return super.ownerOf(tokenId);
    }

    /// @inheritdoc IPermissionedRegistry
    function getTokenId(uint256 anyId) external view returns (uint256) {
        return _constructTokenId(anyId, _entry(anyId));
    }

    /// @inheritdoc IPermissionedRegistry
    function getResource(uint256 anyId) public view returns (uint256) {
        return _constructResource(anyId, _entry(anyId));
    }

    /// @inheritdoc IERC1155Singleton
    function ownerOf(
        uint256 tokenId
    ) public view virtual override(ERC1155Singleton, IERC1155Singleton) returns (address) {
        Entry storage entry = _entry(tokenId);
        return
            tokenId != _constructTokenId(tokenId, entry) || _isExpired(entry.expiry)
                ? address(0)
                : super.ownerOf(tokenId);
    }

    /// @inheritdoc IPermissionedRegistry
    function getState(uint256 anyId) external view returns (State memory state) {
        Entry storage entry = _entry(anyId);
        uint256 tokenId = _constructTokenId(anyId, entry);
        state.tokenId = tokenId;
        state.resource = _constructResource(anyId, entry);
        uint64 expiry = entry.expiry;
        state.available = _isExpired(expiry);
        state.expiry = expiry;
        state.owner = super.ownerOf(tokenId);
    }

    // Enhanced access control methods adapted for token-based resources

    function roles(
        uint256 anyId,
        address account
    ) public view override(EnhancedAccessControl, IEnhancedAccessControl) returns (uint256) {
        return super.roles(getResource(anyId), account);
    }

    function roleCount(
        uint256 anyId
    ) public view override(EnhancedAccessControl, IEnhancedAccessControl) returns (uint256) {
        return super.roleCount(getResource(anyId));
    }

    function hasRoles(
        uint256 anyId,
        uint256 rolesBitmap,
        address account
    ) public view override(EnhancedAccessControl, IEnhancedAccessControl) returns (bool) {
        return super.hasRoles(getResource(anyId), rolesBitmap, account);
    }

    function hasAssignees(
        uint256 anyId,
        uint256 roleBitmap
    ) public view override(EnhancedAccessControl, IEnhancedAccessControl) returns (bool) {
        return super.hasAssignees(getResource(anyId), roleBitmap);
    }

    function getAssigneeCount(
        uint256 anyId,
        uint256 roleBitmap
    )
        public
        view
        override(EnhancedAccessControl, IEnhancedAccessControl)
        returns (uint256 counts, uint256 mask)
    {
        return super.getAssigneeCount(getResource(anyId), roleBitmap);
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal Functions
    ////////////////////////////////////////////////////////////////////////

    /**
     * @dev Internal register method that takes string memory and performs the actual registration logic.
     * @param label The label to register.
     * @param owner The owner of the registered name.
     * @param subregistry The registry to use for the name.
     * @param resolver The resolver to set for the name.
     * @param roleBitmap The roles to grant to the owner.
     * @param expires The expiration time of the name.
     * @return tokenId The token ID of the registered name.
     */
    function _register(
        string memory label,
        address owner,
        IRegistry subregistry,
        address resolver,
        uint256 roleBitmap,
        uint64 expires
    ) internal virtual returns (uint256 tokenId) {
        if (_isExpired(expires)) {
            revert CannotSetPastExpiration(expires);
        }
        NameCoder.assertLabelSize(label);
        tokenId = _labelhash(label);
        emit LabelRevealed(tokenId, label);
        Entry storage entry = _entry(tokenId);
        tokenId = _constructTokenId(tokenId, entry);
        address sender = _msgSender();
        address prevOwner = super.ownerOf(tokenId);
        if (_isExpired(entry.expiry)) {
            if (prevOwner != address(0)) {
                tokenId = _destroy(prevOwner, tokenId, entry);
            }
        } else if (
            prevOwner != address(0) || !hasRootRoles(RegistryRolesLib.ROLE_RESERVE, sender)
        ) {
            revert NameNotAvailable(label);
        }
        entry.expiry = expires;
        entry.subregistry = subregistry;
        entry.resolver = resolver;

        // emit NameRegistered before mint so we can determine this is a registry (in an indexer)
        //emit NameRegistered(tokenId, label, expires, sender);

        _mint(owner, tokenId, 1, "");
        _grantRoles(_constructResource(tokenId, entry), roleBitmap, owner, false);

        emit ExpiryUpdated(tokenId, expires, sender);
        emit SubregistryUpdated(tokenId, subregistry, sender);
        emit ResolverUpdated(tokenId, resolver, sender);
    }

    function _destroy(
        address owner,
        uint256 tokenId,
        Entry storage entry
    ) internal returns (uint256) {
        if (entry.resolver != address(0)) {
            delete entry.resolver;
            emit ResolverUpdated(tokenId, address(0), _msgSender());
        }
        if (address(entry.subregistry) != address(0)) {
            delete entry.subregistry;
            emit SubregistryUpdated(tokenId, IRegistry(address(0)), _msgSender());
        }
        _burn(owner, tokenId, 1);
        ++entry.eacVersionId;
        ++entry.tokenVersionId;
        return _constructTokenId(tokenId, entry);
    }

    /**
     * @dev Override the base registry _update function to transfer the roles to the new owner when the token is transferred.
     */
    function _update(
        address from,
        address to,
        uint256[] memory tokenIds,
        uint256[] memory values
    ) internal virtual override {
        bool externalTransfer = to != address(0) && from != address(0);
        if (externalTransfer) {
            // Check ROLE_CAN_TRANSFER for actual transfers only
            // Skip check for mints (from == address(0)) and burns (to == address(0))
            for (uint256 i; i < tokenIds.length; ++i) {
                if (!hasRoles(tokenIds[i], RegistryRolesLib.ROLE_CAN_TRANSFER_ADMIN, from)) {
                    revert TransferDisallowed(tokenIds[i], from);
                }
            }
        }
        super._update(from, to, tokenIds, values);
        if (externalTransfer) {
            for (uint256 i; i < tokenIds.length; ++i) {
                _transferRoles(getResource(tokenIds[i]), from, to, false);
            }
        }
    }

    /**
     * @dev Override the base registry _onRolesGranted function to regenerate the token when the roles are granted.
     */
    function _onRolesGranted(
        uint256 resource,
        address /*account*/,
        uint256 /*oldRoles*/,
        uint256 /*newRoles*/,
        uint256 /*roleBitmap*/
    ) internal virtual override {
        _regenerateToken(resource);
    }

    /**
     * @dev Override the base registry _onRolesRevoked function to regenerate the token when the roles are revoked.
     */
    function _onRolesRevoked(
        uint256 resource,
        address /*account*/,
        uint256 /*oldRoles*/,
        uint256 /*newRoles*/,
        uint256 /*roleBitmap*/
    ) internal virtual override {
        _regenerateToken(resource);
    }

    /// @dev Bump `tokenVersionId` via burn+mint if token is not expired.
    function _regenerateToken(uint256 anyId) internal {
        Entry storage entry = _entry(anyId);
        if (!_isExpired(entry.expiry)) {
            uint256 tokenId = _constructTokenId(anyId, entry);
            address owner = super.ownerOf(tokenId); // skip expiry check
            if (owner != address(0)) {
                _burn(owner, tokenId, 1);
                ++entry.tokenVersionId;
                uint256 newTokenId = _constructTokenId(tokenId, entry);
                _mint(owner, newTokenId, 1, "");
                emit TokenRegenerated(tokenId, newTokenId, _constructResource(tokenId, entry));
            }
        }
    }

    function _entry(uint256 anyId) internal view returns (Entry storage) {
        return _entries[_entryId(anyId)];
    }

    /**
     * @dev Override to prevent admin roles from being granted in the registry.
     *
     * In the registry context, admin roles are only assigned during name registration
     * to maintain controlled permission management. This ensures that role delegation
     * follows the intended security model where admin privileges are granted at
     * registration time and cannot be arbitrarily granted afterward.
     *
     * @param resource The resource to get settable roles for.
     * @param account The account to get settable roles for.
     * @return The settable roles (regular roles only, not admin roles).
     */
    function _getSettableRoles(
        uint256 resource,
        address account
    ) internal view virtual override returns (uint256) {
        return (super.roles(resource, account) | super.roles(ROOT_RESOURCE, account)) >> 128;
    }

    /// @dev Assert token is not expired and caller has necessary roles.
    function _checkExpiryAndTokenRoles(
        uint256 anyId,
        uint256 roleBitmap
    ) internal view returns (uint256 tokenId, Entry storage entry) {
        entry = _entry(anyId);
        tokenId = _constructTokenId(anyId, entry);
        if (_isExpired(entry.expiry)) {
            revert NameExpired(tokenId);
        }
        _checkRoles(_constructResource(anyId, entry), roleBitmap, _msgSender());
    }

    /// @dev Internal logic for expired status.
    ///      Only use of `block.timestamp`.
    function _isExpired(uint64 expiry) internal view returns (bool) {
        return block.timestamp >= expiry;
    }

    /// @dev Create `resource` from parts.
    ///      Returns next resource if token is expired.
    function _constructResource(
        uint256 anyId,
        Entry storage entry
    ) internal view returns (uint256) {
        return
            _entryId(anyId) |
            (_isExpired(entry.expiry) ? entry.eacVersionId + 1 : entry.eacVersionId);
    }

    /// @dev Create `tokenId` from parts.
    function _constructTokenId(uint256 anyId, Entry storage entry) internal view returns (uint256) {
        return _entryId(anyId) | entry.tokenVersionId;
    }

    /// @dev Convert `anyId` to `entryId`.
    function _entryId(uint256 anyId) internal pure returns (uint256) {
        return anyId ^ uint32(anyId);
    }

    /// @dev Convert `label` to `anyId`.
    function _labelhash(string memory label) internal pure returns (uint256) {
        return uint256(keccak256(bytes(label)));
    }
}
