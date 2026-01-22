// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/console.sol";

import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IABIResolver} from "@ens/contracts/resolvers/profiles/IABIResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IContentHashResolver} from "@ens/contracts/resolvers/profiles/IContentHashResolver.sol";
import {IExtendedResolver} from "@ens/contracts/resolvers/profiles/IExtendedResolver.sol";
import {IHasAddressResolver} from "@ens/contracts/resolvers/profiles/IHasAddressResolver.sol";
import {IInterfaceResolver} from "@ens/contracts/resolvers/profiles/IInterfaceResolver.sol";
import {INameResolver} from "@ens/contracts/resolvers/profiles/INameResolver.sol";
import {IPubkeyResolver} from "@ens/contracts/resolvers/profiles/IPubkeyResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";
import {ENSIP19, COIN_TYPE_ETH, COIN_TYPE_DEFAULT} from "@ens/contracts/utils/ENSIP19.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ContextUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {EnhancedAccessControl} from "../access-control/EnhancedAccessControl.sol";
import {InvalidOwner} from "../CommonErrors.sol";
import {HCAContext} from "../hca/HCAContext.sol";
import {HCAContextUpgradeable} from "../hca/HCAContextUpgradeable.sol";
import {HCAEquivalence} from "../hca/HCAEquivalence.sol";
import {IHCAFactoryBasic} from "../hca/interfaces/IHCAFactoryBasic.sol";

import {OwnedResolverLib} from "./libraries/OwnedResolverLib.sol";
import {ResolverProfileRewriterLib} from "./libraries/ResolverProfileRewriterLib.sol";

/// @notice An owned resolver that supports multiple names and internal aliasing.
///
/// Resolved names find the longest match and rewrites the name accordingly.
/// Successful matches recursively check for additional aliasing.
/// Stops if the same alias applies twice.
/// Circular references result in OOG.
///
/// 1. Rewrite: `setAlias("a.eth", "b.eth")`
///    eg. `getAlias("a.eth") => "b.eth"`
///    eg. `getAlias("sub.a.eth") => "sub.b.eth"`
///    eg. `getAlias("x.eth") => ""
///
/// 2. Replace: `setAlias("com", ".c.eth")`
///    eg. `getAlias("abc.com") => "c.eth"`
///    eg. `getAlias("x.y.com") => "c.eth"`
///
contract OwnedResolver is
    HCAContextUpgradeable,
    UUPSUpgradeable,
    EnhancedAccessControl,
    IExtendedResolver,
    IMulticallable,
    IABIResolver,
    IAddrResolver,
    IAddressResolver,
    IContentHashResolver,
    IHasAddressResolver,
    IInterfaceResolver,
    IPubkeyResolver,
    ITextResolver,
    INameResolver
{
    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    event VersionChanged(bytes32 indexed node, uint256 newVersion);

    event AliasChanged(bytes indexed fromName, bytes indexed toName);

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /// @notice The resolver profile cannot be answered.
    /// @dev Error selector: `0x7b1c461b`
    error UnsupportedResolverProfile(bytes4 selector);

    /// @notice The address could not be converted to `address`.
    /// @dev Error selector: `0x8d666f60`
    error InvalidEVMAddress(bytes addressBytes);

    /// @notice The coin type is not a power of 2.
    /// @dev Error selector: `0xe7cf0ac4`
    error InvalidContentType(uint256 contentType);

    ////////////////////////////////////////////////////////////////////////
    // Modifiers
    ////////////////////////////////////////////////////////////////////////

    modifier onlyNodeRoles(bytes32 node, uint256 roleBitmap) {
        _checkRoles(OwnedResolverLib.nodeResource(node), roleBitmap, _msgSender());
        _;
    }

    modifier onlyPartRoles(bytes32 node, bytes32 part, uint256 roleBitmap) {
        address sender = _msgSender();
        if ((roles(OwnedResolverLib.partResource(node, part), sender) & roleBitmap) == 0) {
            if (
                (roles(OwnedResolverLib.partResource(bytes32(0), part), sender) & roleBitmap) == 0
            ) {
                _checkRoles(OwnedResolverLib.nodeResource(node), roleBitmap, sender);
            }
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    constructor(IHCAFactoryBasic hcaFactory) HCAEquivalence(hcaFactory) {
        _disableInitializers();
    }

    /// @inheritdoc EnhancedAccessControl
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(EnhancedAccessControl) returns (bool) {
        return
            type(IExtendedResolver).interfaceId == interfaceId ||
            type(IMulticallable).interfaceId == interfaceId ||
            type(IABIResolver).interfaceId == interfaceId ||
            type(IAddrResolver).interfaceId == interfaceId ||
            type(IAddressResolver).interfaceId == interfaceId ||
            type(IContentHashResolver).interfaceId == interfaceId ||
            type(IHasAddressResolver).interfaceId == interfaceId ||
            type(IInterfaceResolver).interfaceId == interfaceId ||
            type(IPubkeyResolver).interfaceId == interfaceId ||
            type(ITextResolver).interfaceId == interfaceId ||
            type(INameResolver).interfaceId == interfaceId ||
            type(UUPSUpgradeable).interfaceId == interfaceId ||
            super.supportsInterface(interfaceId);
    }

    ////////////////////////////////////////////////////////////////////////
    // Implementation
    ////////////////////////////////////////////////////////////////////////

    /// @notice Initialize the contract.
    /// @param admin The resolver owner.
    /// @param roleBitmap The roles granted to `admin`.
    function initialize(address admin, uint256 roleBitmap) external initializer {
        if (admin == address(0)) {
            revert InvalidOwner();
        }
        __UUPSUpgradeable_init();
        _grantRoles(ROOT_RESOURCE, roleBitmap, admin, false);
    }

    /// @notice Clear all records for `node`.
    /// @param node The node to update.
    function clearRecord(bytes32 node) external onlyNodeRoles(node, OwnedResolverLib.ROLE_CLEAR) {
        uint256 version = ++_storage().versions[node];
        emit VersionChanged(node, version);
    }

    /// @notice Create an alias from `fromName` to `toName`.
    /// @param fromName The source DNS-encoded name.
    /// @param toName The destination DNS-encoded name.
    function setAlias(
        bytes calldata fromName,
        bytes calldata toName
    ) external onlyRootRoles(OwnedResolverLib.ROLE_ALIAS) {
        _storage().aliases[NameCoder.namehash(fromName, 0)] = toName;
        emit AliasChanged(fromName, toName);
    }

    /// @notice Set ABI data of the associated ENS node.
    /// @param node The node to update.
    /// @param contentType The content type of the ABI.
    /// @param data The ABI data.
    function setABI(
        bytes32 node,
        uint256 contentType,
        bytes calldata data
    ) external onlyNodeRoles(node, OwnedResolverLib.ROLE_SET_ABI) {
        if (!_isPowerOf2(contentType)) {
            revert InvalidContentType(contentType);
        }
        _record(node).abis[contentType] = data;
        emit ABIChanged(node, contentType);
    }

    /// @notice Set Ethereum mainnet address of the associated ENS node.
    ///         `address(0)` is stored as `new bytes(20)`.
    /// @param node The node to update.
    /// @param addr_ The address to set.
    function setAddr(bytes32 node, address addr_) external {
        setAddr(node, COIN_TYPE_ETH, abi.encodePacked(addr_));
    }

    /// @notice Set the contenthash of the associated ENS node.
    /// @param node The node to update.
    /// @param hash The contenthash to set.
    function setContenthash(
        bytes32 node,
        bytes calldata hash
    ) external onlyNodeRoles(node, OwnedResolverLib.ROLE_SET_CONTENTHASH) {
        _record(node).contenthash = hash;
        emit ContenthashChanged(node, hash);
    }

    /// @notice Set an interface of the associated ENS node.
    /// @param node The node to update.
    /// @param interfaceId The EIP-165 interface ID.
    /// @param implementer The address of the contract that implements this interface for this node.
    function setInterface(
        bytes32 node,
        bytes4 interfaceId,
        address implementer
    ) external onlyNodeRoles(node, OwnedResolverLib.ROLE_SET_INTERFACE) {
        _record(node).interfaces[interfaceId] = implementer;
        emit InterfaceChanged(node, interfaceId, implementer);
    }

    /// @notice Set the SECP256k1 public key associated with an ENS node.
    /// @param node The node to update.
    /// @param x The x coordinate of the public key.
    /// @param y The y coordinate of the public key.
    function setPubkey(
        bytes32 node,
        bytes32 x,
        bytes32 y
    ) external onlyNodeRoles(node, OwnedResolverLib.ROLE_SET_PUBKEY) {
        _record(node).pubkey = [x, y];
        emit PubkeyChanged(node, x, y);
    }

    /// @notice Set the name of the associated ENS node.
    /// @param node The node to update.
    function setName(
        bytes32 node,
        string calldata name_
    ) external onlyNodeRoles(node, OwnedResolverLib.ROLE_SET_NAME) {
        _record(node).name = name_;
        emit NameChanged(node, name_);
    }

    /// @notice Set the text for `key` of the associated ENS node.
    /// @param node The node to update.
    /// @param key The key to set.
    /// @param value The text value to set.
    function setText(
        bytes32 node,
        string calldata key,
        string calldata value
    )
        external
        onlyPartRoles(node, OwnedResolverLib.partForTextKey(key), OwnedResolverLib.ROLE_SET_TEXT)
    {
        _record(node).texts[key] = value;
        emit TextChanged(node, key, key, value);
    }

    /// @notice Same as `multicall()`.
    /// @dev The purpose of node check is to prevent a trusted operator from modifying multiple names.
    //       Since there is no trusted operator, the node check logic can be elided.
    function multicallWithNodeCheck(
        bytes32,
        bytes[] calldata calls
    ) external returns (bytes[] memory) {
        return multicall(calls);
    }

    /// @notice Determine which name is queried when `fromName` is resolved.
    /// @param fromName The DNS-encoded name.
    /// @return toName The DNS-encoded alias or null if not aliased.
    function getAlias(bytes memory fromName) public view returns (bytes memory toName) {
        bytes32 prev;
        for (;;) {
            bytes memory aliasName;
            (aliasName, fromName) = _getAlias(fromName);
            if (fromName.length == 0) break;
            bytes32 next = keccak256(aliasName);
            if (next == prev) break;
            toName = fromName;
            prev = next;
        }
    }

    /// @inheritdoc IExtendedResolver
    function resolve(
        bytes calldata fromName,
        bytes calldata data
    ) external view returns (bytes memory) {
        bytes memory toName = getAlias(fromName);
        (bool ok, bytes memory v) = address(this).staticcall(
            ResolverProfileRewriterLib.replaceNode(
                data,
                NameCoder.namehash(toName.length == 0 ? fromName : toName, 0)
            )
        );
        if (!ok) {
            assembly {
                revert(add(v, 32), mload(v))
            }
        } else if (v.length == 0) {
            revert UnsupportedResolverProfile(bytes4(data));
        }
        return v;
    }

    /// @inheritdoc IABIResolver
    // solhint-disable-next-line func-name-mixedcase
    function ABI(
        bytes32 node,
        uint256 contentTypes
    ) external view returns (uint256 contentType, bytes memory data) {
        OwnedResolverLib.Record storage R = _record(node);
        for (contentType = 1; contentType > 0 && contentType <= contentTypes; contentType <<= 1) {
            if ((contentType & contentTypes) != 0) {
                data = R.abis[contentType];
                if (data.length > 0) {
                    return (contentType, data);
                }
            }
        }
        return (0, "");
    }

    /// @inheritdoc IHasAddressResolver
    function hasAddr(bytes32 node, uint256 coinType) external view returns (bool) {
        return _record(node).addresses[coinType].length > 0;
    }

    /// @inheritdoc IContentHashResolver
    function contenthash(bytes32 node) external view returns (bytes memory) {
        return _record(node).contenthash;
    }

    /// @inheritdoc IInterfaceResolver
    function interfaceImplementer(
        bytes32 node,
        bytes4 interfaceId
    ) external view returns (address implementer) {
        implementer = _record(node).interfaces[interfaceId];
        if (implementer == address(0) && ERC165Checker.supportsInterface(addr(node), interfaceId)) {
            implementer = address(this);
        }
    }

    /// @inheritdoc INameResolver
    function name(bytes32 node) external view returns (string memory) {
        return _record(node).name;
    }

    /// @inheritdoc IPubkeyResolver
    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y) {
        OwnedResolverLib.Record storage R = _record(node);
        x = R.pubkey[0];
        y = R.pubkey[1];
    }

    /// @inheritdoc ITextResolver
    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _record(node).texts[key];
    }

    /// @notice Perform multiple read or write operations.
    /// @dev Reverts with first error.
    function multicall(bytes[] calldata calls) public returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory v) = address(this).delegatecall(calls[i]);
            if (!ok) {
                assembly {
                    revert(add(v, 32), v) // propagate the first error
                }
            }
            results[i] = v;
        }
        return results;
    }

    /// @notice Set the address for `coinType` of the associated ENS node.
    ///         Reverts `InvalidEVMAddress` if coin type is EVM and not 0 or 20 bytes.
    /// @param node The node to update.
    /// @param coinType The coin type.
    /// @param addressBytes The address to set.
    function setAddr(
        bytes32 node,
        uint256 coinType,
        bytes memory addressBytes
    )
        public
        onlyPartRoles(
            node,
            OwnedResolverLib.partForCoinType(coinType),
            OwnedResolverLib.ROLE_SET_ADDR
        )
    {
        if (
            addressBytes.length != 0 && addressBytes.length != 20 && ENSIP19.isEVMCoinType(coinType)
        ) {
            revert InvalidEVMAddress(addressBytes);
        }
        _record(node).addresses[coinType] = addressBytes;
        emit AddressChanged(node, coinType, addressBytes);
        if (coinType == COIN_TYPE_ETH) {
            emit AddrChanged(node, address(bytes20(addressBytes)));
        }
    }

    /// @inheritdoc IAddressResolver
    function addr(bytes32 node, uint256 coinType) public view returns (bytes memory addressBytes) {
        OwnedResolverLib.Record storage R = _record(node);
        addressBytes = R.addresses[coinType];
        if (addressBytes.length == 0 && ENSIP19.chainFromCoinType(coinType) > 0) {
            addressBytes = R.addresses[COIN_TYPE_DEFAULT];
        }
    }

    /// @inheritdoc IAddrResolver
    function addr(bytes32 node) public view returns (address payable) {
        return payable(address(bytes20(addr(node, COIN_TYPE_ETH))));
    }

    ////////////////////////////////////////////////////////////////////////
    // Internal Functions
    ////////////////////////////////////////////////////////////////////////

    /// @dev Allow `ROLE_UPGRADE` to upgrade.
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRootRoles(OwnedResolverLib.ROLE_UPGRADE) {
        //
    }

    function _msgSender()
        internal
        view
        virtual
        override(HCAContext, HCAContextUpgradeable)
        returns (address)
    {
        return HCAContextUpgradeable._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(Context, ContextUpgradeable)
        returns (bytes calldata)
    {
        return msg.data;
    }

    function _contextSuffixLength()
        internal
        view
        virtual
        override(Context, ContextUpgradeable)
        returns (uint256)
    {
        return 0;
    }

    /// @dev Apply one round of aliasing.
    /// @return aliasName The alias that matched or null if no match.
    /// @return toName The new DNS-encoded name or null if no match.
    function _getAlias(
        bytes memory fromName
    ) internal view returns (bytes memory aliasName, bytes memory toName) {
        uint256 offset;
        (aliasName, offset, ) = _findAlias(fromName, 0);
        if (aliasName.length > 0) {
            if (aliasName.length > 1 && aliasName[0] == 0) {
                assembly {
                    // drop first char
                    mstore(add(aliasName, 1), sub(mload(aliasName), 1))
                    toName := add(aliasName, 1)
                }
            } else if (offset > 0) {
                toName = new bytes(offset + aliasName.length);
                assembly {
                    mcopy(add(toName, 32), add(fromName, 32), offset) // copy prefix
                    mcopy(add(toName, add(32, offset)), add(aliasName, 32), mload(aliasName)) // copy suffix
                }
            } else {
                toName = aliasName;
            }
        }
    }

    /// @dev Recursive algorithm for efficiently computing suffix match.
    function _findAlias(
        bytes memory name_,
        uint256 offset
    ) internal view returns (bytes memory suffixName, uint256 prefixOffset, bytes32 node) {
        if (offset + 1 < name_.length) {
            (bytes32 labelhash, uint256 next) = NameCoder.readLabel(name_, offset);
            (suffixName, prefixOffset, node) = _findAlias(name_, next);
            node = NameCoder.namehash(node, labelhash);
        }
        bytes memory suffix = _storage().aliases[node];
        if (suffix.length > 0) {
            suffixName = suffix;
            prefixOffset = offset;
        }
    }

    /// @dev Access record storage pointer.
    function _record(bytes32 node) internal view returns (OwnedResolverLib.Record storage R) {
        OwnedResolverLib.Storage storage S = _storage();
        return S.records[node][S.versions[node]];
    }

    /// @dev Access global storage pointer.
    function _storage() internal pure returns (OwnedResolverLib.Storage storage S) {
        uint256 slot = OwnedResolverLib.NAMED_SLOT;
        assembly {
            S.slot := slot
        }
    }

    /// @dev Returns true if `x` has a single bit set.
    function _isPowerOf2(uint256 x) internal pure returns (bool) {
        return x > 0 && (x - 1) & x == 0;
    }
}
