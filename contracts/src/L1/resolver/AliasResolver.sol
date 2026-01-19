// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {CCIPReader} from "@ens/contracts/ccipRead/CCIPReader.sol";
import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {
    ICompositeResolver,
    IExtendedResolver
} from "@ens/contracts/resolvers/profiles/ICompositeResolver.sol";
import {ResolverFeatures} from "@ens/contracts/resolvers/ResolverFeatures.sol";
import {ResolverCaller} from "@ens/contracts/universalResolver/ResolverCaller.sol";
import {IERC7996} from "@ens/contracts/utils/IERC7996.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import {
    ResolverProfileRewriterLib
} from "../../common/resolver/libraries/ResolverProfileRewriterLib.sol";
import {LibRegistry, IRegistry} from "../../universalResolver/libraries/LibRegistry.sol";

contract AliasResolver is ERC165, IERC7996, ResolverCaller, ICompositeResolver {
    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    IRegistry public immutable ROOT_REGISTRY;

    /// @dev Shared batch gateway provider.
    IGatewayProvider public immutable BATCH_GATEWAY_PROVIDER;

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    event AliasCreated(address clone, address resolver, bytes name);

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    constructor(
        IRegistry rootRegistry,
        IGatewayProvider batchGatewayProvider
    ) CCIPReader(DEFAULT_UNSAFE_CALL_GAS) {
        ROOT_REGISTRY = rootRegistry;
        BATCH_GATEWAY_PROVIDER = batchGatewayProvider;
    }

    /// @inheritdoc ERC165
    function supportsInterface(bytes4 interfaceId) public view override(ERC165) returns (bool) {
        return
            interfaceId == type(IExtendedResolver).interfaceId ||
            interfaceId == type(ICompositeResolver).interfaceId ||
            interfaceId == type(IERC7996).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IERC7996
    function supportsFeature(bytes4 featureId) external pure returns (bool) {
        return featureId == ResolverFeatures.RESOLVE_MULTICALL;
    }

    ////////////////////////////////////////////////////////////////////////
    // Implementation
    ////////////////////////////////////////////////////////////////////////

    /// @notice Deploy an immutable AliasResolver clone.
    /// @param resolver The specific resolver or zero if dynamically resolved.
    /// @param name The rewritten name or null if same name.
    /// @return The AliasResolver clone.
    function createAlias(address resolver, bytes calldata name) external returns (AliasResolver) {
        address clone = Clones.cloneWithImmutableArgs(
            _implementation(),
            // abi.encode(resolver, name)
            resolver == address(0) ? name : abi.encodePacked(name, resolver, uint8(1))
        );
        emit AliasCreated(clone, resolver, name);
        return AliasResolver(clone);
    }

    /// @inheritdoc IExtendedResolver
    function resolve(
        bytes calldata name,
        bytes calldata data
    ) external view returns (bytes memory) {
        (address resolver, bytes memory newName) = this.getAlias();
        if (newName.length == 0) {
            newName = name; // use same name if not specified
        }
        if (resolver == address(0)) {
            // lookup resolver in registry if not specified
            (, resolver, , ) = LibRegistry.findResolver(ROOT_REGISTRY, newName, 0);
        }
        callResolver(
            resolver,
            newName,
            ResolverProfileRewriterLib.replaceNode(data, NameCoder.namehash(newName, 0)),
            false,
            "",
            BATCH_GATEWAY_PROVIDER.gateways()
        );
    }

    /// @inheritdoc ICompositeResolver
    function getResolver(
        bytes calldata name
    ) external view returns (address resolver, bool offchain) {
        (address newResolver, bytes memory newName) = this.getAlias();
        if (newName.length == 0) {
            newName = name;
        }
        if (newResolver == address(0)) {
            (, newResolver, , ) = LibRegistry.findResolver(ROOT_REGISTRY, newName, 0);
        }
        return (newResolver, false);
    }

    /// @inheritdoc ICompositeResolver
    function requiresOffchain(bytes calldata) external pure returns (bool) {
        return false;
    }

    /// @notice Get aliased resolver and name.
    /// @return resolver The specific resolver or zero if dynamically resolved.
    /// @return name The rewritten name or null if same name.
    function getAlias() public view returns (address resolver, bytes memory name) {
        //(resolver, name) = abi.decode(Clones.fetchCloneArgs(address(this)), (address, bytes));
        name = Clones.fetchCloneArgs(address(this));
        assembly {
            let len := mload(name)
            let last := mload(add(name, len))
            if and(last, 1) {
                resolver := shr(8, last) // remove trailing byte
                mstore(name, sub(len, 21)) // truncate
            }
        }
    }

    /// @dev Determine EIP-1167 implementation address.
    function _implementation() private view returns (address) {
        bytes10 prefix;
        address impl;
        assembly {
            extcodecopy(address(), 0, 0, 40)
            prefix := mload(0)
            impl := shr(96, mload(10))
        }
        return prefix == bytes10(0x363d3d373d3d3d363d73) ? impl : address(this);
    }
}
