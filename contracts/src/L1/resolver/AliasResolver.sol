// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {CCIPReader} from "@ens/contracts/ccipRead/CCIPReader.sol";
import {ResolverCaller} from "@ens/contracts/universalResolver/ResolverCaller.sol";
import {IGatewayProvider} from "@ens/contracts/ccipRead/IGatewayProvider.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {IERC7996} from "@ens/contracts/utils/IERC7996.sol";
import {ResolverFeatures} from "@ens/contracts/resolvers/ResolverFeatures.sol";
import {
    ICompositeResolver,
    IExtendedResolver
} from "@ens/contracts/resolvers/profiles/ICompositeResolver.sol";
import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";

import {
    ResolverProfileRewriterLib
} from "../../common/resolver/libraries/ResolverProfileRewriterLib.sol";
import {LibRegistry, IRegistry} from "../../universalResolver/libraries/LibRegistry.sol";

contract AliasResolver is ERC165, IERC7996, ResolverCaller, ICompositeResolver {
    IRegistry public immutable ROOT_REGISTRY;
    IGatewayProvider public immutable BATCH_GATEWAY_PROVIDER;

    event Aliased(address clone, address resolver, bytes name);

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

    function createAlias(address resolver, bytes calldata name) external returns (AliasResolver) {
        address clone = Clones.cloneWithImmutableArgs(address(this), abi.encode(resolver, name));
        emit Aliased(clone, resolver, name);
        return AliasResolver(clone);
    }

    /// @inheritdoc IExtendedResolver
    function resolve(
        bytes calldata name,
        bytes calldata data
    ) external view returns (bytes memory) {
        (address resolver, bytes memory newName) = this.getAlias();
        if (newName.length == 0) {
            newName = name;
        }
        if (resolver == address(0)) {
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
        (resolver, name) = abi.decode(Clones.fetchCloneArgs(address(this)), (address, bytes));
    }
}
