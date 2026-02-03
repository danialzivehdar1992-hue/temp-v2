// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {VerifiableFactory} from "@ensdomains/verifiable-factory/VerifiableFactory.sol";

import {EACBaseRolesLib} from "~src/access-control/libraries/EACBaseRolesLib.sol";
import {BaseUriRegistryMetadata} from "~src/registry/BaseUriRegistryMetadata.sol";
import {PermissionedRegistry} from "~src/registry/PermissionedRegistry.sol";
import {RegistryDatastore} from "~src/registry/RegistryDatastore.sol";
import {MockHCAFactoryBasic} from "~test/mocks/MockHCAFactoryBasic.sol";

/// @dev Reusable testing fixture for ENSv2 with a basic ".eth" deployment.
contract V2Fixture {
    VerifiableFactory verifiableFactory;
    MockHCAFactoryBasic hcaFactory;
    RegistryDatastore datastore;
    BaseUriRegistryMetadata metadata;
    PermissionedRegistry rootRegistry;
    PermissionedRegistry ethRegistry;

    function deployV2Fixture() public {
        hcaFactory = new MockHCAFactoryBasic();
        verifiableFactory = new VerifiableFactory();
        datastore = new RegistryDatastore();
        metadata = new BaseUriRegistryMetadata(hcaFactory);
        rootRegistry = new PermissionedRegistry(
            datastore,
            hcaFactory,
            metadata,
            address(this),
            EACBaseRolesLib.ALL_ROLES
        );
        ethRegistry = new PermissionedRegistry(
            datastore,
            hcaFactory,
            metadata,
            address(this),
            EACBaseRolesLib.ALL_ROLES
        );
        rootRegistry.register(
            "eth",
            address(this),
            ethRegistry,
            address(0),
            EACBaseRolesLib.ALL_ROLES,
            type(uint64).max
        );
    }
}
