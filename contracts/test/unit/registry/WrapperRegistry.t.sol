// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {
    NameWrapper,
    IMetadataService,
    OperationProhibited,
    CANNOT_UNWRAP,
    CAN_DO_EVERYTHING,
    CANNOT_BURN_FUSES,
    CANNOT_TRANSFER,
    CANNOT_SET_RESOLVER,
    CANNOT_SET_TTL,
    CANNOT_CREATE_SUBDOMAIN,
    PARENT_CANNOT_CONTROL,
    IS_DOT_ETH,
    CAN_EXTEND_EXPIRY
} from "@ens/contracts/wrapper/NameWrapper.sol";
import {NameCoder} from "@ens/contracts/utils/NameCoder.sol";
import {GatewayProvider} from "@ens/contracts/ccipRead/GatewayProvider.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

import {ENSV1Resolver} from "~src/resolver/ENSV1Resolver.sol";
import {V1Fixture} from "~test/fixtures/V1Fixture.sol";
import {V2Fixture} from "~test/fixtures/V2Fixture.sol";
import {WrappedErrorLib} from "~src/utils/WrappedErrorLib.sol";
import {LockedMigrationController} from "~src/migration/LockedMigrationController.sol";
import {
    WrapperRegistry,
    IWrapperRegistry,
    RegistryRolesLib,
    MigrationErrors,
    IRegistry
} from "~src/registry/WrapperRegistry.sol";

contract WrapperRegistryTest is V1Fixture, V2Fixture {
    WrapperRegistry migratedRegistryImpl;

    function setUp() external {
        deployV1Fixture();
        deployV2Fixture();
        ENSV1Resolver fallbackResolver = new ENSV1Resolver(
            ensV1,
            new GatewayProvider(address(this), new string[](0))
        );
        migratedRegistryImpl = new WrapperRegistry(
            nameWrapper,
            verifiableFactory,
            address(fallbackResolver),
            datastore,
            hcaFactory,
            metadata
        );
    }

    function test_supportsInterface() external view {
        assertTrue(migratedRegistryImpl.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertTrue(
            migratedRegistryImpl.supportsInterface(type(IERC1155Receiver).interfaceId),
            "IERC1155Receiver"
        );
    }
}
