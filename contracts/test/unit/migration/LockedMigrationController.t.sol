// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import {Vm, console} from "forge-std/Test.sol";
import {
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
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC1155Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {UnauthorizedCaller} from "~src/CommonErrors.sol";
import {ENSV1Resolver} from "~src/resolver/ENSV1Resolver.sol";
import {V1Fixture} from "~test/fixtures/V1Fixture.sol";
import {V2Fixture} from "~test/fixtures/V2Fixture.sol";
import {WrappedErrorLib} from "~src/utils/WrappedErrorLib.sol";
import {IStandardRegistry} from "~src/registry/interfaces/IStandardRegistry.sol";
import {LockedMigrationController} from "~src/migration/LockedMigrationController.sol";
import {
    WrapperRegistry,
    IWrapperRegistry,
    WrapperReceiver,
    RegistryRolesLib,
    MigrationErrors,
    IRegistry,
    IRegistryDatastore
} from "~src/registry/WrapperRegistry.sol";

contract LockedMigrationControllerTest is V1Fixture, V2Fixture {
    LockedMigrationController migrationController;
    WrapperRegistry migratedRegistryImpl;
    ENSV1Resolver ensV1Resolver;
    MockERC1155 dummy1155;

    function setUp() external {
        deployV1Fixture();
        deployV2Fixture();
        dummy1155 = new MockERC1155();
        ensV1Resolver = new ENSV1Resolver(ensV1, batchGatewayProvider);
        migratedRegistryImpl = new WrapperRegistry(
            nameWrapper,
            verifiableFactory,
            address(ensV1Resolver),
            datastore,
            hcaFactory,
            metadata
        );
        migrationController = new LockedMigrationController(
            ethRegistry,
            nameWrapper,
            verifiableFactory,
            address(migratedRegistryImpl)
        );
        ethRegistry.grantRootRoles(RegistryRolesLib.ROLE_REGISTRAR, address(migrationController));
    }

    function _makeData(bytes memory name) internal view returns (IWrapperRegistry.Data memory) {
        return
            IWrapperRegistry.Data({
                label: NameCoder.firstLabel(name),
                owner: user,
                resolver: address(1),
                salt: uint256(keccak256(abi.encode(name, block.timestamp)))
            });
    }

    function test_constructor() external view {
        assertEq(address(migrationController.NAME_WRAPPER()), address(nameWrapper), "NAME_WRAPPER");
        assertEq(
            address(migrationController.VERIFIABLE_FACTORY()),
            address(verifiableFactory),
            "VERIFIABLE_FACTORY"
        );
        assertEq(
            migrationController.MIGRATED_REGISTRY_IMPL(),
            address(migratedRegistryImpl),
            "MIGRATED_REGISTRY_IMPL"
        );
    }

    function test_supportsInterface() external view {
        assertTrue(migrationController.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertTrue(
            migrationController.supportsInterface(type(IERC1155Receiver).interfaceId),
            "IERC1155Receiver"
        );
    }

    function test_migrate_unauthorizedCaller_finish() external {
        vm.expectRevert(abi.encodeWithSelector(UnauthorizedCaller.selector, user));
        vm.prank(user);
        migrationController.finishERC1155Migration(
            new uint256[](0),
            new IWrapperRegistry.Data[](0)
        );
    }

    function test_migrate_unauthorizedCaller_transfer() external {
        uint256 tokenId = dummy1155.mint(user);
        vm.expectRevert(
            WrappedErrorLib.wrap(abi.encodeWithSelector(UnauthorizedCaller.selector, dummy1155))
        );
        vm.prank(user);
        dummy1155.safeTransferFrom(user, address(migrationController), tokenId, 1, ""); // wrong
    }

    function test_migrate_invalidWrapperRegistryData() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(MigrationErrors.InvalidWrapperRegistryData.selector)
            )
        );
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            "" // wrong
        );
    }

    function test_migrate_invalidArrayLength() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        IWrapperRegistry.Data[] memory mds = new IWrapperRegistry.Data[](1);
        ids[0] = uint256(NameCoder.namehash(name, 0));
        amounts[0] = 1;
        bytes memory payload = abi.encode(mds);
        uint256 fakeLength = 0;
        assembly {
            mstore(add(payload, 64), fakeLength) // wrong
        }
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(
                    IERC1155Errors.ERC1155InvalidArrayLength.selector,
                    ids.length,
                    fakeLength
                )
            )
        );
        vm.prank(user);
        nameWrapper.safeBatchTransferFrom(
            user,
            address(migrationController),
            ids,
            amounts,
            payload
        );
    }

    function test_migrate_invalidReceiver() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        IWrapperRegistry.Data memory md = _makeData(name);
        md.owner = address(0);
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(IERC1155Errors.ERC1155InvalidReceiver.selector, md.owner)
            )
        );
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            abi.encode(md)
        );
    }

    function test_migrate_nameDataMismatch() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        bytes32 node = NameCoder.namehash(name, 0);
        IWrapperRegistry.Data memory md = _makeData(name);
        md.label = "wrong";
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(MigrationErrors.NameDataMismatch.selector, node)
            )
        );
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(node),
            1,
            abi.encode(md)
        );
    }

    function test_migrate_nameNotLocked() external {
        bytes memory name = registerWrappedETH2LD("test", CAN_DO_EVERYTHING);
        bytes32 node = NameCoder.namehash(name, 0);
        IWrapperRegistry.Data memory md = _makeData(name);
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(MigrationErrors.NameNotLocked.selector, node)
            )
        );
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(node),
            1,
            abi.encode(md)
        );
    }

    function test_migrate() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        IWrapperRegistry.Data memory md = _makeData(name);
        // vm.recordLogs();
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            abi.encode(md)
        );
        // Vm.Log[] memory logs = vm.getRecordedLogs();
        // console.log("Logs = %s", logs.length);
        // for (uint256 i; i < logs.length; ++i) {
        //     console.log("i = %s", i);
        //     console.logBytes32(logs[i].topics[0]);
        //     console.logBytes(logs[i].data);
        //     console.log();
        // }
        // NameRegistered
        // SubregistryUpdated
        // ResolverUpdated
        (uint256 tokenId, IRegistryDatastore.Entry memory e) = ethRegistry.getNameData(
            NameCoder.firstLabel(name)
        );
        assertEq(ethRegistry.ownerOf(tokenId), md.owner, "owner");
        assertEq(e.resolver, md.resolver, "resolver");
        assertEq(
            e.expiry,
            ethRegistrarV1.nameExpires(uint256(keccak256(bytes(NameCoder.firstLabel(name))))),
            "expiry"
        );
        WrapperRegistry subregistry = WrapperRegistry(address(e.subregistry));
        assertTrue(
            ERC165Checker.supportsInterface(
                address(subregistry),
                type(IWrapperRegistry).interfaceId
            ),
            "IWrapperRegistry"
        );
        assertTrue(
            subregistry.hasRootRoles(RegistryRolesLib.ROLE_REGISTRAR, md.owner),
            "ROLE_REGISTRAR"
        );
        assertEq(address(subregistry.NAME_WRAPPER()), address(nameWrapper), "NAME_WRAPPER");
        assertEq(
            address(subregistry.VERIFIABLE_FACTORY()),
            address(verifiableFactory),
            "VERIFIABLE_FACTORY"
        );
        assertEq(
            subregistry.MIGRATED_REGISTRY_IMPL(),
            address(migratedRegistryImpl),
            "MIGRATED_REGISTRY_IMPL"
        );
    }

    function test_migrateBatch(uint8 count) external {
        vm.assume(count < 5);
        uint256[] memory ids = new uint256[](count);
        uint256[] memory amounts = new uint256[](count);
        IWrapperRegistry.Data[] memory mds = new IWrapperRegistry.Data[](count);
        for (uint256 i; i < count; ++i) {
            bytes memory name = registerWrappedETH2LD(_label(i), CANNOT_UNWRAP);
            IWrapperRegistry.Data memory md = _makeData(name);
            md.resolver = address(uint160(i));
            mds[i] = md;
            ids[i] = uint256(NameCoder.namehash(name, 0));
            amounts[i] = 1;
        }
        vm.prank(user);
        nameWrapper.safeBatchTransferFrom(
            user,
            address(migrationController),
            ids,
            amounts,
            abi.encode(mds)
        );
        for (uint256 i; i < count; ++i) {
            (uint256 tokenId, IRegistryDatastore.Entry memory e) = ethRegistry.getNameData(
                _label(i)
            );
            assertEq(ethRegistry.ownerOf(tokenId), user, "owner");
            assertEq(e.resolver, address(uint160(i)), "resolver");
            assertTrue(
                ERC165Checker.supportsInterface(
                    address(e.subregistry),
                    type(IWrapperRegistry).interfaceId
                ),
                "IWrapperRegistry"
            );
        }
    }

    function test_migrateBatch_lastOneWrong(uint8 count) external {
        vm.assume(count > 1 && count < 5);
        uint256[] memory ids = new uint256[](count);
        uint256[] memory amounts = new uint256[](count);
        IWrapperRegistry.Data[] memory mds = new IWrapperRegistry.Data[](count);
        for (uint256 i; i < count; ++i) {
            bytes memory name = registerWrappedETH2LD(
                _label(i),
                i == count - 1 ? CAN_DO_EVERYTHING : CANNOT_UNWRAP
            );
            IWrapperRegistry.Data memory md = _makeData(name);
            mds[i] = md;
            ids[i] = uint256(NameCoder.namehash(name, 0));
            amounts[i] = 1;
        }
        vm.expectRevert(
            WrappedErrorLib.wrap(
                abi.encodeWithSelector(MigrationErrors.NameNotLocked.selector, ids[count - 1])
            )
        );
        vm.prank(user);
        nameWrapper.safeBatchTransferFrom(
            user,
            address(migrationController),
            ids,
            amounts,
            abi.encode(mds)
        );
    }

    function test_migrate_lockedResolver() external {
        bytes memory name = registerWrappedETH2LD("test", CAN_DO_EVERYTHING);
        bytes32 node = NameCoder.namehash(name, 0);
        IWrapperRegistry.Data memory md = _makeData(name);

        address frozenResolver = address(2);
        vm.startPrank(user);
        nameWrapper.setResolver(node, frozenResolver);
        nameWrapper.setFuses(node, uint16(CANNOT_UNWRAP | CANNOT_SET_RESOLVER));
        vm.stopPrank();
        assertNotEq(md.resolver, frozenResolver, "unfrozen");

        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(node),
            1,
            abi.encode(md)
        );

        assertEq(findResolver(name), frozenResolver, "frozen");
    }

    function test_migrate_lockedTransfer() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP | CANNOT_TRANSFER);
        bytes32 node = NameCoder.namehash(name, 0);
        IWrapperRegistry.Data memory md = _makeData(name);

        vm.expectRevert(abi.encodeWithSelector(OperationProhibited.selector, node));
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(node),
            1,
            abi.encode(md)
        );
    }

    function test_migrate_lockedExpiry() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP | CAN_EXTEND_EXPIRY);
        IWrapperRegistry.Data memory md = _makeData(name);

        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            abi.encode(md)
        );
        (uint256 tokenId, ) = ethRegistry.getNameData(NameCoder.firstLabel(name));
        assertFalse(ethRegistry.hasRoles(tokenId, RegistryRolesLib.ROLE_RENEW, user));
    }

    function test_migrate_lockedChildren() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP | CANNOT_CREATE_SUBDOMAIN);
        IWrapperRegistry.Data memory md = _makeData(name);

        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            abi.encode(md)
        );
        (uint256 tokenId, ) = ethRegistry.getNameData(NameCoder.firstLabel(name));
        assertFalse(ethRegistry.hasRoles(tokenId, RegistryRolesLib.ROLE_REGISTRAR, user));
    }

    function test_migrate_lockedFuses() external {
        bytes memory name = registerWrappedETH2LD("test", CANNOT_UNWRAP | CANNOT_CREATE_SUBDOMAIN);
        IWrapperRegistry.Data memory md = _makeData(name);

        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name, 0)),
            1,
            abi.encode(md)
        );
        (uint256 tokenId, ) = ethRegistry.getNameData(NameCoder.firstLabel(name));
        assertFalse(ethRegistry.hasRoles(tokenId, RegistryRolesLib.ROLE_REGISTRAR, user));
    }

    function test_migrate_emancipatedChildren() external {
        bytes memory name2 = registerWrappedETH2LD("test", CANNOT_UNWRAP);
        bytes memory name3 = createWrappedChild(
            name2,
            "3ld",
            CANNOT_UNWRAP | PARENT_CANNOT_CONTROL
        );
        bytes memory name3unmigrated = createWrappedChild(
            name2,
            "unmigrated3ld",
            CANNOT_UNWRAP | PARENT_CANNOT_CONTROL
        );

        // migrate 2LD
        IWrapperRegistry.Data memory data2 = _makeData(name2);
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(migrationController),
            uint256(NameCoder.namehash(name2, 0)),
            1,
            abi.encode(data2)
        );
        (uint256 tokenId2, IRegistryDatastore.Entry memory entry2) = ethRegistry.getNameData(
            NameCoder.firstLabel(name2)
        );
        assertEq(ethRegistry.ownerOf(tokenId2), data2.owner, "owner2");

        IWrapperRegistry registry2 = IWrapperRegistry(address(entry2.subregistry));
        assertTrue(
            ERC165Checker.supportsInterface(address(registry2), type(IWrapperRegistry).interfaceId),
            "registry2"
        );

        // migrate 3LD
        IWrapperRegistry.Data memory data3 = _makeData(name3);
        vm.prank(user);
        nameWrapper.safeTransferFrom(
            user,
            address(entry2.subregistry),
            uint256(NameCoder.namehash(name3, 0)),
            1,
            abi.encode(data3)
        );
        (uint256 tokenId3, IRegistryDatastore.Entry memory entry3) = registry2.getNameData(
            NameCoder.firstLabel(name3)
        );
        assertEq(findResolver(name3), data3.resolver, "resolver3");
        assertEq(registry2.ownerOf(tokenId3), data3.owner, "owner3");

        IWrapperRegistry registry3 = IWrapperRegistry(address(entry3.subregistry));
        assertTrue(
            ERC165Checker.supportsInterface(address(registry3), type(IWrapperRegistry).interfaceId),
            "registry3"
        );

        // check migrated 3LD child
        vm.expectRevert(
            abi.encodeWithSelector(
                IStandardRegistry.NameAlreadyRegistered.selector,
                NameCoder.firstLabel(name3)
            )
        );
        vm.prank(user);
        registry2.register(
            NameCoder.firstLabel(name3),
            user,
            IRegistry(address(0)),
            address(0),
            0,
            uint64(block.timestamp + 1000)
        );

        // check unmigrated 3LD child
        vm.expectRevert(
            abi.encodeWithSelector(MigrationErrors.NameNotMigrated.selector, name3unmigrated)
        );
        vm.prank(user);
        registry2.register(
            NameCoder.firstLabel(name3unmigrated),
            user,
            IRegistry(address(0)),
            address(0),
            0,
            uint64(block.timestamp + 1000)
        );
        assertEq(findResolver(name3unmigrated), address(ensV1Resolver), "unmigratedResolver");
    }

    function _label(uint256 i) internal pure returns (string memory) {
        return string.concat("test", vm.toString(i));
    }
}

contract MockERC1155 is ERC1155 {
    uint256 _id;
    constructor() ERC1155("") {}
    function mint(address to) external returns (uint256) {
        _mint(to, _id, 1, "");
        return _id++;
    }
}
