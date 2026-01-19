// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// solhint-disable no-console, private-vars-leading-underscore, state-visibility, func-name-mixedcase, namechain/ordering, one-contract-per-file

import {Test} from "forge-std/Test.sol";

import {IMulticallable} from "@ens/contracts/resolvers/IMulticallable.sol";
import {IABIResolver} from "@ens/contracts/resolvers/profiles/IABIResolver.sol";
import {IAddressResolver} from "@ens/contracts/resolvers/profiles/IAddressResolver.sol";
import {IAddrResolver} from "@ens/contracts/resolvers/profiles/IAddrResolver.sol";
import {IContentHashResolver} from "@ens/contracts/resolvers/profiles/IContentHashResolver.sol";
import {IHasAddressResolver} from "@ens/contracts/resolvers/profiles/IHasAddressResolver.sol";
import {IInterfaceResolver} from "@ens/contracts/resolvers/profiles/IInterfaceResolver.sol";
import {INameResolver} from "@ens/contracts/resolvers/profiles/INameResolver.sol";
import {IPubkeyResolver} from "@ens/contracts/resolvers/profiles/IPubkeyResolver.sol";
import {ITextResolver} from "@ens/contracts/resolvers/profiles/ITextResolver.sol";
import {ResolverFeatures} from "@ens/contracts/resolvers/ResolverFeatures.sol";
import {ENSIP19, COIN_TYPE_ETH, COIN_TYPE_DEFAULT} from "@ens/contracts/utils/ENSIP19.sol";
import {VerifiableFactory} from "@ensdomains/verifiable-factory/VerifiableFactory.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";

import {
    IEnhancedAccessControl
} from "~src/common/access-control/interfaces/IEnhancedAccessControl.sol";
import {EACBaseRolesLib} from "~src/common/access-control/libraries/EACBaseRolesLib.sol";
import {OwnedResolver, OwnedResolverLib} from "~src/common/resolver/OwnedResolver.sol";
import {MockHCAFactoryBasic} from "~test/mocks/MockHCAFactoryBasic.sol";

contract OwnedResolverTest is Test {
    uint256 constant DEFAULT_ROLES = EACBaseRolesLib.ALL_ROLES;
    uint256 constant ROOT_RESOURCE = 0;

    struct I {
        bytes4 interfaceId;
        string name;
    }
    function _supportedInterfaces() internal pure returns (I[] memory v) {
        uint256 i;
        v = new I[](12);
        v[i++] = I(type(IMulticallable).interfaceId, "IMulticallable");
        v[i++] = I(type(IABIResolver).interfaceId, "IABIResolver");
        v[i++] = I(type(IAddrResolver).interfaceId, "IAddrResolver");
        v[i++] = I(type(IAddressResolver).interfaceId, "IAddressResolver");
        v[i++] = I(type(IContentHashResolver).interfaceId, "IContentHashResolver");
        v[i++] = I(type(IHasAddressResolver).interfaceId, "IHasAddressResolver");
        v[i++] = I(type(IInterfaceResolver).interfaceId, "IInterfaceResolver");
        v[i++] = I(type(INameResolver).interfaceId, "INameResolver");
        v[i++] = I(type(IPubkeyResolver).interfaceId, "IPubkeyResolver");
        v[i++] = I(type(ITextResolver).interfaceId, "ITextResolver");
        v[i++] = I(type(UUPSUpgradeable).interfaceId, "UUPSUpgradeable");
        v[i++] = I(type(IEnhancedAccessControl).interfaceId, "IEnhancedAccessControl");
        assertEq(v.length, i);
    }

    MockHCAFactoryBasic hcaFactory;
    OwnedResolver resolver;

    address owner = makeAddr("owner");
    address friend = makeAddr("friend");

    string testName = "test.eth";
    bytes32 testNode = keccak256(bytes(testName)); // hash type doesn't matter
    address testAddr = 0x8000000000000000000000000000000000000001;
    bytes testAddress = abi.encodePacked(testAddr);

    function setUp() external {
        VerifiableFactory factory = new VerifiableFactory();
        hcaFactory = new MockHCAFactoryBasic();
        OwnedResolver resolverImpl = new OwnedResolver(hcaFactory);

        bytes memory initData = abi.encodeCall(OwnedResolver.initialize, (owner, DEFAULT_ROLES));
        resolver = OwnedResolver(
            factory.deployProxy(address(resolverImpl), uint256(keccak256(initData)), initData)
        );
    }

    function test_initialize() external view {
        assertTrue(resolver.hasRootRoles(DEFAULT_ROLES, owner));
    }

    function test_upgrade() external {
        MockUpgrade upgrade = new MockUpgrade();
        vm.prank(owner);
        resolver.upgradeToAndCall(address(upgrade), "");
        assertEq(resolver.addr(testNode), upgrade.addr(testNode));
    }

    function test_upgrade_noRole() external {
        MockUpgrade upgrade = new MockUpgrade();
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_UPGRADE,
                friend
            )
        );
        vm.prank(friend);
        resolver.upgradeToAndCall(address(upgrade), "");
    }

    function test_supportsInterface() external view {
        assertTrue(ERC165Checker.supportsERC165(address(resolver)), "ERC165");
        I[] memory v = _supportedInterfaces();
        for (uint256 i; i < v.length; i++) {
            assertTrue(
                ERC165Checker.supportsInterface(address(resolver), v[i].interfaceId),
                v[i].name
            );
        }
    }

    function test_grantRootRoles_canGrantAdmin() external {
        vm.prank(owner);
        resolver.grantRootRoles(OwnedResolverLib.ROLE_SET_ADDR_ADMIN, friend);
        vm.prank(friend);
        resolver.grantRootRoles(OwnedResolverLib.ROLE_SET_ADDR, address(this));
        assertTrue(resolver.hasRootRoles(OwnedResolverLib.ROLE_SET_ADDR, address(this)));
    }

    function test_grantRootRoles_canTransferAdmin() external {
        vm.prank(owner);
        resolver.grantRootRoles(DEFAULT_ROLES, friend);
        vm.prank(friend);
        resolver.revokeRootRoles(DEFAULT_ROLES, owner);
        assertEq(resolver.roles(ROOT_RESOURCE, owner), 0, "owner");
        assertEq(resolver.roles(ROOT_RESOURCE, friend), DEFAULT_ROLES, "friend");
    }

    function test_grantRootRoles_notAdmin() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACCannotGrantRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_ADDR_ADMIN,
                address(this)
            )
        );
        resolver.grantRootRoles(OwnedResolverLib.ROLE_SET_ADDR_ADMIN, friend);
    }

    function test_revokeRootRoles_canRevokeAdmin() external {
        vm.prank(owner);
        resolver.revokeRootRoles(OwnedResolverLib.ROLE_SET_ADDR_ADMIN, owner);
    }

    function test_setAlias() external {
        bytes32 otherNode = keccak256("other");

        vm.startPrank(owner);
        resolver.setAlias(otherNode, testNode);
        resolver.setAddr(testNode, COIN_TYPE_ETH, testAddress);
        vm.stopPrank();

        assertEq(resolver.addr(otherNode, COIN_TYPE_ETH), testAddress, "before");

        vm.prank(owner);
        resolver.setAlias(otherNode, bytes32(0));

        assertEq(resolver.addr(otherNode, COIN_TYPE_ETH), "", "after");
    }

    function test_setAddr(uint256 coinType, bytes memory addressBytes) external {
        if (ENSIP19.isEVMCoinType(coinType)) {
            addressBytes = vm.randomBool() ? vm.randomBytes(20) : new bytes(0);
        }
        vm.prank(owner);
        resolver.setAddr(testNode, coinType, addressBytes);

        assertEq(resolver.addr(testNode, coinType), addressBytes);
    }

    function test_setAddr_fallback(uint32 chain) external {
        vm.assume(chain < COIN_TYPE_DEFAULT);
        bytes memory a = vm.randomBytes(20);

        vm.prank(owner);
        resolver.setAddr(testNode, COIN_TYPE_DEFAULT, a);

        assertEq(
            resolver.addr(testNode, chain == 1 ? COIN_TYPE_ETH : COIN_TYPE_DEFAULT | chain),
            a
        );
    }

    function test_setAddr_zeroEVM() external {
        vm.prank(owner);
        resolver.setAddr(testNode, COIN_TYPE_ETH, abi.encodePacked(address(0)));

        assertTrue(resolver.hasAddr(testNode, COIN_TYPE_ETH), "null");
        assertFalse(resolver.hasAddr(testNode, COIN_TYPE_DEFAULT), "unset");
    }

    function test_setAddr_zeroEVM_fallbacks() external {
        vm.startPrank(owner);
        resolver.setAddr(testNode, COIN_TYPE_DEFAULT, abi.encodePacked(address(1)));
        resolver.setAddr(testNode, COIN_TYPE_DEFAULT | 1, abi.encodePacked(address(0)));
        resolver.setAddr(testNode, COIN_TYPE_DEFAULT | 2, abi.encodePacked(address(2)));
        vm.stopPrank();

        assertEq(
            resolver.addr(testNode, COIN_TYPE_DEFAULT | 1),
            abi.encodePacked(address(0)),
            "block"
        );
        assertEq(
            resolver.addr(testNode, COIN_TYPE_DEFAULT | 2),
            abi.encodePacked(address(2)),
            "override"
        );
        assertEq(
            resolver.addr(testNode, COIN_TYPE_DEFAULT | 3),
            abi.encodePacked(address(1)),
            "fallback"
        );
    }

    function test_setAddr_invalidEVM_tooShort() external {
        bytes memory v = new bytes(1);
        vm.expectRevert(abi.encodeWithSelector(OwnedResolver.InvalidEVMAddress.selector, v));
        vm.prank(owner);
        resolver.setAddr(testNode, COIN_TYPE_ETH, v);
    }

    function test_setAddr_invalidEVM_tooLong() external {
        bytes memory v = new bytes(21);
        vm.expectRevert(abi.encodeWithSelector(OwnedResolver.InvalidEVMAddress.selector, v));
        vm.prank(owner);
        resolver.setAddr(testNode, COIN_TYPE_ETH, v);
    }

    function test_setAddr_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.nodeResource(testNode),
                OwnedResolverLib.ROLE_SET_ADDR,
                address(this)
            )
        );
        resolver.setAddr(testNode, COIN_TYPE_ETH, "");
    }

    /*
    function testFuzz_setText(string calldata key, string calldata value) external {
        vm.prank(owner);
        resolver.setText(key, value);

        assertEq(resolver.text(NODE_ANY, key), value, "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(ITextResolver.text, (NODE_ANY, key))
        );
        assertEq(abi.decode(result, (string)), value, "extended");

        assertEq(
            bytes(value),
            readBytes(address(resolver), follow(OwnedResolverLib.SLOT_TEXTS, bytes(key))),
            "storage"
        );
    }

    function test_setText_notAuthorized() external {
        string memory key = "abc";
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.textResource(key),
                OwnedResolverLib.ROLE_SET_TEXT,
                address(this)
            )
        );
        resolver.setText(key, "");
    }

    function testFuzz_setName(string calldata name) external {
        vm.prank(owner);
        resolver.setName(name);

        assertEq(resolver.name(NODE_ANY), name, "immediate");
        bytes memory result = resolver.resolve("", abi.encodeCall(INameResolver.name, (NODE_ANY)));
        assertEq(abi.decode(result, (string)), name, "extended");

        assertEq(bytes(name), readBytes(address(resolver), OwnedResolverLib.SLOT_NAME), "storage");
    }

    function test_setName_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_NAME,
                address(this)
            )
        );
        resolver.setName("");
    }

    function testFuzz_setContenthash(bytes calldata v) external {
        vm.prank(owner);
        resolver.setContenthash(v);

        assertEq(resolver.contenthash(NODE_ANY), v, "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(IContentHashResolver.contenthash, (NODE_ANY))
        );
        assertEq(abi.decode(result, (bytes)), v, "extended");

        assertEq(v, readBytes(address(resolver), OwnedResolverLib.SLOT_CONTENTHASH), "storage");
    }

    function test_setContenthash_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_CONTENTHASH,
                address(this)
            )
        );
        resolver.setContenthash("");
    }

    function testFuzz_setPubkey(bytes32 x, bytes32 y) external {
        vm.prank(owner);
        resolver.setPubkey(x, y);

        (bytes32 x_, bytes32 y_) = resolver.pubkey(NODE_ANY);
        assertEq(abi.encode(x_, y_), abi.encode(x, y), "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(IPubkeyResolver.pubkey, (NODE_ANY))
        );
        assertEq(result, abi.encode(x, y), "extended");

        assertEq(
            x,
            vm.load(address(resolver), bytes32(OwnedResolverLib.SLOT_PUBKEY)),
            "storage[0]"
        );
        assertEq(
            y,
            vm.load(address(resolver), bytes32(OwnedResolverLib.SLOT_PUBKEY + 1)),
            "storage[1]"
        );
    }

    function test_setPubkey_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_PUBKEY,
                address(this)
            )
        );
        resolver.setPubkey(0, 0);
    }

    function testFuzz_setABI(uint8 bit, bytes calldata data) external {
        uint256 contentType = 1 << bit;

        vm.prank(owner);
        resolver.setABI(contentType, data);

        uint256 contentTypes = ~uint256(0);
        (uint256 contentType_, bytes memory data_) = resolver.ABI(NODE_ANY, contentTypes);
        bytes memory expect = data.length > 0 ? abi.encode(contentType, data) : abi.encode(0, "");
        assertEq(abi.encode(contentType_, data_), expect, "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(IABIResolver.ABI, (NODE_ANY, contentTypes))
        );
        assertEq(result, expect, "extended");

        assertEq(
            data,
            readBytes(
                address(resolver),
                follow(OwnedResolverLib.SLOT_ABIS, abi.encode(contentType))
            ),
            "storage"
        );
    }

    function test_setABI_invalidContentType_noBits() external {
        vm.expectRevert(
            abi.encodeWithSelector(IDedicatedResolverSetters.InvalidContentType.selector, 0)
        );
        vm.prank(owner);
        resolver.setABI(0, "");
    }

    function test_setABI_invalidContentType_manyBits() external {
        vm.expectRevert(
            abi.encodeWithSelector(IDedicatedResolverSetters.InvalidContentType.selector, 3)
        );
        vm.prank(owner);
        resolver.setABI(3, "");
    }

    function test_setABI_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_ABI,
                address(this)
            )
        );
        resolver.setABI(1, "");
    }

    function testFuzz_setInterface(bytes4 interfaceId, address impl) external {
        vm.assume(!resolver.supportsInterface(interfaceId));

        vm.prank(owner);
        resolver.setInterface(interfaceId, impl);

        assertEq(resolver.interfaceImplementer(NODE_ANY, interfaceId), impl, "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(IInterfaceResolver.interfaceImplementer, (NODE_ANY, interfaceId))
        );
        assertEq(abi.decode(result, (address)), impl, "extended");

        assertEq(
            bytes32(uint256(uint160(impl))),
            vm.load(
                address(resolver),
                bytes32(follow(OwnedResolverLib.SLOT_INTERFACES, abi.encode(interfaceId)))
            ),
            "storage"
        );
    }

    function test_interfaceImplementer_overlap() external {
        vm.prank(owner);
        resolver.setAddr(COIN_TYPE_ETH, abi.encodePacked(resolver));

        I[] memory v = _supportedInterfaces();
        for (uint256 i; i < v.length; i++) {
            assertEq(
                resolver.interfaceImplementer(NODE_ANY, v[i].interfaceId),
                address(resolver),
                v[i].name
            );
        }
    }

    function test_setInterface_notAuthorized() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_INTERFACE,
                address(this)
            )
        );
        resolver.setInterface(bytes4(0), address(0));
    }

    function test_multicall_setters() external {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(DedicatedResolver.setName, (testName));
        calls[1] = abi.encodeCall(DedicatedResolver.setAddr, (COIN_TYPE_ETH, testAddress));

        vm.prank(owner);
        resolver.multicall(calls);

        assertEq(resolver.name(NODE_ANY), testName, "name()");
        assertEq(resolver.addr(NODE_ANY, COIN_TYPE_ETH), testAddress, "addr()");
    }

    function test_multicall_setters_notAuthorized() external {
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(DedicatedResolver.setName, (testName));
        calls[1] = abi.encodeCall(DedicatedResolver.setAddr, (COIN_TYPE_ETH, testAddress));

        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                ROOT_RESOURCE,
                OwnedResolverLib.ROLE_SET_NAME, // first error
                address(this)
            )
        );
        resolver.multicall(calls);
    }

    function test_multicall_getters() external {
        vm.startPrank(owner);
        resolver.setName(testName);
        resolver.setAddr(COIN_TYPE_ETH, testAddress);
        vm.stopPrank();

        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeCall(INameResolver.name, (NODE_ANY));
        calls[1] = abi.encodeCall(IAddressResolver.addr, (NODE_ANY, COIN_TYPE_ETH));

        bytes[] memory answers = new bytes[](2);
        answers[0] = abi.encode(testName);
        answers[1] = abi.encode(testAddress);

        bytes memory expect = abi.encode(answers);
        assertEq(abi.encode(resolver.multicall(calls)), expect, "immediate");
        bytes memory result = resolver.resolve(
            "",
            abi.encodeCall(DedicatedResolver.multicall, (calls))
        );
        assertEq(result, expect, "extended");
    }

    function test_setAddr_withRole() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.addrResource(60),
                OwnedResolverLib.ROLE_SET_ADDR,
                friend
            )
        );
        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_ETH, testAddress);

        vm.prank(owner);
        resolver.grantRootRoles(OwnedResolverLib.ROLE_SET_ADDR, friend);

        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_ETH, testAddress);

        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_DEFAULT, testAddress);
    }

    function test_setAddr_withResourceRole() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.addrResource(COIN_TYPE_ETH),
                OwnedResolverLib.ROLE_SET_ADDR,
                friend
            )
        );
        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_ETH, testAddress);

        vm.prank(owner);
        resolver.grantRoles(
            OwnedResolverLib.addrResource(COIN_TYPE_ETH),
            OwnedResolverLib.ROLE_SET_ADDR,
            friend
        );

        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_ETH, testAddress);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.addrResource(COIN_TYPE_DEFAULT),
                OwnedResolverLib.ROLE_SET_ADDR,
                friend
            )
        );
        vm.prank(friend);
        resolver.setAddr(COIN_TYPE_DEFAULT, testAddress);
    }

    function test_setText_withRole() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.textResource("a"),
                OwnedResolverLib.ROLE_SET_TEXT,
                friend
            )
        );
        vm.prank(friend);
        resolver.setText("a", "A");

        vm.prank(owner);
        resolver.grantRootRoles(OwnedResolverLib.ROLE_SET_TEXT, friend);

        vm.prank(friend);
        resolver.setText("a", "A");

        vm.prank(friend);
        resolver.setText("b", "B");
    }

    function test_setText_withResourceRole() external {
        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.textResource("a"),
                OwnedResolverLib.ROLE_SET_TEXT,
                friend
            )
        );
        vm.prank(friend);
        resolver.setText("a", "A");

        vm.prank(owner);
        resolver.grantRoles(
            OwnedResolverLib.textResource("a"),
            OwnedResolverLib.ROLE_SET_TEXT,
            friend
        );

        vm.prank(friend);
        resolver.setText("a", "A");

        vm.expectRevert(
            abi.encodeWithSelector(
                IEnhancedAccessControl.EACUnauthorizedAccountRoles.selector,
                OwnedResolverLib.textResource("b"),
                OwnedResolverLib.ROLE_SET_TEXT,
                friend
            )
        );
        vm.prank(friend);
        resolver.setText("b", "B");
    }
    */
}

contract MockUpgrade is UUPSUpgradeable {
    function addr(bytes32) external pure returns (address) {
        return address(1);
    }
    function _authorizeUpgrade(address) internal override {}
}
