// SPDX-License-Identifier: MIT
// Portions from OpenZeppelin Contracts (token/ERC1155/ERC1155.sol)
pragma solidity >=0.8.13;

import {ERC1155Singleton, IERC165} from "../erc1155/ERC1155Singleton.sol";

import {ITokenRegistry, IRegistry} from "./interfaces/ITokenRegistry.sol";

abstract contract BaseRegistry is ITokenRegistry, ERC1155Singleton {
    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    error AccessDenied(uint256 tokenId, address owner, address caller);

    ////////////////////////////////////////////////////////////////////////
    // Modifiers
    ////////////////////////////////////////////////////////////////////////

    modifier onlyTokenOwner(uint256 tokenId) {
        address owner = ownerOf(tokenId);
        if (owner != _msgSender()) {
            revert AccessDenied(tokenId, owner, _msgSender());
        }
        _;
    }

    ////////////////////////////////////////////////////////////////////////
    // Initialization
    ////////////////////////////////////////////////////////////////////////

    /// @inheritdoc IERC165
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(IERC165, ERC1155Singleton) returns (bool) {
        return
            interfaceId == type(IRegistry).interfaceId ||
            interfaceId == type(ITokenRegistry).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
