// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

interface IRegistry {
    event ParentChanged(IRegistry indexed parent, string label);

    /// @notice Find the registry and resolver for a subdomain.
    ///
    /// @param label The subdomain.
    ///
    /// @return subregistry The registry address.
    /// @return resolver The resolver address.
    function findChild(
        string calldata label
    ) external view returns (IRegistry subregistry, address resolver);

    /// @notice Get canonical "home" of this registry.
    ///
    /// @return parent The canonical parent of this registry.
    /// @return label The canonical subdomain of this registry.
    function getParent() external view returns (IRegistry parent, string memory label);
}
