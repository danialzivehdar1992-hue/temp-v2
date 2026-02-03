// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

/**
 * @title MigrationErrors
 * @dev Error definitions specific to migration operations
 */

/**
 * @dev Thrown when attempting to migrate a subdomain whose parent has not been migrated
 * @param name The DNS-encoded name being migrated
 * @param offset The byte offset where the parent domain starts in the name
 */
error ParentNotMigrated(bytes name, uint256 offset);

/**
 * @dev Thrown when attempting to register a label that has an emancipated NFT in the old system but hasn't been migrated
 * @param label The label that needs to be migrated first
 */
error LabelNotMigrated(string label);

/// @dev Errors for migration process.
library MigrationErrors {
    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    error NameNotMigrated(bytes name);
    error NameNotSubdomain(bytes name, bytes parentName);

    error NameIsLocked(bytes name);
    error NameNotLocked(bytes name);
    error NameNotETH2LD(bytes name);
    error NameNotEmancipated(bytes name);

    error InvalidWrapperRegistryData();

    error TokenNodeMismatch(uint256 tokenId, bytes32 node);
}
