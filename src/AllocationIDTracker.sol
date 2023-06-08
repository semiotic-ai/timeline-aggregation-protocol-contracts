// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

/**
 * @title AllocationIDTracker
 * @dev This contract tracks the allocation IDs of the RAVs that have been submitted to
 *      ensure that each allocation ID is only used once. It is external to collateral
 *      contract to allow for updating the collateral contract without losing the list of
 *      used allocation IDs.
 * @notice This contract is intended to be used with the `Collateral` contract.
 */
contract AllocationIDTracker {
    mapping (address => bool) private _usedAllocationIDs;

    /**
     * @dev Emitted when an allocation ID is used.
     */
    event AllocationIDUsed(address indexed allocationID);

    /**
     * @dev Checks if an allocation ID has been used.
     * @param allocationID The allocation ID to check.
     * @return True if the allocation ID has been used, false otherwise.
     */
    function isAllocationIDUsed(address allocationID) public view returns (bool) {
        return _usedAllocationIDs[allocationID];
    }

    /**
     * @dev Marks an allocation ID as used.
     * @param allocationID The allocation ID to mark as used.
     * @notice REVERT: This function may revert if the allocation ID has already been used.
     */
    function useAllocationID(address allocationID) public {
        require(!_usedAllocationIDs[allocationID], "Allocation ID already used");
        _usedAllocationIDs[allocationID] = true;
        emit AllocationIDUsed(allocationID);
    }

    /**
     * @dev Marks multiple allocation IDs as used.
     * @param allocationIDs The allocation IDs to mark as used.
     * @notice REVERT: This function may revert if any of the allocation IDs have already been used.
     */
    function useAllocationIDs(address[] memory allocationIDs) public {
        for (uint256 i = 0; i < allocationIDs.length; i++) {
            useAllocationID(allocationIDs[i]);
        }
    }
}