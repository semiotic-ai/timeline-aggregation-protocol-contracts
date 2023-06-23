// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title AllocationIDTracker
 * @dev This contract tracks the allocation IDs of the RAVs that have been submitted to
 *      ensure that each allocation ID is only used once. It is external to collateral
 *      contract to allow for updating the collateral contract without losing the list of
 *      used allocation IDs.
 * @notice This contract is intended to be used with the `Collateral` contract.
 */
contract AllocationIDTracker {
    mapping(address allocationId => bool isUsed) private _usedAllocationIDs;

    /**
     * @dev Emitted when an allocation ID is used.
     */
    event AllocationIDUsed(address indexed allocationID);

    /**
     * @dev Checks if an allocation ID has been used.
     * @param allocationID The allocation ID to check.
     * @return True if the allocation ID has been used, false otherwise.
     */
    function isAllocationIDUsed(address allocationID) external view returns (bool) {
        return _usedAllocationIDs[allocationID];
    }

    /**
     * @dev Marks an allocation ID as used.
     * @param allocationID The allocation ID to mark as used.
     * @notice REVERT: This function may revert if the allocation ID has already been used.
     */
    function useAllocationID(address allocationID, bytes calldata proof) external {
        require(!_usedAllocationIDs[allocationID], "Allocation ID already used");
        require(verifyProof(proof, allocationID) == true, "Proof is not valid");
        _usedAllocationIDs[allocationID] = true;
        emit AllocationIDUsed(allocationID);
    }

    /**
     * @dev Verifies a proof.
     * @param proof The proof to verify.
     * @param allocationID The allocation ID to verify.
     * @return True if the proof is valid.
     * @notice REVERT: This function may revert if the proof is not valid.
     */
    function verifyProof(bytes calldata proof, address allocationID) private pure returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(allocationID));
        bytes32 digest = ECDSA.toEthSignedMessageHash(messageHash);
        require(ECDSA.recover(digest, proof) == allocationID, "!proof");
        return true;
    }
}
