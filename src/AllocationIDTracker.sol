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
    // senders used allocation IDs
    mapping(address sender => mapping(address allocationId => bool isUsed))
        private _sendersUsedAllocationIDs;

    // Custom error to indicate the provided allocation ID was previously claimed and no longer valid
    error AllocationIDPreviouslyClaimed(address sender, address allocationID);

    // Custom error to indicate the provided proof is not valid
    error InvalidProof();

    /**
     * @dev Emitted when an allocation ID is used.
     */
    event AllocationIDUsed(
        address indexed sender,
        address indexed allocationID
    );

    /**
     * @dev Checks if an allocation ID has been used.
     * @param allocationID The allocation ID to check.
     * @return True if the allocation ID has been used, false otherwise.
     */
    function isAllocationIDUsed(
        address sender,
        address allocationID
    ) external view returns (bool) {
        return _sendersUsedAllocationIDs[sender][allocationID];
    }

    /**
     * @dev Marks an allocation ID as used.
     * @param sender The sender of the token to receiver.
     * @param allocationID The allocation ID to mark as used.
     * @param proof ECDSA Proof signed by the receiver's allocationID consisting of packed (sender address, allocationID, collateral contract address).
     * @notice REVERT with error:
     *               - AllocationIDPreviouslyClaimed: If the (sender, allocationID) pair was previously claimed
     *               - InvalidProof: If the proof is not valid
     */
    function useAllocationID(
        address sender,
        address allocationID,
        bytes calldata proof
    ) external {
        if (_sendersUsedAllocationIDs[sender][allocationID] == true) {
            revert AllocationIDPreviouslyClaimed(sender, allocationID);
        }
        verifyProof(proof, sender, allocationID);

        _sendersUsedAllocationIDs[sender][allocationID] = true;
        emit AllocationIDUsed(sender, allocationID);
    }

    /**
     * @dev Verifies a proof.
     * @param proof ECDSA Proof signed by the receiver's allocationID consisting of packed (sender address, allocationID, collateral contract address).
     * @param sender The sender of the token to receiver.
     * @param allocationID The allocation ID to verify.
     * @notice REVERT with error:
     *               - InvalidProof: If the proof is not valid
     */
    function verifyProof(
        bytes calldata proof,
        address sender,
        address allocationID
    ) private view {
        bytes32 messageHash = keccak256(
            abi.encodePacked(sender, allocationID, msg.sender)
        );
        bytes32 digest = ECDSA.toEthSignedMessageHash(messageHash);
        if (ECDSA.recover(digest, proof) != allocationID) {
            revert InvalidProof();
        }
    }
}
