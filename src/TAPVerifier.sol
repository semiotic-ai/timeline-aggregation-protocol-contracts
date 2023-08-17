// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title TAPVerifier
 * @dev A contract for verifying receipt aggregation vouchers.
 */
contract TAPVerifier is EIP712 {
    struct ReceiptAggregateVoucher {
        address allocationId;
        uint64 timestampNs;
        uint128 valueAggregate;
    }

    struct SignedRAV {
        ReceiptAggregateVoucher rav;
        bytes signature; // 65 bytes: r (32 Bytes) || s (32 Bytes) || v (1 Byte)
    }

    // --- EIP 712 ---
    bytes32 private constant RAV_TYPEHASH =
        keccak256(
            "ReceiptAggregateVoucher(address allocationId,uint64 timestampNs,uint128 valueAggregate)"
        );

    /**
     * @dev Constructs a new instance of the TAPVerifier contract.
     */
    constructor(string memory name, string memory version) EIP712(name, version) {}

    /**
     * @dev Recovers the signer address of a signed ReceiptAggregateVoucher (RAV).
     * @param signedRAV The SignedRAV containing the RAV and its signature.
     * @return The address of the signer.
     * @notice REVERT: This function may revert if ECDSA.recover fails, check ECDSA library for details.
     */
    function recoverRAVSigner(
        SignedRAV calldata signedRAV
    ) public view returns (address) {
        bytes32 messageHash = hashRAV(signedRAV.rav);
        return ECDSA.recover(messageHash, signedRAV.signature);
    }

    /**
     * @dev Compares address recovered from signature to provided address.
     * @param signedRAV The SignedRAV containing the RAV and its signature.
     * @param expectedAddress The address to compare the recovered address to.
     * @return True if the recovered address matches the provided address, false otherwise.
     * @notice REVERT: This function may revert if ECDSA.recover fails, check ECDSA library for details.
     */
    function verifyRAVSignature(
        SignedRAV calldata signedRAV,
        address expectedAddress
    ) external view returns (bool) {
        return recoverRAVSigner(signedRAV) == expectedAddress;
    }

    /**
     * @dev Computes the hash of a ReceiptAggregateVoucher (RAV).
     * @param rav The RAV for which to compute the hash.
     * @return The hash of the RAV.
     */
    function hashRAV(
        ReceiptAggregateVoucher calldata rav
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        RAV_TYPEHASH,
                        rav.allocationId,
                        rav.timestampNs,
                        rav.valueAggregate
                    )
                )
            );
    }
}
