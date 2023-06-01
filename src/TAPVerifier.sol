// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";


/**
 * @title TAPVerifier
 * @dev A contract for verifying receipt aggregation vouchers.
 */
contract TAPVerifier is EIP712 {
    struct ReceiptAggregationVoucher {
        address allocationID;
        uint64 timestamp_ns;
        uint128 value_aggregate;
    }

    struct SignedRAV {
        ReceiptAggregationVoucher rav;
        bytes signature; // 65 bytes: r (32 Bytes) || s (32 Bytes) || v (1 Byte)
    }

    // --- EIP 712 ---
    bytes32 private constant RAV_TYPEHASH =
        keccak256("ReceiptAggregateVoucher(address allocationId,uint64 timestampNs,uint128 valueAggregate)");

    /**
     * @dev Constructs a new instance of the TAPVerifier contract.
     */
    constructor() EIP712("TAP", "1.0.0") {}
    /**
     * @dev Recovers the signer address of a signed ReceiptAggregationVoucher (RAV).
     * @param _signedRAV The SignedRAV containing the RAV and its signature.
     * @return The address of the signer.
     */
    function recoverRAVSigner(SignedRAV memory _signedRAV) public view returns (address) {
        bytes32 messageHash = hashRAV(_signedRAV.rav);
        return ECDSA.recover(messageHash, _signedRAV.signature);
    }

    /**
     * @dev Computes the hash of a ReceiptAggregationVoucher (RAV).
     * @param _rav The RAV for which to compute the hash.
     * @return The hash of the RAV.
     */
    function hashRAV(ReceiptAggregationVoucher memory _rav) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RAV_TYPEHASH,
                    _rav.allocationID,
                    _rav.timestamp_ns,
                    _rav.value_aggregate
                )
            )
        );
    }
}