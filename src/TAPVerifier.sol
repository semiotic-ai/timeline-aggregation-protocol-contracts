// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import "forge-std/console.sol";
import "forge-std/Test.sol";

contract TAPVerifier is EIP712 {
    struct ReceiptAggregationVoucher {
        address allocationID;
        uint64 timestamp_ns;
        uint128 value_aggregate;
    }

    struct SignedRAV{
        ReceiptAggregationVoucher rav;
        // 65 bytes: r (32 Bytes) || s (32 Bytes) || v (1 Byte)
        bytes signature;
    }

    // --- For EIP 712 ---
    bytes32 private constant RAV_TYPE_HASH =
        keccak256("ReceiptAggregateVoucher(address allocationId,uint64 timestampNs,uint128 valueAggregate)");


    constructor() EIP712("TAP", "1.0.0") {}

    function recoverRAVSigner(SignedRAV memory _signed_rav)public view returns(address){
        bytes32 messageHash = HashRAV(_signed_rav.rav);
        return ECDSA.recover(messageHash, _signed_rav.signature);
    }

    function HashRAV(ReceiptAggregationVoucher memory _rav)public view returns(bytes32){
        return _hashTypedDataV4(
                keccak256(
                abi.encode(
                    RAV_TYPE_HASH,
                    _rav.allocationID,
                    _rav.timestamp_ns,
                    _rav.value_aggregate
                )
            )
        );
    }
}