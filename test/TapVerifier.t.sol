// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import "forge-std/console.sol";

contract TAPVerifierTest is Test {
    TAPVerifier internal tap_verifier;
    bytes32 private constant _EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    uint256 internal signerPrivateKey;

    address internal signer;

    function setUp() public {
        tap_verifier = new TAPVerifier();
        bytes memory code = address(tap_verifier).code;
        address targetAddr = address(1);
        vm.etch(targetAddr, code);

        string memory signerMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        signerPrivateKey = vm.deriveKey(signerMnemonic, 0);

        signer = vm.addr(signerPrivateKey);
    }

    function testRecoverSignature() public {
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            158
        );
        bytes32 digest = tap_verifier.hashRAV(rav);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        address recovered_signer = tap_verifier.recoverRAVSigner(signed_rav);
        assertEq(recovered_signer, signer);
    }


    /**
     * @notice Uses RAV sampled from rust TAP Library
     */
    function testSampledValidRAV() public {
        // Sampled RAV and signature (created using same Mnemonic for signer, same signer is shared)
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            158
        );
        // Sampled RAV Signature
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        address recovered_signer = tap_verifier.recoverRAVSigner(signed_rav);
        assertEq(recovered_signer, signer);
    }

        /**
     * @notice Uses RAV sampled from rust TAP Library and changes
     */
    function testSampledRAVInvalidAllocationID() public {
        // Sampled RAV with invalid value
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            // Updating the value that was actually signed to an arbitrary invalid value
            // Changed from address(0x1), to:
            address(0x2),
            10,
            158
        );
        // Sampled RAV Signature (signed for the RAV before it was changed)
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);
        // Recovered singer should not be the same as actual signer since the RAV is invalid
        assertFalse(recovered_signer == signer);
    }

    function testSampledRAVInvalidTimestamp() public {
        // Sampled RAV with invalid value
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            // Updating the value that was actually signed to an arbitrary invalid value
            // Changed from 10, to:
            20,
            158
        );
        // Sampled RAV Signature (signed for the RAV before it was changed)
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);
        // Recovered singer should not be the same as actual signer since the RAV is invalid
        assertFalse(recovered_signer == signer);
    }

    function testSampledRAVInvalidValueAggregate() public {
        // Sampled RAV with invalid value
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            // Updating the value that was actually signed to an arbitrary invalid value
            // Changed from 158, to:
            200
        );
        // Sampled RAV Signature (signed for the RAV before it was changed)
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);
        // Recovered singer should not be the same as actual signer since the RAV is invalid
        assertFalse(recovered_signer == signer);
    }

}