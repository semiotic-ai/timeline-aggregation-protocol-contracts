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

        // Set up the signer for testing purposes
        string memory signerMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        signerPrivateKey = vm.deriveKey(signerMnemonic, 0);
        signer = vm.addr(signerPrivateKey);
    }

    /**
     * @notice Test case for recovering the signer from a signed ReceiptAggregationVoucher (RAV).
     */
    function testRecoverSignature() public {
        // Create a sample ReceiptAggregationVoucher (RAV)
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            158
        );

        // Compute the digest of the RAV
        bytes32 digest = tap_verifier.hashRAV(rav);

        // Sign the digest using the signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        // Create a SignedRAV structure with the RAV and its signature
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        // Recover the signer address from the signed RAV
        address recovered_signer = tap_verifier.recoverRAVSigner(signed_rav);

        // Assert that the recovered signer matches the expected signer address
        assertEq(recovered_signer, signer);
    }

    /**
     * @notice Test case using a sampled valid ReceiptAggregationVoucher (RAV) and its signature.
     */
    function testSampledValidRAV() public {
        // Sampled RAV and signature (created using the same mnemonic for the signer)
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            158
        );
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        // Recover the signer address from the signed RAV
        address recovered_signer = tap_verifier.recoverRAVSigner(signed_rav);

        // Assert that the recovered signer matches the expected signer address
        assertEq(recovered_signer, signer);
    }

    /**
     * @notice Test case using a sampled RAV with an invalid allocation ID.
     */
    function testSampledRAVInvalidAllocationID() public {
        // Sampled RAV with invalid allocation ID
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x2), // Invalid allocation ID
            10,
            158
        );
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        // Recover the signer address from the signed RAV
        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);

        // Assert that the recovered signer is not the same as the expected signer address
        assertFalse(recovered_signer == signer);
    }

    /**
     * @notice Test case using a sampled RAV with an invalid timestamp.
     */
    function testSampledRAVInvalidTimestamp() public {
        // Sampled RAV with invalid timestamp
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            20, // Invalid timestamp
            158
        );
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        // Recover the signer address from the signed RAV
        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);

        // Assert that the recovered signer is not the same as the expected signer address
        assertFalse(recovered_signer == signer);
    }

    /**
     * @notice Test case using a sampled RAV with an invalid value aggregate.
     */
    function testSampledRAVInvalidValueAggregate() public {
        // Sampled RAV with invalid value aggregate
        TAPVerifier.ReceiptAggregationVoucher memory invalid_rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            200 // Invalid value aggregate
        );
        (uint8 v, bytes32 r, bytes32 s) = (
            27,
            0x6a18671465401bf0003b88048eccefaa7c6961168d2dfd3d12b9485cb857ddca,
            0x14b662a328daf6658364935b1f33e807b7b9f196cf51d1027038b82877cef07e
        );
        TAPVerifier.SignedRAV memory signed_invalid_rav = TAPVerifier.SignedRAV(invalid_rav, abi.encodePacked(r, s, v));

        // Recover the signer address from the signed RAV
        address recovered_signer = tap_verifier.recoverRAVSigner(signed_invalid_rav);

        // Assert that the recovered signer is not the same as the expected signer address
        assertFalse(recovered_signer == signer);
    }

    /**
     * @notice Test case for an invalid signature.
     * The test creates a sample ReceiptAggregationVoucher (RAV) and an invalid signature (tampered with or incorrect).
     * It then attempts to recover the signer address from the signed RAV, expecting a revert due to the invalid signature.
     */
    function testInvalidSignature() public {
        // Create a sample ReceiptAggregationVoucher (RAV)
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            10,
            158
        );

        // Create an invalid signature (e.g., tampered with or incorrect)
        (uint8 v, bytes32 r, bytes32 s) = (27, bytes32(0), bytes32(0));

        // Create a SignedRAV structure with the RAV and the invalid signature
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        // Expect a revert with the message "ECDSA: invalid signature"
        vm.expectRevert("ECDSA: invalid signature");
        tap_verifier.recoverRAVSigner(signed_rav);
    }

    /**
     * @notice Test case for the edge scenario with minimum values for timestamp_ns and value_aggregate in ReceiptAggregationVoucher.
     * The test creates a ReceiptAggregationVoucher with minimum values and signs it.
     * It then recovers the signer address from the signed RAV and asserts that it matches the expected signer address.
     */
    function testEdgeCaseMinValuedRav() public {
        // Test with minimum values for timestamp_ns and value_aggregate
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            0,
            0
        );
        bytes32 digest1 = tap_verifier.hashRAV(rav);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signerPrivateKey, digest1);
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r1, s1, v1));
        address recovered_signer1 = tap_verifier.recoverRAVSigner(signed_rav);
        assertEq(recovered_signer1, signer);
    }

    /**
     * @notice Test case for the edge scenario with maximum values for timestamp_ns and value_aggregate in ReceiptAggregationVoucher.
     * The test creates a ReceiptAggregationVoucher with maximum values and signs it.
     * It then recovers the signer address from the signed RAV and asserts that it matches the expected signer address.
     */
    function testEdgeCaseMaxValuedRav() public {
        // Test with maximum values for timestamp_ns and value_aggregate
        TAPVerifier.ReceiptAggregationVoucher memory rav = TAPVerifier.ReceiptAggregationVoucher(
            address(0x1),
            type(uint64).max,
            type(uint128).max
        );
        bytes32 digest2 = tap_verifier.hashRAV(rav);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signerPrivateKey, digest2);
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r2, s2, v2));
        address recovered_signer2 = tap_verifier.recoverRAVSigner(signed_rav);
        assertEq(recovered_signer2, signer);
    }
}