// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import {Escrow} from "../src/Escrow.sol";
import {MockERC20Token} from "./MockERC20Token.sol";
import {AllocationIDTracker} from "../src/AllocationIDTracker.sol";
import {MockStaking} from "./MockStaking.sol";

contract EscrowContractTest is Test {
    address private constant SENDER_ADDRESS = address(0x789);
    uint256 private constant ESCROW_AMOUNT = 1000;
    uint256 private constant WITHDRAW_ESCROW_FREEZE_PERIOD = 800;
    uint256 private constant REVOKE_SIGNER_FREEZE_PERIOD = 800;

    MockERC20Token private mockERC20;
    MockStaking private staking;
    Escrow private escrowContract;
    TAPVerifier private tap_verifier;

    uint256[] internal authorizedSignerPrivateKeys;
    address[] internal authorizedsigners;

    uint256 internal receiverPrivateKey;
    uint256[] internal receiversAllocationIDPrivateKeys;
    address internal receiverAddress;
    address[] internal receiversAllocationIDs;

    function setUp() public {
        // Create an instance of the TAPVerifier contract
        tap_verifier = new TAPVerifier("TAP", "1.0.0");

        // set up mock ERC20 token
        mockERC20 = new MockERC20Token(1000000000);

        // set up staking contract
        staking = new MockStaking(address(mockERC20));

        // set up allocation ID tracker
        AllocationIDTracker allocationIDTracker = new AllocationIDTracker();

        // give sender tokens
        assert(mockERC20.transfer(SENDER_ADDRESS, 10000000));

        escrowContract =
        new Escrow(address(mockERC20), address(staking), address(tap_verifier), address(allocationIDTracker), WITHDRAW_ESCROW_FREEZE_PERIOD, REVOKE_SIGNER_FREEZE_PERIOD);

        // Approve staking contract to transfer tokens from the escrow contract
        escrowContract.approveAll();

        // Set up the signer to be authorized for signing rav's
        string memory signerMnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        authorizedSignerPrivateKeys.push(vm.deriveKey(signerMnemonic, 0));
        authorizedsigners.push(vm.addr(authorizedSignerPrivateKeys[0]));

        // Set up the signer to be authorized for signing rav's
        string memory secondSignerMnemonic =
            "thunder proof mule record purity unfair jump light limb ozone fade gift stay reduce menu";
        authorizedSignerPrivateKeys.push(vm.deriveKey(secondSignerMnemonic, 0));
        authorizedsigners.push(vm.addr(authorizedSignerPrivateKeys[1]));

        // Set up the receiver address and derive the allocation ID
        string memory receiverMnemonic =
            "betray tornado relax hold february impact rain run nut frown bag this gravity amused math";
        receiverPrivateKey = vm.deriveKey(receiverMnemonic, 0);
        receiverAddress = vm.addr(receiverPrivateKey);

        // Derive the allocation IDs from the receiver Mneumonic
        receiversAllocationIDPrivateKeys.push(vm.deriveKey(receiverMnemonic, 1));
        receiversAllocationIDs.push(vm.addr(receiversAllocationIDPrivateKeys[0]));

        receiversAllocationIDPrivateKeys.push(vm.deriveKey(receiverMnemonic, 2));
        receiversAllocationIDs.push(vm.addr(receiversAllocationIDPrivateKeys[1]));

        // label all known addresses for debugging
        vm.label(SENDER_ADDRESS, "SENDER_ADDRESS");
        vm.label(receiverAddress, "receiver");
        vm.label(receiversAllocationIDs[0], "receiversAllocationID");
        vm.label(authorizedsigners[0], "authorizedsigner_0");
        vm.label(authorizedsigners[1], "authorizedsigner_1");
        vm.label(address(escrowContract), "escrowContract");
        vm.label(address(mockERC20), "mockERC20");
        vm.label(address(tap_verifier), "tap_verifier");
    }

    function testDepositFunds() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);

        vm.prank(SENDER_ADDRESS);
        uint256 depositedAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);

        assertEq(depositedAmount, ESCROW_AMOUNT, "Incorrect deposited amount");
    }

    function testWithdrawFundsAfterFreezePeriod() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiverAddress, ESCROW_AMOUNT);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD + 1);

        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        escrowContract.withdraw(receiverAddress);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, ESCROW_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    function testRedeemRAVSignedByAuthorizedSigner() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);
        uint256 remainingEscrow = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingEscrow, ESCROW_AMOUNT, "Incorrect remaining escrow");

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = 158;
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // get number of tokens in staking contract account before redeeming
        uint256 stakingBalance = mockERC20.balanceOf(address(staking));

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        remainingEscrow -= RAVAggregateAmount;

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress),
            remainingEscrow,
            "Incorrect remaining escrow"
        );

        // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
        uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
        assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");
    }

        function testRedeemRAVWithValueGreaterThanAvailableEscrow() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = 2 * uint128(ESCROW_AMOUNT);
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // get number of tokens in staking contract account before redeeming
        uint256 stakingBalance = mockERC20.balanceOf(address(staking));

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress),
            uint128(0),
            "Incorrect remaining escrow"
        );

        // get number of tokens in staking contract account after redeeming and check that it increased by the amount of remaining sender escrow
        uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
        assertEq(stakingBalanceAfter, stakingBalance + ESCROW_AMOUNT, "Incorrect receiver balance after redeeming");
    }

    function testGetEscrowAmount() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);

        uint256 depositedAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(depositedAmount, ESCROW_AMOUNT, "Incorrect deposited amount");
    }

    function testMultipleThawRequests() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);
        uint256 partialEscrowAmount = ESCROW_AMOUNT / 10;
        uint256 partialFreezePeriod = WITHDRAW_ESCROW_FREEZE_PERIOD / 10;
        uint256 expectedThawEnd = 0;

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);

        for (uint256 i = 0; i < 10; i++) {
            // Sets msg.sender address for next contract calls until stop is called
            escrowContract.thaw(receiverAddress, partialEscrowAmount);
            expectedThawEnd = block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD;

            // Simulate passing partial freeze period
            vm.warp(block.timestamp + partialFreezePeriod);
        }

        // expected to revert because not enough time has passed since the last thaw request
        vm.expectRevert(abi.encodeWithSignature("EscrowStillThawing(uint256,uint256)", block.timestamp, expectedThawEnd));
        escrowContract.withdraw(receiverAddress);

        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD);
        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        escrowContract.withdraw(receiverAddress);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, ESCROW_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    // test that the contract reverts when allocation ID is used more than once
    function testRevertOnDuplicateAllocationID() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);
        uint256 remainingEscrow = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingEscrow, ESCROW_AMOUNT, "Incorrect remaining escrow");

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = 158;
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // get number of tokens in staking contract account before redeeming
        uint256 stakingBalance = mockERC20.balanceOf(address(staking));

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        remainingEscrow -= RAVAggregateAmount;

        // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
        uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
        assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress),
            remainingEscrow,
            "Incorrect remaining amount"
        );

        // expect revert when trying to redeem with the same allocation ID
        vm.expectRevert(abi.encodeWithSignature("AllocationIDPreviouslyClaimed(address,address)", SENDER_ADDRESS, receiversAllocationIDs[0]));
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        // remaining escrow should not have changed
        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiverAddress),
            remainingEscrow,
            "Incorrect remaining amount"
        );

        // create additional sender address to test that the contract does not revert when redeeming same allocation ID with a different sender
        address secondSenderAddress = address(0xa789);
        assert(mockERC20.transfer(secondSenderAddress, 10000000));
        depositEscrow(secondSenderAddress, receiverAddress, ESCROW_AMOUNT);

        // should not revert when redeeming same allocationID with a different sender
        authorizeSignerWithProof(secondSenderAddress, authorizedSignerPrivateKeys[1], authorizedsigners[1]);

        // Create a RAV with same allocation ID but different signer/sender
        TAPVerifier.SignedRAV memory second_signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[1]);

        // get number of tokens in staking contract account before redeeming
        stakingBalance = mockERC20.balanceOf(address(staking));

        // should be able to redeem since the (sender, allocation ID) pair is unused
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            secondSenderAddress,
            address(escrowContract),
            second_signed_rav
        );

        // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
        stakingBalanceAfter = mockERC20.balanceOf(address(staking));
        assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");
    }

    function testRevokeAuthorizedSigner() public {
        depositEscrow(SENDER_ADDRESS, receiverAddress, ESCROW_AMOUNT);

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);
        vm.prank(SENDER_ADDRESS);
        escrowContract.thawSigner(authorizedsigners[0]);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + REVOKE_SIGNER_FREEZE_PERIOD + 1);

        // Create a rav signed by signer that is thawed for revocation
        uint128 RAVAggregateAmount = 158;
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // RAV's signed by authorized signer should still be valid until signer is revoked
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        vm.prank(SENDER_ADDRESS);
        escrowContract.revokeAuthorizedSigner(authorizedsigners[0]);

        // expect revert when trying to redeem rav signed by revoked signer

        // Create a rav signed by revoked signer
        signed_rav =
            createSignedRAV(receiversAllocationIDs[1], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[1]);

        vm.expectRevert(Escrow.InvalidRAVSigner.selector);
        redeemSignedRAV(
            receiversAllocationIDs[1],
            receiversAllocationIDPrivateKeys[1],
            receiverAddress,
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );
    }

    function authorizeSignerWithProof(address sender, uint256 signerPivateKey, address signer) private {
        bytes memory authSignerAuthorizesSenderProof = createAuthorizedSignerProof(sender, signerPivateKey);

        // Authorize the signer
        vm.prank(sender);
        escrowContract.authorizeSigner(signer, authSignerAuthorizesSenderProof);
    }

    function createAuthorizedSignerProof(address sender, uint256 signerPrivateKey)
        private
        pure
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(sender));
        bytes32 allocationIDdigest = ECDSA.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, allocationIDdigest);
        return abi.encodePacked(r, s, v);
    }

    function createAllocationIDOwnershipProof(
        address allocationID,
        address sender,
        address escrowContractAddress,
        uint256 allocationIDPrivateKey
    ) private pure returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked(sender, allocationID, escrowContractAddress));
        bytes32 allocationIDdigest = ECDSA.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(allocationIDPrivateKey, allocationIDdigest);
        return abi.encodePacked(r, s, v);
    }

    function depositEscrow(address sender, address receiver, uint256 amount) public {
        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(sender);
        // Approve the escrow contract to transfer tokens from the sender
        mockERC20.approve(address(escrowContract), amount);
        escrowContract.deposit(receiver, amount);
        vm.stopPrank();
    }

    function createSignedRAV(
        address allocationID,
        uint64 timestampNs,
        uint128 aggregateAmount,
        uint256 authorizedSignerPrivateKey
    ) private view returns (TAPVerifier.SignedRAV memory) {
        // Create a RAV
        TAPVerifier.ReceiptAggregateVoucher memory rav =
            TAPVerifier.ReceiptAggregateVoucher(allocationID, timestampNs, aggregateAmount);
        bytes32 digest = tap_verifier.hashRAV(rav);

        // Sign the digest using the authorized signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPrivateKey, digest);

        // Create a SignedRAV structure with the RAV and its signature
        return TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));
    }

    function redeemSignedRAV(
        address allocationID,
        uint256 allocationIDPrivateKey,
        address receiverAddress_,
        address senderAddress,
        address escrowContractAddress,
        TAPVerifier.SignedRAV memory signedRAV
    ) private {
        // create proof of allocationID ownership
        bytes memory proof = createAllocationIDOwnershipProof(
            allocationID, senderAddress, address(escrowContractAddress), allocationIDPrivateKey
        );
        vm.prank(receiverAddress_);
        escrowContract.redeem(signedRAV, proof);
    }
}
