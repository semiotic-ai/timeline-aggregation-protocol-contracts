// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import {Collateral} from "../src/Collateral.sol";
import {MockERC20Token} from "./MockERC20Token.sol";
import {AllocationIDTracker} from "../src/AllocationIDTracker.sol";

contract CollateralContractTest is Test {
    address private constant SENDER_ADDRESS = address(0x789);
    uint256 private constant COLLATERAL_AMOUNT = 1000;
    uint256 private constant FREEZE_PERIOD = 800;

    MockERC20Token private mockERC20;
    Collateral private collateralContract;
    TAPVerifier private tap_verifier;

    uint256[] internal authorizedSignerPrivateKeys;
    address[] internal authorizedsigners;

    uint256 internal receiverPrivateKey;
    uint256 internal receiversAllocationIDPrivateKey;
    address internal receiverAddress;
    address internal receiversAllocationID;

    function setUp() public {
        // Create an instance of the TAPVerifier contract
        tap_verifier = new TAPVerifier();

        // set up mock ERC20 token
        mockERC20 = new MockERC20Token(1000000000);

        // set up allocation ID tracker
        AllocationIDTracker allocationIDTracker = new AllocationIDTracker();

        // give sender tokens
        assert(mockERC20.transfer(SENDER_ADDRESS, 10000000));

        collateralContract =
            new Collateral(address(mockERC20), address(tap_verifier), address(allocationIDTracker), FREEZE_PERIOD);

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

        // Derive the allocation ID from the receiver Mneumonic
        receiversAllocationIDPrivateKey = vm.deriveKey(receiverMnemonic, 1);
        receiversAllocationID = vm.addr(receiversAllocationIDPrivateKey);

        // label all known addresses for debugging
        vm.label(SENDER_ADDRESS, "SENDER_ADDRESS");
        vm.label(receiverAddress, "receiver");
        vm.label(receiversAllocationID, "receiversAllocationID");
        vm.label(authorizedsigners[0], "authorizedsigner_0");
        vm.label(authorizedsigners[1], "authorizedsigner_1");
        vm.label(address(collateralContract), "collateralContract");
        vm.label(address(mockERC20), "mockERC20");
        vm.label(address(tap_verifier), "tap_verifier");
    }

    function testDepositFunds() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);

        vm.prank(SENDER_ADDRESS);
        uint256 depositedAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);

        assertEq(depositedAmount, COLLATERAL_AMOUNT, "Incorrect deposited amount");
    }

    function testWithdrawFundsAfterFreezePeriod() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        collateralContract.thaw(receiverAddress, COLLATERAL_AMOUNT);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + FREEZE_PERIOD + 1);

        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        collateralContract.withdraw(receiverAddress);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, COLLATERAL_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    function testRedeemRAVSignedByAuthorizedSigner() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);
        uint256 remainingCollateral = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingCollateral, COLLATERAL_AMOUNT, "Incorrect remaining collateral");

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = 158;
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationID, timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // get number of tokens in receiver's account before redeeming
        uint256 receiverBalance = mockERC20.balanceOf(receiverAddress);

        // create proof of allocationID ownership
        bytes memory proof = createAllocationIDOwnershipProof(receiversAllocationID, receiversAllocationIDPrivateKey);

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        vm.prank(receiverAddress);
        collateralContract.redeem(signed_rav, proof);

        remainingCollateral -= RAVAggregateAmount;

        assertEq(
            collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress),
            remainingCollateral,
            "Incorrect remaining collateral"
        );

        // get number of tokens in receiver's account after redeeming and check that it increased by the RAV amount
        uint256 receiverBalanceAfter = mockERC20.balanceOf(receiverAddress);
        assertEq(
            receiverBalanceAfter, receiverBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming"
        );
    }

    function testGetCollateralAmount() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);

        uint256 depositedAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(depositedAmount, COLLATERAL_AMOUNT, "Incorrect deposited amount");
    }

    function testMultipleThawRequests() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);
        uint256 partialCollateralAmount = COLLATERAL_AMOUNT / 10;
        uint256 partialFreezePeriod = FREEZE_PERIOD / 10;

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);

        for (uint256 i = 0; i < 10; i++) {
            // Sets msg.sender address for next contract calls until stop is called
            collateralContract.thaw(receiverAddress, partialCollateralAmount);

            // Simulate passing partial freeze period
            vm.warp(block.timestamp + partialFreezePeriod);
        }

        // expected to revert because not enough time has passed since the last thaw request
        vm.expectRevert("Collateral still thawing");
        collateralContract.withdraw(receiverAddress);

        vm.warp(block.timestamp + FREEZE_PERIOD);
        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        collateralContract.withdraw(receiverAddress);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, COLLATERAL_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    // test that the contract reverts when allocation ID is used more than once
    function testRevertOnDuplicateAllocationID() public {
        depositCollateral(SENDER_ADDRESS, receiverAddress, COLLATERAL_AMOUNT);
        uint256 remainingCollateral = collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress);
        assertEq(remainingCollateral, COLLATERAL_AMOUNT, "Incorrect remaining collateral");

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = 158;
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationID, timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // get number of tokens in receiver's account before redeeming
        uint256 receiverBalance = mockERC20.balanceOf(receiverAddress);

        // create proof of allocationID ownership
        bytes memory proof = createAllocationIDOwnershipProof(receiversAllocationID, receiversAllocationIDPrivateKey);

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        vm.prank(receiverAddress);
        collateralContract.redeem(signed_rav, proof);

        remainingCollateral -= RAVAggregateAmount;

        // get number of tokens in receiver's account after redeeming and check that it increased by the RAV amount
        uint256 receiverBalanceAfter = mockERC20.balanceOf(receiverAddress);
        assertEq(
            receiverBalanceAfter, receiverBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming"
        );

        assertEq(
            collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress),
            remainingCollateral,
            "Incorrect remaining amount"
        );

        // expect revert when trying to redeem with the same allocation ID
        vm.expectRevert("Allocation ID already used");
        vm.prank(receiverAddress);
        collateralContract.redeem(signed_rav, proof);

        // remaining collateral should not have changed
        assertEq(
            collateralContract.getCollateralAmount(SENDER_ADDRESS, receiverAddress),
            remainingCollateral,
            "Incorrect remaining amount"
        );
    }

    function authorizeSignerWithProof(address sender, uint256 signerPivateKey, address signer) private {
        bytes memory authSignerAuthorizesSenderProof = createAuthorizedSignerProof(sender, signerPivateKey);

        // Authorize the signer
        vm.prank(sender);
        collateralContract.authorizeSigner(signer, authSignerAuthorizesSenderProof);
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

    function createAllocationIDOwnershipProof(address allocationID, uint256 allocationIDPrivateKey)
        private
        pure
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(allocationID));
        bytes32 allocationIDdigest = ECDSA.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(allocationIDPrivateKey, allocationIDdigest);
        return abi.encodePacked(r, s, v);
    }

    function depositCollateral(address sender, address receiver, uint256 amount) public {
        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(sender);
        // Approve the collateral contract to transfer tokens from the sender
        mockERC20.approve(address(collateralContract), amount);
        collateralContract.deposit(receiver, amount);
        vm.stopPrank();
    }

    function createSignedRAV(
        address allocationID,
        uint64 timestampNs,
        uint128 aggregateAmount,
        uint256 authorizedSignerPrivateKey
    ) private view returns (TAPVerifier.SignedRAV memory) {
        // Create a RAV
        TAPVerifier.ReceiptAggregationVoucher memory rav =
            TAPVerifier.ReceiptAggregationVoucher(allocationID, timestampNs, aggregateAmount);
        bytes32 digest = tap_verifier.hashRAV(rav);

        // Sign the digest using the authorized signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPrivateKey, digest);

        // Create a SignedRAV structure with the RAV and its signature
        return TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));
    }
}
