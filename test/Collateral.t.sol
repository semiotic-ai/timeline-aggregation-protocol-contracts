// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import {Collateral} from "../src/Collateral.sol";
import {MockERC20Token} from "./MockERC20Token.sol";

contract CollateralContractTest is Test {
    address private constant RECEIVER_ADDRESS = address(0x123);
    address private constant SENDER_ADDRESS = address(0x789);
    uint256 private constant COLLATERAL_AMOUNT = 1000;
    uint256 private constant FREEZE_PERIOD = 800;

    MockERC20Token private mockERC20;
    Collateral private collateralContract;
    TAPVerifier private tap_verifier;

    uint256 internal authorizedSignerPrivateKey;
    address internal authorizedsigner;

    function setUp() public {
        // Create an instance of the TAPVerifier contract
        tap_verifier = new TAPVerifier();

        // set up mock ERC20 token
        mockERC20 = new MockERC20Token(1000000000);

        // give sender tokens
        assert(mockERC20.transfer(SENDER_ADDRESS, 10000000));

        collateralContract = new Collateral(address(mockERC20), address(tap_verifier), FREEZE_PERIOD);

        // Set up the signer to be authorized for signing rav's
        string memory signerMnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        authorizedSignerPrivateKey = vm.deriveKey(signerMnemonic, 0);
        authorizedsigner = vm.addr(authorizedSignerPrivateKey);

        // label all known addresses for debugging
        vm.label(SENDER_ADDRESS, "SENDER_ADDRESS");
        vm.label(RECEIVER_ADDRESS, "RECEIVER_ADDRESS");
        vm.label(address(collateralContract), "collateralContract");
        vm.label(address(mockERC20), "mockERC20");
        vm.label(address(tap_verifier), "tap_verifier");
    }

    function testDepositFunds() public {
        depositCollateral(SENDER_ADDRESS, RECEIVER_ADDRESS, COLLATERAL_AMOUNT);

        vm.prank(SENDER_ADDRESS);
        uint256 depositedAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS);

        assertEq(depositedAmount, COLLATERAL_AMOUNT, "Incorrect deposited amount");
    }

    function testWithdrawFundsAfterFreezePeriod() public {
        depositCollateral(SENDER_ADDRESS, RECEIVER_ADDRESS, COLLATERAL_AMOUNT);

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        collateralContract.thawCollateral(RECEIVER_ADDRESS, COLLATERAL_AMOUNT);

        // Simulate passing the freeze period
        vm.roll(block.number + FREEZE_PERIOD + 1);

        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        collateralContract.withdrawThawedCollateral(RECEIVER_ADDRESS);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, COLLATERAL_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    function testRedeemRAVSignedByAuthorizedSigner() public {
        depositCollateral(SENDER_ADDRESS, RECEIVER_ADDRESS, COLLATERAL_AMOUNT);
        uint256 remainingCollateral = collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS);
        assertEq(remainingCollateral, COLLATERAL_AMOUNT, "Incorrect remaining collateral");

        // Authorize the signer
        vm.prank(SENDER_ADDRESS);
        collateralContract.authorizeSigner(authorizedsigner);

        // Create a RAV
        uint128 RAVAggregateAmount = 158;
        TAPVerifier.ReceiptAggregationVoucher memory rav =
            TAPVerifier.ReceiptAggregationVoucher(address(0x1), 10, RAVAggregateAmount);
        bytes32 digest = tap_verifier.hashRAV(rav);

        // Sign the digest using the authorized signer's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(authorizedSignerPrivateKey, digest);

        // Create a SignedRAV structure with the RAV and its signature
        TAPVerifier.SignedRAV memory signed_rav = TAPVerifier.SignedRAV(rav, abi.encodePacked(r, s, v));

        // get number of tokens in receiver's account before redeeming
        uint256 receiverBalance = mockERC20.balanceOf(RECEIVER_ADDRESS);

        // Receiver redeems value from the SignedRAV, expect receiver grt amount to increase
        vm.prank(RECEIVER_ADDRESS);
        collateralContract.redeem(signed_rav);

        remainingCollateral -= RAVAggregateAmount;

        assertEq(
            collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS),
            remainingCollateral,
            "Incorrect remaining collateral"
        );

        // get number of tokens in receiver's account after redeeming and check that it increased by the RAV amount
        uint256 receiverBalanceAfter = mockERC20.balanceOf(RECEIVER_ADDRESS);
        assertEq(
            receiverBalanceAfter, receiverBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming"
        );
    }

    function testGetCollateralAmount() public {
        depositCollateral(SENDER_ADDRESS, RECEIVER_ADDRESS, COLLATERAL_AMOUNT);

        uint256 depositedAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS);
        assertEq(depositedAmount, COLLATERAL_AMOUNT, "Incorrect deposited amount");
    }

    function depositCollateral(address sender, address receiver, uint256 amount) public {
        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(sender);
        // Approve the collateral contract to transfer tokens from the sender
        mockERC20.approve(address(collateralContract), amount);
        collateralContract.depositCollateral(receiver, amount);
        vm.stopPrank();
    }

    function testMultipleThawRequests() public {
        depositCollateral(SENDER_ADDRESS, RECEIVER_ADDRESS, COLLATERAL_AMOUNT);
        uint256 partialCollateralAmount = COLLATERAL_AMOUNT / 10;
        uint256 partialFreezePeriod = FREEZE_PERIOD / 10;

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);

        for (uint256 i = 0; i < 10; i++) {
            // Sets msg.sender address for next contract calls until stop is called
            collateralContract.thawCollateral(RECEIVER_ADDRESS, partialCollateralAmount);

            // Simulate passing partial freeze period
            vm.roll(block.number + partialFreezePeriod);
        }

        // expected to revert because not enough time has passed since the last thaw request
        vm.expectRevert("Collateral still thawing");
        collateralContract.withdrawThawedCollateral(RECEIVER_ADDRESS);

        vm.roll(block.number + FREEZE_PERIOD);
        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        collateralContract.withdrawThawedCollateral(RECEIVER_ADDRESS);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, COLLATERAL_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = collateralContract.getCollateralAmount(SENDER_ADDRESS, RECEIVER_ADDRESS);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }
}
