// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.18;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "../src/TAPVerifier.sol";
import {Escrow} from "../src/Escrow.sol";
import {MockERC20Token} from "./MockERC20Token.sol";
import {AllocationIDTracker} from "../src/AllocationIDTracker.sol";
import {MockStaking} from "./MockStaking.sol";
import {VmSafe} from "forge-std/Vm.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract EscrowContractTest is Test {
    address private constant SENDER_ADDRESS = address(0x789);

    // Arbitrary values for testing
    uint256 private constant ESCROW_AMOUNT = 1000;
    uint256 private constant INITIAL_SENDER_BALANCE = 10**23;
    uint256 private constant WITHDRAW_ESCROW_FREEZE_PERIOD = 800;
    uint256 private constant INITIAL_TOKEN_BALANCE =  10**28;
    uint256 private constant REVOKE_SIGNER_FREEZE_PERIOD = 800;
    // needs to hit minimum stake amount
    uint256 private constant STAKE_AMOUNT = 10**23;

    MockERC20Token private mockERC20;
    MockStaking private staking;
    Escrow private escrowContract;
    TAPVerifier private tap_verifier;
    AllocationIDTracker private allocationIDTracker;
    address controller;

    uint256[] internal authorizedSignerPrivateKeys;
    address[] internal authorizedsigners;

    uint256[] internal receiversPrivateKeys;
    uint256[] internal receiversAllocationIDPrivateKeys;
    address[] internal receiversAddresses;
    address[] internal receiversAllocationIDs;
    string[] internal receiversMnemonics = [
        "betray tornado relax hold february impact rain run nut frown bag this gravity amused math",
        "traffic return wide refuse sustain dirt leader end deposit flash paddle snow grit fall like",
        "diary lawsuit sign cause kiss distance segment minimum kit moment sponsor ensure plate shaft police"
    ];

    address internal deployerAddress;
    uint256 internal deployerPrivateKey;

    address governor =0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b;
    address pauseGuardian = 0x95cED938F7991cd0dFcb48F0a06a40FA1aF46EBC;

    bool runIntegrationTests = false;

    function setUp() public {
        runIntegrationTests = vm.envOr("RUN_INTEGRATION_TESTS", false);

        console.log("Generating keys...");
        generateKeys();
        console.log("Keys generated.");

        console.log("Setting up contracts...");
        deployContracts();
        console.log("Contracts set up.");

        console.log("Defining debug labels...");
        defineDebugLabels();
        console.log("Debug labels defined.");

        console.log("Approving staking contract to transfer tokens from the escrow contract...");
        escrowContract.approveAll();
        console.log("Staking contract approved.");

        console.log("Transferring tokens to sender address...");
        transferTokens();
        console.log("Tokens transferred.");

        if (runIntegrationTests) {
            console.log("Running integration test specific set up...");
            integrationTestSetup();
            console.log("Set up complete.");
        }

        console.log("creating allocation...");
        createAllocation();
        console.log("allocation created.");
    }

    function deployContracts() public {
        mockERC20 = MockERC20Token(vm.envOr("GRAPH_NODE_ADDRESS", address(mockERC20)));
        staking = MockStaking(vm.envOr("STAKING_ADDRESS", address(staking)));
        escrowContract = Escrow(vm.envOr("ESCROW_ADDRESS", address(escrowContract)));
        tap_verifier = TAPVerifier(vm.envOr("TAP_VERIFIER_ADDRESS", address(tap_verifier)));
        allocationIDTracker = AllocationIDTracker(vm.envOr("ALLOCATION_TRACKER_ADDRESS", address(allocationIDTracker)));
        controller = vm.envOr("CONTROLLER_ADDRESS", address(controller));

        vm.startPrank(deployerAddress);

        if (address(tap_verifier) == address(0x0)){
            // Create an instance of the TAPVerifier contract
            tap_verifier = new TAPVerifier("TAP", "1.0.0");
        }

        if (address(mockERC20) == address(0x0)){
            // set up mock ERC20 token
            mockERC20 = new MockERC20Token(INITIAL_TOKEN_BALANCE);
        }


        if (address(staking) == address(0x0)){
            // set up staking contract
            staking = new MockStaking(address(mockERC20));
        }

        if (address(allocationIDTracker) == address(0x0)){
            // set up allocation ID tracker
            allocationIDTracker = new AllocationIDTracker();
        }

        if (address(escrowContract) == address(0x0)){
            escrowContract =
            new Escrow(address(mockERC20), address(staking), address(tap_verifier), address(allocationIDTracker), WITHDRAW_ESCROW_FREEZE_PERIOD, REVOKE_SIGNER_FREEZE_PERIOD);
        }
        vm.stopPrank();
    }

    function generateKeys() public {
        string memory mnemonic =
            'myth like bonus scare over problem client lizard pioneer submit female collect';

        // Set up the deployer address and derive the allocation ID
        deployerPrivateKey = vm.deriveKey(mnemonic, 0);
        deployerAddress = vm.addr(deployerPrivateKey);

        // Set up the signer to be authorized for signing rav's
        authorizedSignerPrivateKeys.push(vm.deriveKey(mnemonic, 1));
        authorizedsigners.push(vm.addr(authorizedSignerPrivateKeys[0]));

        // Set up the signer to be authorized for signing rav's
        authorizedSignerPrivateKeys.push(vm.deriveKey(mnemonic, 2));
        authorizedsigners.push(vm.addr(authorizedSignerPrivateKeys[1]));

        // Set up the receiver address and derive the allocation ID
        for (uint i = 0; i < receiversMnemonics.length; i++) {
            receiversPrivateKeys.push(vm.deriveKey(receiversMnemonics[i], 0));
            receiversAddresses.push(vm.addr(receiversPrivateKeys[i]));
        }

        receiversAllocationIDPrivateKeys.push(vm.deriveKey(receiversMnemonics[0], 1));
        receiversAllocationIDs.push(vm.addr(receiversAllocationIDPrivateKeys[0]));

        receiversAllocationIDPrivateKeys.push(vm.deriveKey(receiversMnemonics[0], 2));
        receiversAllocationIDs.push(vm.addr(receiversAllocationIDPrivateKeys[1]));
    }

    function transferTokens() public{
        address tokenOwner;
        if (runIntegrationTests) {
            address graphDeployerAddress = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;
            tokenOwner = graphDeployerAddress;
        } else {
            tokenOwner = deployerAddress;
        }

        // print amount of tokens token holder has
        console.log("Token owner balance: ", mockERC20.balanceOf(tokenOwner));
        vm.prank(tokenOwner);
        assert(mockERC20.transfer(SENDER_ADDRESS, INITIAL_SENDER_BALANCE));
        vm.prank(tokenOwner);
        assert(mockERC20.transfer(receiversAddresses[0], STAKE_AMOUNT));
    }

    function defineDebugLabels() public {
        // label all known addresses for debugging
        vm.label(SENDER_ADDRESS, "SENDER_ADDRESS");
        for (uint i = 0; i < receiversAddresses.length; i++) {
            vm.label(receiversAddresses[i], string.concat("receiver", Strings.toString(i)));
        }
        vm.label(receiversAllocationIDs[0], "receiversAllocationID");
        vm.label(authorizedsigners[0], "authorizedsigner_0");
        vm.label(authorizedsigners[1], "authorizedsigner_1");

        vm.label(address(mockERC20), "mockERC20");
        vm.label(address(staking), "staking");
        vm.label(address(escrowContract), "escrowContract");
        vm.label(address(tap_verifier), "tap_verifier");
        vm.label(address(allocationIDTracker), "allocationIDTracker");
    }

    function createAllocation() public {
        // Stake tokens to create an allocation
        vm.prank(receiversAddresses[0]);
        mockERC20.approve(address(staking), STAKE_AMOUNT);
        vm.prank(receiversAddresses[0]);
        staking.stake(STAKE_AMOUNT);
        // Define arbitrary values for bytes32 and tokens
        bytes32 arbitraryBytes32 = bytes32(uint256(123));
        uint256 tokens = 1;

        bytes memory allocationIDProof = createAllocationIDProof(
            receiversAllocationIDs[0],
            receiversAddresses[0],
            receiversAllocationIDPrivateKeys[0]
        );

        // Call mock staking contract to register the allocationID to the receiver address
        vm.prank(receiversAddresses[0]);
        staking.allocate(
            arbitraryBytes32,
            tokens,
            receiversAllocationIDs[0],
            arbitraryBytes32,
            allocationIDProof
        );
    }

    function integrationTestSetup() public {
        // unpause the staking contract
        // Function selector for the `setPaused(bool)` function
        bytes4 selector = bytes4(keccak256("setPaused(bool)"));

        // Prepare the calldata (function selector + parameters)
        bytes memory data = abi.encodeWithSelector(selector, false);

        // Call the contract's function using the address and calldata
        vm.prank(pauseGuardian);
        (bool success, ) = controller.call(data);
        require(success, "Function call failed");

        address graphDeployerAddress = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;
        vm.prank(graphDeployerAddress);
        staking.setAssetHolder(address(escrowContract), true);
    }

    // test plan tags: 2-1
    function testDepositFunds() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

        vm.prank(SENDER_ADDRESS);
        uint256 depositedAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);

        assertEq(depositedAmount, ESCROW_AMOUNT, "Incorrect deposited amount");
    }

    function testDepositManyFunds() public {
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = ESCROW_AMOUNT;
        amounts[1] = ESCROW_AMOUNT*10;
        amounts[2] = ESCROW_AMOUNT*2;

        uint256 totalAmount = 0;
        for (uint i = 0; i < amounts.length; i++) {
           totalAmount += amounts[i]; 
        }

        depositManyEscrow(SENDER_ADDRESS, receiversAddresses, amounts);

        vm.prank(SENDER_ADDRESS);

        for (uint i = 0; i < receiversAddresses.length; i++) {
            uint256 depositedAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[i]);
            assertEq(depositedAmount, amounts[i], "Incorrect deposited amount");
        }
    }

    function testDepositManyFundsWithLengthMismatch() public {
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = ESCROW_AMOUNT;
        amounts[1] = ESCROW_AMOUNT;

        vm.prank(SENDER_ADDRESS);
        vm.expectRevert(Escrow.InputsLengthMismatch.selector);
        escrowContract.depositMany(receiversAddresses, amounts);
    }

    // test plan tags: 2-3, 2-4, 2-6
    function testWithdrawFundsAfterFreezePeriod() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiversAddresses[0], ESCROW_AMOUNT);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD + 1);

        // Cancel thaw and attempt to withdraw (expect revert)
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiversAddresses[0], 0);

        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        vm.expectRevert(Escrow.EscrowNotThawing.selector);
        escrowContract.withdraw(receiversAddresses[0]);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        assertEq(senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw, 0, "Incorrect removed amount");

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiversAddresses[0], ESCROW_AMOUNT);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD + 1);

        senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        escrowContract.withdraw(receiversAddresses[0]);
        senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, ESCROW_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    // test plan tags: 2-3, 2-5, 2-6, 2-7
    function testThawReduce() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiversAddresses[0], ESCROW_AMOUNT);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD + 1);

        // Cancel thaw and attempt to withdraw (expect revert)
        vm.startPrank(SENDER_ADDRESS);
        escrowContract.thaw(receiversAddresses[0], ESCROW_AMOUNT/2);
        uint256 expectedThawEnd = block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD;

        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        vm.expectRevert(abi.encodeWithSignature("EscrowStillThawing(uint256,uint256)", block.timestamp, expectedThawEnd));
        escrowContract.withdraw(receiversAddresses[0]);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        assertEq(senderBalanceBeforeWithdraw - senderBalanceAfterWithdraw, 0, "Incorrect removed amount");

        // Simulate passing the freeze period
        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD + 1);

        senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        escrowContract.withdraw(receiversAddresses[0]);
        senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, ESCROW_AMOUNT/2, "Incorrect removed amount");

        uint256 remainingAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
        assertEq(remainingAmount, ESCROW_AMOUNT/2, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    // test plan tags: 2-3, 2-6, 2-8
    function testMultipleThawRequests() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);
        uint256 partialEscrowAmount = ESCROW_AMOUNT / 10;
        uint256 partialFreezePeriod = WITHDRAW_ESCROW_FREEZE_PERIOD / 10;
        uint256 expectedThawEnd = 0;

        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(SENDER_ADDRESS);

        for (uint256 i = 0; i < 10; i++) {
            // Sets msg.sender address for next contract calls until stop is called
            escrowContract.thaw(receiversAddresses[0], partialEscrowAmount);
            expectedThawEnd = block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD;

            // Simulate passing partial freeze period
            vm.warp(block.timestamp + partialFreezePeriod);
            partialEscrowAmount += ESCROW_AMOUNT / 10;
        }

        // expected to revert because not enough time has passed since the last thaw request
        vm.expectRevert(abi.encodeWithSignature("EscrowStillThawing(uint256,uint256)", block.timestamp, expectedThawEnd));
        escrowContract.withdraw(receiversAddresses[0]);

        vm.warp(block.timestamp + WITHDRAW_ESCROW_FREEZE_PERIOD);
        uint256 senderBalanceBeforeWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);
        escrowContract.withdraw(receiversAddresses[0]);
        uint256 senderBalanceAfterWithdraw = mockERC20.balanceOf(SENDER_ADDRESS);

        uint256 removedAmount = senderBalanceAfterWithdraw - senderBalanceBeforeWithdraw;

        assertEq(removedAmount, ESCROW_AMOUNT, "Incorrect removed amount");

        uint256 remainingAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
        assertEq(remainingAmount, 0, "Incorrect remaining amount");
        // Stop setting msg.sender address for any remaining contract calls
        vm.stopPrank();
    }

    // test plan tags: 3-1, 3-5, 3-6, 4-4
    function testRevokeAuthorizedSigner() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

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
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        // Cancel thaw and attempt to revoke signer (expect revert)
        vm.prank(SENDER_ADDRESS);
        escrowContract.cancelThawSigner(authorizedsigners[0]);

        vm.prank(SENDER_ADDRESS);
        vm.expectRevert(Escrow.SignerNotThawing.selector);
        escrowContract.revokeAuthorizedSigner(authorizedsigners[0]);

        // Restart thaw and revoke signer
        vm.prank(SENDER_ADDRESS);
        escrowContract.thawSigner(authorizedsigners[0]);

        // Simulate passing the freeze period
        vm.warp(block.timestamp + REVOKE_SIGNER_FREEZE_PERIOD + 1);

        vm.prank(SENDER_ADDRESS);
        escrowContract.revokeAuthorizedSigner(authorizedsigners[0]);

        // expect revert when trying to redeem rav signed by revoked signer

        // Create a rav signed by revoked signer
        signed_rav =
            createSignedRAV(receiversAllocationIDs[1], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        vm.expectRevert(Escrow.InvalidRAVSigner.selector);
        redeemSignedRAV(
            receiversAllocationIDs[1],
            receiversAllocationIDPrivateKeys[1],
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );
    }

    function testInvalidAuthorizeSignerProof() public {
        // Uses the wrong signer private key to create the proof
        vm.expectRevert(Escrow.InvalidSignerProof.selector);
        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[1], authorizedsigners[0]);

        // Uses random bits for proof
        // create random bits for 65 byte proof
        uint256 randomBits = 0xabcdef12345678900987654321fedcba1234567890abcdef1234567890abcdef;
        uint8 v = 27;
        bytes memory invalidProof = abi.encodePacked(randomBits, randomBits, v); //65 bytes
        vm.prank(SENDER_ADDRESS);
        // expect any revert since the proof is not valid (could be invalid signer or invalid ecdsa proof)
        vm.expectRevert();
        escrowContract.authorizeSigner(authorizedsigners[0], block.timestamp+8600, invalidProof);
    }

    // test plan tags: 3-1
    function testRedeemRAVSignedByAuthorizedSigner() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);
        uint256 remainingEscrow = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
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
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        remainingEscrow -= RAVAggregateAmount;

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]),
            remainingEscrow,
            "Incorrect remaining escrow"
        );

        // the non-mocked staking contract handles collected balance differently causing this check to be invalid
        if(!runIntegrationTests){
            // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
            uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
            assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");
        }
    }

    // test plan tags: 3-1, 4-1, 4-3
        function testRedeemRAVWithValueGreaterThanAvailableEscrow() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

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
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]),
            uint128(0),
            "Incorrect remaining escrow"
        );

        if (!runIntegrationTests){
            // get number of tokens in staking contract account after redeeming and check that it increased by the amount of remaining sender escrow
            uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
            assertEq(stakingBalanceAfter, stakingBalance + ESCROW_AMOUNT, "Incorrect receiver balance after redeeming");
        }
    }

    // test plan tags:
    function testGetEscrowAmount() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

        uint256 depositedAmount = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
        assertEq(depositedAmount, ESCROW_AMOUNT, "Incorrect deposited amount");
    }

    // test that the contract reverts when allocation ID is used more than once
    // test plan tags: 3-1, 2-1, 4-1, 4-5
    function testDuplicateAllocationID() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);
        uint256 remainingEscrow = escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]);
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
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        remainingEscrow -= RAVAggregateAmount;

        // the non-mocked staking contract handles collected balance differently causing this check to be invalid
        if(!runIntegrationTests){
            // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
            uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
            assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");
        }

        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]),
            remainingEscrow,
            "Incorrect remaining amount"
        );

        // expect revert when trying to redeem with the same allocation ID
        vm.expectRevert(abi.encodeWithSignature("AllocationIDPreviouslyClaimed(address,address)", SENDER_ADDRESS, receiversAllocationIDs[0]));
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );

        // remaining escrow should not have changed
        assertEq(
            escrowContract.getEscrowAmount(SENDER_ADDRESS, receiversAddresses[0]),
            remainingEscrow,
            "Incorrect remaining amount"
        );

        // create additional sender address to test that the contract does not revert when redeeming same allocation ID with a different sender
        address secondSenderAddress = address(0xa789);
        vm.prank(deployerAddress);
        assert(mockERC20.transfer(secondSenderAddress, INITIAL_SENDER_BALANCE));
        depositEscrow(secondSenderAddress, receiversAddresses[0], ESCROW_AMOUNT);

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
            receiversAddresses[0],
            secondSenderAddress,
            address(escrowContract),
            second_signed_rav
        );

        // the non-mocked staking contract handles collected balance differently causing this check to be invalid
        if(!runIntegrationTests){
            // get number of tokens in staking contract account after redeeming and check that it increased by the RAV amount
            uint256 stakingBalanceAfter = mockERC20.balanceOf(address(staking));
            assertEq(stakingBalanceAfter, stakingBalance + RAVAggregateAmount, "Incorrect receiver balance after redeeming");
        }
    }

    function testRedeemRAVWithInvalidSignature() public {
        depositEscrow(SENDER_ADDRESS, receiversAddresses[0], ESCROW_AMOUNT);

        authorizeSignerWithProof(SENDER_ADDRESS, authorizedSignerPrivateKeys[0], authorizedsigners[0]);

        // Create a signed rav
        uint128 RAVAggregateAmount = uint128(ESCROW_AMOUNT);
        uint64 timestampNs = 10;
        TAPVerifier.SignedRAV memory signed_rav =
            createSignedRAV(receiversAllocationIDs[0], timestampNs, RAVAggregateAmount, authorizedSignerPrivateKeys[0]);

        // Alter signature to random bits
        uint256 randomBits = 0xabcdef12345678900987654321fedcba1234567890abcdef1234567890abcdef;
        uint8 v = 27;
        signed_rav.signature = abi.encodePacked(randomBits, randomBits, v);

        // Receiver redeems value from the SignedRAV, expected to revert
        vm.expectRevert();
        redeemSignedRAV(
            receiversAllocationIDs[0],
            receiversAllocationIDPrivateKeys[0],
            receiversAddresses[0],
            SENDER_ADDRESS,
            address(escrowContract),
            signed_rav
        );
    }

    function authorizeSignerWithProof(address sender, uint256 signerPivateKey, address signer) private {
        uint256 proofDeadline = block.timestamp + 86400;
        bytes memory authSignerAuthorizesSenderProof = createAuthorizedSignerProof(proofDeadline, sender, signerPivateKey);

        // Authorize the signer
        vm.prank(sender);
        escrowContract.authorizeSigner(signer, proofDeadline, authSignerAuthorizesSenderProof);
    }

    function createAuthorizedSignerProof(uint256 proofDeadline, address sender, uint256 signerPrivateKey)
        private
        view
        returns (bytes memory)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(block.chainid, proofDeadline, sender));
        bytes32 allocationIDdigest = ECDSA.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, allocationIDdigest);
        return abi.encodePacked(r, s, v);
    }

    /*
    * Create a proof that the receiver owns the allocationID (for escrow contract/allocationIDTracker)
    */
    function createAllocationIDOwnershipProof(
        address allocationID,
        address sender,
        address escrowContractAddress,
        uint256 allocationIDPrivateKey
    ) private view returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked(block.chainid, sender, allocationID, escrowContractAddress));
        bytes32 allocationIDdigest = ECDSA.toEthSignedMessageHash(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(allocationIDPrivateKey, allocationIDdigest);
        return abi.encodePacked(r, s, v);
    }

    /*
    * Create a proof that the receiver owns the allocationID (for staking contract)
    */
    function createAllocationIDProof(
        address allocationID,
        address receiver,
        uint256 allocationIDPrivateKey
    ) private pure returns (bytes memory){
        bytes32 messageHash = keccak256(abi.encodePacked(receiver, allocationID));
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

    function depositManyEscrow(address sender, address[] memory receivers, uint256[] memory amounts) public {
        // Sets msg.sender address for next contract calls until stop is called
        vm.startPrank(sender);

        // Approve the escrow contract to transfer tokens from the sender
        uint256 totalAmount = 0;
        for (uint i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }
        mockERC20.approve(address(escrowContract), totalAmount);

        escrowContract.depositMany(receivers, amounts);
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
        address receiverAddress,
        address senderAddress,
        address escrowContractAddress,
        TAPVerifier.SignedRAV memory signedRAV
    ) private {
        // create proof of allocationID ownership
        bytes memory proof = createAllocationIDOwnershipProof(
            allocationID, senderAddress, address(escrowContractAddress), allocationIDPrivateKey
        );
        vm.prank(receiverAddress);
        escrowContract.redeem(signedRAV, proof);
    }
}
