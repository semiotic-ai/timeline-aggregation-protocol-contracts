// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "./TAPVerifier.sol";
import {AllocationIDTracker} from "./AllocationIDTracker.sol";
import {IStaking} from "./IStaking.sol";

/**
 * @title Collateral
 * @dev This contract allows `senders` to deposit collateral for specific `receivers`,
 *      which can later be redeemed using Receipt Aggregate Vouchers (`RAV`) signed
 *      by an authorized `signer`. `Senders` can deposit collateral for `receivers`,
 *      authorize `signers` to create signed `RAVs`, and withdraw collateral after a
 *      set `thawingPeriod` number of seconds. `Receivers` can redeem signed `RAVs` to
 *      claim collateral.
 * @notice This contract uses the `TAPVerifier` contract for recovering signer addresses
 *         from `RAVs`.
 */
contract Collateral {
    using SafeERC20 for IERC20;

    struct CollateralAccount {
        uint256 balance; // Total collateral balance for a sender-receiver pair
        uint256 amountThawing; // Amount of collateral currently being thawed
        uint256 thawEndTimestamp; // Block number at which thawing period ends
    }

    // Stores how much collateral each sender has deposited for each receiver, as well as thawing information
    mapping(address sender => mapping(address reciever => CollateralAccount collateralAccount))
        private collateralAccounts;
    // Map of authorized signers to which sender they are authorized to sign for
    mapping(address signer => address sender) private authorizedSigners;

    // The ERC20 token used for collateral
    IERC20 public immutable collateralToken;

    // Graph staking contract
    IStaking public immutable staking;

    // The contract used for verifying receipt aggregate vouchers
    TAPVerifier public immutable tapVerifier;

    // The contract used for tracking used allocation IDs
    AllocationIDTracker public immutable allocationIDTracker;

    // The duration (in seconds) in which collateral funds are thawing before they can be withdrawn
    uint256 public immutable thawingPeriod;

    /**
     * @dev Emitted when collateral is deposited for a receiver.
     */
    event Deposit(
        address indexed sender,
        address indexed receiver,
        uint256 amount
    );

    /**
     * @dev Emitted when collateral is redeemed by a receiver.
     */
    event Redeem(
        address indexed sender,
        address indexed receiver,
        address indexed allocationID,
        uint256 amount
    );

    /**
     * @dev Emitted when a thaw request is made for collateral.
     */
    event Thaw(
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        uint256 totalAmountThawing,
        uint256 thawEndTimestamp
    );

    /**
     * @dev Emitted when thawed collateral is withdrawn by the sender.
     */
    event Withdraw(
        address indexed sender,
        address indexed receiver,
        uint256 amount
    );

    /**
     * @dev Emitted when a signer is authorized to sign RAVs for a sender.
     */
    event AuthorizeSigner(address indexed signer, address indexed sender);

    constructor(
        address collateralToken_,
        address staking_,
        address tapVerifier_,
        address allocationIDTracker_,
        uint256 thawingPeriod_
    ) {
        collateralToken = IERC20(collateralToken_);
        staking = IStaking(staking_);
        tapVerifier = TAPVerifier(tapVerifier_);
        allocationIDTracker = AllocationIDTracker(allocationIDTracker_);
        thawingPeriod = thawingPeriod_;
    }

    /**
     * @notice Approve the staking contract to pull any amount of tokens from this contract.
     * @dev Increased gas efficiency instead of approving on each voucher redeem
     */
    function approveAll() external {
        collateralToken.approve(address(staking), type(uint256).max);
    }

    /**
     * @dev Deposits collateral for a receiver.
     * @param receiver Address of the receiver.
     * @param amount Amount of collateral to deposit.
     * @notice The collateral must be approved for transfer by the sender.
     * @notice REVERT: this function will revert if the collateral transfer fails.
     */
    function deposit(address receiver, uint256 amount) external {
        collateralAccounts[msg.sender][receiver].balance += amount;
        collateralToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, receiver, amount);
    }

    /**
     * @dev Requests to thaw a specific amount of collateral from a receivers collateral account.
     * @param receiver Address of the receiver the collateral account is for.
     * @param amount Amount of collateral to thaw.
     * @notice REVERT: this function will revert if the sender receiver collateral account does
     *                 not have enough collateral (greater than `amount`).
     */
    function thaw(address receiver, uint256 amount) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][
            receiver
        ];
        uint256 totalThawingRequested = account.amountThawing + amount;
        require(
            account.balance >= totalThawingRequested,
            "Insufficient collateral balance"
        );

        // Increase the amount being thawed
        account.amountThawing = totalThawingRequested;
        // Set when the thaw is complete (thawing period number of seconds after current timestamp)
        account.thawEndTimestamp = block.timestamp + thawingPeriod;

        emit Thaw(
            msg.sender,
            receiver,
            amount,
            account.amountThawing,
            account.thawEndTimestamp
        );
    }

    /**
     * @dev Withdraws all thawed collateral from a receivers collateral account.
     * @param receiver Address of the receiver.
     * @notice REVERT: this function will revert if the sender receiver collateral account does
     *                 not have any thawed collateral. This function will also revert if no thawing
     *                 period has been completed.
     */
    function withdraw(address receiver) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][
            receiver
        ];
        require(account.thawEndTimestamp != 0, "No collateral thawing");
        require(
            account.thawEndTimestamp <= block.timestamp,
            "Collateral still thawing"
        );

        // Amount is the minimum between the amount being thawed and the actual balance
        uint256 amount = account.amountThawing > account.balance
            ? account.balance
            : account.amountThawing;

        unchecked {
            account.balance -= amount; // Reduce the balance by the withdrawn amount (no underflow risk)
        }
        account.amountThawing = 0;
        account.thawEndTimestamp = 0;
        collateralToken.safeTransfer(msg.sender, amount);
        emit Withdraw(msg.sender, receiver, amount);
    }

    /**
     * @dev Authorizes a signer to sign RAVs for the sender.
     * @param signer Address of the authorized signer.
     */
    function authorizeSigner(address signer, bytes calldata proof) external {
        require(
            authorizedSigners[signer] == address(0),
            "Signer already authorized"
        );
        require(
            verifyAuthorizedSignerProof(proof, signer),
            "Invalid signer proof"
        );
        authorizedSigners[signer] = msg.sender;
        emit AuthorizeSigner(signer, msg.sender);
    }

    /**
     * @dev Redeems collateral for a receiver using a signed RAV.
     * @param signedRAV Signed RAV containing the receiver and collateral amount.
     * @param allocationIDProof Proof of allocationID ownership.
     * @notice REVERT: this function will revert if:
     *                  - the signer is not authorized to sign for a sender.
     *                  - the sender receiver collateral account does not have enough
     *                    collateral (greater than the amount in the RAV).
     *                  - the allocation ID has already been used.
     */
    function redeem(
        TAPVerifier.SignedRAV calldata signedRAV,
        bytes calldata allocationIDProof
    ) external {
        address signer = tapVerifier.recoverRAVSigner(signedRAV);
        require(
            authorizedSigners[signer] != address(0),
            "Signer not authorized"
        );

        address sender = authorizedSigners[signer];
        address receiver = msg.sender;
        uint256 amount = signedRAV.rav.valueAggregate;
        address allocationId = signedRAV.rav.allocationId;
        require(
            collateralAccounts[sender][receiver].balance >= amount,
            "Insufficient collateral balance"
        );
        unchecked {
            collateralAccounts[sender][receiver].balance -= amount;
        }

        allocationIDTracker.useAllocationID(
            sender,
            allocationId,
            allocationIDProof
        );
        staking.collect(amount, allocationId);
        emit Redeem(sender, msg.sender, signedRAV.rav.allocationId, amount);
    }

    /**
     * @dev Retrieves the amount of collateral deposited by a sender for a receiver.
     * @param sender Address of the sender.
     * @param receiver Address of the receiver.
     * @return The amount of collateral deposited.
     */
    function getCollateralAmount(
        address sender,
        address receiver
    ) external view returns (uint256) {
        return collateralAccounts[sender][receiver].balance;
    }

    /**
     * @dev Retrieves the collateral account details for a sender-receiver pair.
     * @param sender Address of the sender.
     * @param receiver Address of the receiver.
     * @return The collateral account details.
     */
    function getCollateralAccount(
        address sender,
        address receiver
    ) external view returns (CollateralAccount memory) {
        return collateralAccounts[sender][receiver];
    }

    /**
     * @dev Retrieves the collateral account details for a sender-receiver pair of the sender that a signer is authorized for.
     * @param signer Address of the authorized signer.
     * @param receiver Address of the receiver.
     * @return The collateral account details.
     */
    function getCollateralAccountFromSignerAddress(
        address signer,
        address receiver
    ) external view returns (CollateralAccount memory) {
        return collateralAccounts[authorizedSigners[signer]][receiver];
    }

    /**
     * @dev Verifies a proof that authorizes the sender to authorize the signer.
     * @param proof The proof provided by the signer to authorize the sender.
     * @param signer The address of the signer being authorized.
     * @return A boolean indicating whether the proof is valid.
     * @notice REVERT: This function may revert if the proof is not valid.
     */
    function verifyAuthorizedSignerProof(
        bytes calldata proof,
        address signer
    ) private view returns (bool) {
        // Generate the hash of the sender's address
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender));

        // Generate the digest to be signed by the signer
        bytes32 digest = ECDSA.toEthSignedMessageHash(messageHash);

        // Verify that the recovered signer matches the expected signer
        require(ECDSA.recover(digest, proof) == signer, "Invalid proof");

        return true;
    }
}
