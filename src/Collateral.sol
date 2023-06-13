// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "./TAPVerifier.sol";
import {AllocationIDTracker} from "./AllocationIDTracker.sol";

import "forge-std/console.sol";

/**
 * @title Collateral
 * @dev This contract allows `senders` to deposit collateral for specific `receivers`,
 *      which can later be redeemed using Receipt Aggregate Vouchers (`RAV`) signed
 *      by an authorized `signer`. `Senders` can deposit collateral for `receivers`,
 *      authorize `signers` to create signed `RAVs`, and withdraw collateral after a
 *      set `thawingPeriod` number of blocks. `Receivers` can redeem signed `RAVs` to
 *      claim collateral.
 * @notice This contract uses the `TAPVerifier` contract for recovering signer addresses
 *         from `RAVs`.
 */
contract Collateral {
    struct CollateralAccount {
        uint256 balance; // Total collateral balance for a sender-receiver pair
        uint256 amountThawing; // Amount of collateral currently being thawed
        uint256 thawEnd; // Block number at which thawing period ends
    }

    // Stores how much collateral each sender has deposited for each receiver, as well as thawing information
    mapping(address => mapping(address => CollateralAccount)) private collateralAccounts;
    // Map of authorized signers to which sender they are authorized to sign for
    // key: signer address, value: sender address
    mapping(address => address) private authorizedSigners;

    // The ERC20 token used for collateral
    IERC20 public immutable collateralToken;

    // The contract used for verifying receipt aggregate vouchers
    TAPVerifier public immutable tapVerifier;

    // The contract used for tracking used allocation IDs
    AllocationIDTracker public immutable allocationIDTracker;

    // The duration in which collateral funds are thawing before they can be withdrawn
    uint256 public immutable thawingPeriod;

    /**
     * @dev Emitted when collateral is deposited for a receiver.
     */
    event Deposit(address indexed sender, address indexed receiver, uint256 amount);

    /**
     * @dev Emitted when collateral is redeemed by a receiver.
     */
    event Redeem(address indexed receiver, uint256 amount);

    /**
     * @dev Emitted when a thaw request is made for collateral.
     */
    event ThawRequest(address indexed sender, address indexed receiver, uint256 amount, uint256 thawEnd);

    /**
     * @dev Emitted when thawed collateral is withdrawn by the sender.
     */
    event Withdraw(address indexed sender, address indexed receiver, uint256 amount);

    /**
     * @dev Emitted when a signer is authorized to sign RAVs for a sender.
     */
    event AuthorizeSigner(address indexed signer, address indexed sender);

    constructor(address collateralToken_, address tapVerifier_, address allocationIDTracker_, uint256 thawingPeriod_) {
        collateralToken = IERC20(collateralToken_);
        tapVerifier = TAPVerifier(tapVerifier_);
        allocationIDTracker = AllocationIDTracker(allocationIDTracker_);
        thawingPeriod = thawingPeriod_;
    }

    /**
     * @dev Deposits collateral for a receiver.
     * @param receiver Address of the receiver.
     * @param amount Amount of collateral to deposit.
     * @notice The collateral must be approved for transfer by the sender.
     * @notice REVERT: this function will revert if the collateral transfer fails.
     */
    function depositCollateral(address receiver, uint256 amount) external {
        collateralAccounts[msg.sender][receiver].balance += amount;
        emit Deposit(msg.sender, receiver, amount);
        require(collateralToken.transferFrom(msg.sender, address(this), amount));
    }

    /**
     * @dev Requests to thaw a specific amount of collateral from a receivers collateral account.
     * @param receiver Address of the receiver the collateral account is for.
     * @param amount Amount of collateral to thaw.
     * @notice REVERT: this function will revert if the sender receiver collateral account does
     *                 not have enough collateral (greater than `amount`).
     */
    function thawCollateral(address receiver, uint256 amount) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][receiver];
        uint256 totalThawingRequested = account.amountThawing + amount;
        require(account.balance >= totalThawingRequested, "Insufficient collateral balance");

        // Increase the amount being thawed
        account.amountThawing = totalThawingRequested;
        // Set when the thaw is complete (thawing period number of blocks after current block)
        account.thawEnd = block.number + thawingPeriod;

        emit ThawRequest(msg.sender, receiver, amount, account.thawEnd);
    }

    /**
     * @dev Withdraws all thawed collateral from a receivers collateral account.
     * @param receiver Address of the receiver.
     * @notice REVERT: this function will revert if the sender receiver collateral account does
     *                not have any thawed collateral. This function will also revert if no thawing
     *               period has been completed.
     */
    function withdrawThawedCollateral(address receiver) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][receiver];
        require(account.thawEnd != 0, "No collateral thawing");
        require(account.thawEnd <= block.number, "Collateral still thawing");

        // Amount is the minimum between the amount being thawed and the actual balance
        uint256 amount = account.amountThawing > account.balance ? account.balance : account.amountThawing;

        unchecked {
            account.balance -= amount; // Reduce the balance by the withdrawn amount (no underflow risk)
        }
        account.amountThawing = 0;
        account.thawEnd = 0;
        emit Withdraw(msg.sender, receiver, amount);
        require(collateralToken.transfer(msg.sender, amount));
    }

    /**
     * @dev Authorizes a signer to sign RAVs for the sender.
     * @param signer Address of the authorized signer.
     */
    function authorizeSigner(address signer) external {
        require(authorizedSigners[signer] == address(0), "Signer already authorized");
        authorizedSigners[signer] = msg.sender;
        emit AuthorizeSigner(signer, msg.sender);
    }

    /**
     * @dev Redeems collateral for a receiver using a signed RAV.
     * @param signedRAV Signed RAV containing the receiver and collateral amount.
     * @notice REVERT: this function will revert if:
     *                  - the signer is not authorized to sign for a sender.
     *                  - the sender receiver collateral account does not have enough
     *                    collateral (greater than the amount in the RAV).
     *                  - the allocation ID has already been used.
     */
    function redeem(TAPVerifier.SignedRAV memory signedRAV) external {
        address signer = tapVerifier.recoverRAVSigner(signedRAV);
        require(authorizedSigners[signer] != address(0), "Signer not authorized");

        address sender = authorizedSigners[signer];
        address receiver = msg.sender;
        uint256 amount = signedRAV.rav.valueAggregate;
        require(collateralAccounts[sender][receiver].balance >= amount, "Insufficient collateral balance");
        unchecked {
            collateralAccounts[sender][receiver].balance -= amount;
        }

        emit Redeem(msg.sender, amount);
        allocationIDTracker.useAllocationID(signedRAV.rav.allocationId);
        require(collateralToken.transfer(msg.sender, amount));
    }

    /**
     * @dev Retrieves the amount of collateral deposited by a sender for a receiver.
     * @param sender Address of the sender.
     * @param receiver Address of the receiver.
     * @return The amount of collateral deposited.
     */
    function getCollateralAmount(address sender, address receiver) external view returns (uint256) {
        return collateralAccounts[sender][receiver].balance;
    }

    /**
     * @dev Retrieves the collateral account details for a sender-receiver pair.
     * @param sender Address of the sender.
     * @param receiver Address of the receiver.
     * @return The collateral account details.
     */
    function getCollateralAccount(address sender, address receiver) external view returns (CollateralAccount memory) {
        return collateralAccounts[sender][receiver];
    }

    /**
     * @dev Retrieves the collateral account details for a sender-receiver pair of the sender that a signer is authorized for.
     * @param signer Address of the authorized signer.
     * @param receiver Address of the receiver.
     * @return The collateral account details.
     */
    function getCollateralAccountFromSignerAddress(address signer, address receiver) external view returns (CollateralAccount memory) {
        return collateralAccounts[authorizedSigners[signer]][receiver];
    }
}
