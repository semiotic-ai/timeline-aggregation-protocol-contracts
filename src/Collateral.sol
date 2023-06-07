// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "./TAPVerifier.sol";

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
        uint256 balance;        // Total collateral balance for a sender-receiver pair

        uint256 amountThawing;  // Amount of collateral currently being thawed
        uint256 thawEnd;        // Block number at which thawing period ends
    }

    // Stores how much collateral each sender has deposited for each receiver, as well as thawing information
    mapping(address => mapping(address => CollateralAccount)) private collateralAccounts;
    // Map of authorized signers to which sender they are authorized to sign for
    // key: signer address, value: sender address
    mapping(address => address) private authorizedSigners;

    // The ERC20 token used for collateral
    IERC20 public collateralToken;

    // The contract used for verifying receipt aggregate vouchers
    TAPVerifier public tapVerifier;

    // The duration in which collateral funds are thawing before they can be withdrawn
    uint256 public thawingPeriod;

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

    constructor(address _collateralToken, address _tapVerifier, uint256 _thawingPeriod) {
        collateralToken = IERC20(_collateralToken);
        tapVerifier = TAPVerifier(_tapVerifier);
        thawingPeriod = _thawingPeriod;
    }

    /**
     * @dev Deposits collateral for a receiver.
     * @param _receiver Address of the receiver.
     * @param _amount Amount of collateral to deposit.
     */
    function depositCollateral(address _receiver, uint256 _amount) external {
        collateralToken.transferFrom(msg.sender, address(this), _amount);
        collateralAccounts[msg.sender][_receiver].balance += _amount;
        emit Deposit(msg.sender, _receiver, _amount);
    }

    /**
     * @dev Requests to thaw a specific amount of collateral from a receivers collateral account.
     * @param _receiver Address of the receiver the collateral account is for.
     * @param _amount Amount of collateral to thaw.
     */
    function thawCollateral(address _receiver, uint256 _amount) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][_receiver];
        uint256 totalThawingRequested = account.amountThawing + _amount;
        require(account.balance >= totalThawingRequested, "Insufficient collateral balance");

        // Increase the amount being thawed
        account.amountThawing = totalThawingRequested;
        // Set when the thaw is complete (thawing period number of blocks after current block)
        account.thawEnd = block.number + thawingPeriod;

        emit ThawRequest(msg.sender, _receiver, _amount, account.thawEnd);
    }

    /**
     * @dev Withdraws all thawed collateral from a receivers collateral account.
     * @param _receiver Address of the receiver.
     */
    function withdrawThawedCollateral(address _receiver) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][_receiver];
        require(account.thawEnd != 0, "No collateral thawing");
        require(account.thawEnd <= block.number, "Collateral still thawing");

        // Amount is the minimum between the amount being thawed and the actual balance
        uint256 amount = account.amountThawing > account.balance ? account.balance : account.amountThawing;

        unchecked {
            account.balance -= amount;  // Reduce the balance by the withdrawn amount (no underflow risk)
        }
        account.amountThawing = 0;
        account.thawEnd = 0;
        emit Withdraw(msg.sender, _receiver, amount);
        collateralToken.transfer(msg.sender, amount);
    }

    /**
     * @dev Authorizes a signer to sign RAVs for the sender.
     * @param _signer Address of the authorized signer.
     */
    function authorizeSigner(address _signer) external {
        require(authorizedSigners[_signer] == address(0), "Signer already authorized");
        authorizedSigners[_signer] = msg.sender;
        emit AuthorizeSigner(_signer, msg.sender);
    }

    /**
     * @dev Redeems collateral for a receiver using a signed RAV.
     * @param _signedRAV Signed RAV containing the receiver and collateral amount.
     */
    function redeem(TAPVerifier.SignedRAV memory _signedRAV) external {
        address signer = tapVerifier.recoverRAVSigner(_signedRAV);
        require(authorizedSigners[signer] != address(0), "Signer not authorized");

        address sender = authorizedSigners[signer];
        address receiver = msg.sender;
        uint256 amount = _signedRAV.rav.valueAggregate;
        uint256 availableCollateral = collateralAccounts[sender][receiver].balance;
        require(availableCollateral >= amount, "Insufficient collateral balance");
        unchecked {
            availableCollateral -= amount;
        }
        emit Redeem(msg.sender, amount);
        collateralToken.transfer(msg.sender, amount);
    }

    /**
     * @dev Retrieves the amount of collateral deposited by a sender for a receiver.
     * @param _sender Address of the sender.
     * @param _receiver Address of the receiver.
     * @return The amount of collateral deposited.
     */
    function getCollateralAmount(address _sender, address _receiver) external view returns (uint256) {
        return collateralAccounts[_sender][_receiver].balance;
    }

    /**
     * @dev Retrieves the collateral account details for a sender-receiver pair.
     * @param _sender Address of the sender.
     * @param _receiver Address of the receiver.
     * @return The collateral account details.
     */
    function getCollateralAccount(address _sender, address _receiver) external view returns (CollateralAccount memory) {
        return collateralAccounts[_sender][_receiver];
    }
}