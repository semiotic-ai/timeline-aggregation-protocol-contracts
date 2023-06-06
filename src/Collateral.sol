// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TAPVerifier} from "./TAPVerifier.sol";

import "forge-std/console.sol";


contract Collateral {
    struct CollateralAccount {
        uint256 balance;
        uint256 amountThawing;
        uint256 thawEnd;
    }
    // Stores how much collateral each sender has deposited for each receiver
    mapping(address => mapping(address => CollateralAccount)) private collateralAccounts;
    // Map of authorized signers to which sender they are authorized to sign for
    mapping(address => address) private authorizedSigners;

    IERC20 public collateralToken;
    TAPVerifier public tapVerifier;
    uint256 public thawingPeriod;

    event Deposit(address indexed sender, address indexed receiver, uint256 amount);
    event Redeem(address indexed receiver, uint256 amount);
    event ThawRequest(address indexed sender, address indexed receiver, uint256 amount, uint256 thawEnd);
    event Withdraw(address indexed sender, address indexed receiver, uint256 amount);
    event AuthorizeSigner(address indexed signer, address indexed sender);

    constructor(address _collateralToken, address _tapVerifier, uint256 _thawingPeriod) {
        collateralToken = IERC20(_collateralToken);
        tapVerifier = TAPVerifier(_tapVerifier);
        thawingPeriod = _thawingPeriod;
    }

    function depositCollateral(address _receiver, uint256 _amount) external {
        collateralToken.transferFrom(msg.sender, address(this), _amount);
        collateralAccounts[msg.sender][_receiver].balance += _amount;
        emit Deposit(msg.sender, _receiver, _amount);
    }

    function thawCollateral(address _receiver, uint256 _amount) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][_receiver];
        uint256 totalThawingRequested = account.amountThawing + _amount;
        require(account.balance >= totalThawingRequested, "Insufficient collateral balance");

        // increase the amount thawing
        account.amountThawing = totalThawingRequested;
        // set the thaw end to be thawingPeriod from now
        account.thawEnd = block.number + thawingPeriod;

        emit ThawRequest(msg.sender, _receiver, _amount, account.thawEnd);
    }

    function withdrawThawedCollateral(address _receiver) external {
        CollateralAccount storage account = collateralAccounts[msg.sender][_receiver];
        require(account.thawEnd != 0, "No collateral thawing");
        require(account.thawEnd <= block.number, "Collateral still thawing");

        // amount is the min between the amount thawing and the balance
        uint256 amount = account.amountThawing > account.balance ? account.balance : account.amountThawing;

        unchecked {
            // amount cannot be greater than balance so no risk of underflow
            account.balance -= amount;
        }
        account.amountThawing = 0;
        account.thawEnd = 0;
        emit Withdraw(msg.sender, _receiver, amount);
        collateralToken.transfer(msg.sender, amount);
    }

    function authorizeSigner(address _signer) external {
        require(authorizedSigners[_signer] == address(0), "Signer already authorized");
        authorizedSigners[_signer] = msg.sender;
        emit AuthorizeSigner(_signer, msg.sender);
    }

    function redeem(TAPVerifier.SignedRAV memory _signedRAV) external {
        address signer = tapVerifier.recoverRAVSigner(_signedRAV);
        require(authorizedSigners[signer] != address(0), "Signer not authorized");

        address sender = authorizedSigners[signer];
        address receiver = msg.sender;
        uint256 amount = _signedRAV.rav.valueAggregate;
        uint available_collateral = collateralAccounts[sender][receiver].balance;
        require(available_collateral >= amount, "Insufficient collateral balance");
        available_collateral -= amount;
        emit Redeem(msg.sender, amount);
        collateralToken.transfer(msg.sender, amount);
    }

    function getCollateralAmount(address _sender, address _receiver) external view returns (uint256) {
        return collateralAccounts[_sender][_receiver].balance;
    }

    function getCollateralAccount(address _sender, address _receiver) external view returns (CollateralAccount memory) {
        return collateralAccounts[_sender][_receiver];
    }
}
