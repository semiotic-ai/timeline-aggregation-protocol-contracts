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
 * @title Escrow
 * @dev This contract allows `senders` to deposit escrow for specific `receivers`,
 *      which can later be redeemed using Receipt Aggregate Vouchers (`RAV`) signed
 *      by an authorized `signer`. `Senders` can deposit escrow for `receivers`,
 *      authorize `signers` to create signed `RAVs`, and withdraw escrow after a
 *      set `thawingPeriod` number of seconds. `Receivers` can redeem signed `RAVs` to
 *      claim escrow.
 * @notice This contract uses the `TAPVerifier` contract for recovering signer addresses
 *         from `RAVs`.
 */
contract Escrow {
    using SafeERC20 for IERC20;

    struct EscrowAccount {
        uint256 balance; // Total escrow balance for a sender-receiver pair
        uint256 amountThawing; // Amount of escrow currently being thawed
        uint256 thawEndTimestamp; // Timestamp at which thawing period ends (zero if not thawing)
    }

    struct SenderAuthorization {
        address sender; // Sender the signer is authorized to sign for
        uint256 thawEndTimestamp; // Timestamp at which thawing period ends (zero if not thawing)
    }

    // Stores how much escrow each sender has deposited for each receiver, as well as thawing information
    mapping(address sender => mapping(address receiver => EscrowAccount escrowAccount))
        public escrowAccounts;
    // Map of signer to authorized signer information
    mapping(address signer => SenderAuthorization authorizedSigner)
        public authorizedSigners;

    // The ERC20 token used for escrow
    IERC20 public immutable escrowToken;

    // Graph staking contract
    IStaking public immutable staking;

    // The contract used for verifying receipt aggregate vouchers
    TAPVerifier public immutable tapVerifier;

    // The contract used for tracking used allocation IDs
    AllocationIDTracker public immutable allocationIDTracker;

    // The duration (in seconds) in which escrow funds are thawing before they can be withdrawn
    uint256 public immutable withdrawEscrowThawingPeriod;

    // The duration (in seconds) in which a signer is thawing before they can be revoked
    uint256 public immutable revokeSignerThawingPeriod;

    // Custom error to indicate insufficient escrow balance
    error InsufficientEscrow(uint256 available, uint256 required);

    // Custom error to indicate escrow is still thawing
    error EscrowStillThawing(
        uint256 currentTimestamp,
        uint256 thawEndTimestamp
    );

    // Custom error to indicate escrow thawing has not been initiated
    error EscrowNotThawing();

    // Custom error to indicate invalid signer proof
    error InvalidSignerProof();

    // Custom error to indicate provided signer is not one of provided senders authorized signers
    error SignerNotAuthorizedBySender(address signer, address sender);

    // Custom error to indicate signer already authorized
    error SignerAlreadyAuthorized(address signer, address authorizingSender);

    // Custom error to indicate signer is still thawing
    error SignerStillThawing(
        uint256 currentTimestamp,
        uint256 thawEndTimestamp
    );

    // Custom error to indicate signer thawing has not been initiated
    error SignerNotThawing();

    // Custom error to indicate invalid RAV signer
    error InvalidRAVSigner();

    /**
     * @dev Emitted when escrow is deposited for a receiver.
     */
    event Deposit(
        address indexed sender,
        address indexed receiver,
        uint256 amount
    );

    /**
     * @dev Emitted when escrow is redeemed by a receiver.
     * @notice If the actual amount redeemed is less than the expected amount,
     *         there was insufficient escrow available to redeem.
     */
    event Redeem(
        address indexed sender,
        address indexed receiver,
        address indexed allocationID,
        uint256 expectedAmount,
        uint256 actualAmount
    );

    /**
     * @dev Emitted when a thaw request is made for escrow.
     */
    event Thaw(
        address indexed sender,
        address indexed receiver,
        uint256 amount,
        uint256 totalAmountThawing,
        uint256 thawEndTimestamp
    );

    /**
     * @dev Emitted when a thaw request is made for authorized signer
     */
    event ThawSigner(
        address indexed sender,
        address indexed authorizedSigner,
        uint256 thawEndTimestamp
    );

    /**
     * @dev Emitted when a authorized signer has been revoked
     */
    event RevokeAuthorizedSigner(
        address indexed sender,
        address indexed authorizedSigner
    );

    /**
     * @dev Emitted when thawed escrow is withdrawn by the sender.
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
        address escrowToken_,
        address staking_,
        address tapVerifier_,
        address allocationIDTracker_,
        uint256 withdrawEscrowThawingPeriod_,
        uint256 revokeSignerThawingPeriod_
    ) {
        escrowToken = IERC20(escrowToken_);
        staking = IStaking(staking_);
        tapVerifier = TAPVerifier(tapVerifier_);
        allocationIDTracker = AllocationIDTracker(allocationIDTracker_);
        withdrawEscrowThawingPeriod = withdrawEscrowThawingPeriod_;
        revokeSignerThawingPeriod = revokeSignerThawingPeriod_;
    }

    /**
     * @notice Approve the staking contract to pull any amount of tokens from this contract.
     * @dev Increased gas efficiency instead of approving on each voucher redeem
     */
    function approveAll() external {
        escrowToken.approve(address(staking), type(uint256).max);
    }

    /**
     * @dev Deposits escrow for a receiver.
     * @param receiver Address of the receiver.
     * @param amount Amount of escrow to deposit.
     * @notice The escrow must be approved for transfer by the sender.
     * @notice REVERT: this function will revert if the escrow transfer fails.
     */
    function deposit(address receiver, uint256 amount) external {
        escrowAccounts[msg.sender][receiver].balance += amount;
        escrowToken.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, receiver, amount);
    }

    /**
     * @dev Requests to thaw a specific amount of escrow from a receiver's escrow account.
     * @param receiver Address of the receiver the escrow account is for.
     * @param amount Amount of escrow to thaw.
     * @notice REVERT with error:
     *               - InsufficientEscrow: if the sender receiver escrow account does
     *                 not have enough escrow (greater than `amount`)
     */
    function thaw(address receiver, uint256 amount) external {
        EscrowAccount storage account = escrowAccounts[msg.sender][
            receiver
        ];
        uint256 totalThawingRequested = account.amountThawing + amount;

        // Check if the escrow balance is sufficient
        if (account.balance < totalThawingRequested) {
            revert InsufficientEscrow({
                available: account.balance,
                required: totalThawingRequested
            });
        }

        // Increase the amount being thawed
        account.amountThawing = totalThawingRequested;
        // Set when the thaw is complete (thawing period number of seconds after current timestamp)
        account.thawEndTimestamp =
            block.timestamp +
            withdrawEscrowThawingPeriod;

        emit Thaw(
            msg.sender,
            receiver,
            amount,
            account.amountThawing,
            account.thawEndTimestamp
        );
    }

    /**
     * @dev Withdraws all thawed escrow from a receiver's escrow account.
     * @param receiver Address of the receiver.
     * @notice REVERT with error:
     *               - EscrowNotThawing: There is no escrow currently thawing
     *               - EscrowStillThawing: ThawEndTimestamp has not been reached
     *                 for escrow currently thawing
     */
    function withdraw(address receiver) external {
        EscrowAccount storage account = escrowAccounts[msg.sender][
            receiver
        ];
        if (account.thawEndTimestamp == 0) {
            revert EscrowNotThawing();
        }

        if (account.thawEndTimestamp > block.timestamp) {
            revert EscrowStillThawing({
                currentTimestamp: block.timestamp,
                thawEndTimestamp: account.thawEndTimestamp
            });
        }

        // Amount is the minimum between the amount being thawed and the actual balance
        uint256 amount = account.amountThawing > account.balance
            ? account.balance
            : account.amountThawing;

        account.balance -= amount; // Reduce the balance by the withdrawn amount (no underflow risk)
        account.amountThawing = 0;
        account.thawEndTimestamp = 0;
        escrowToken.safeTransfer(msg.sender, amount);
        emit Withdraw(msg.sender, receiver, amount);
    }

    /**
     * @dev Authorizes a signer to sign RAVs for the sender.
     * @param signer Address of the authorized signer.
     * @param proof The proof provided by the signer to authorize the sender.
     * @notice REVERT with error:
     *               - SignerAlreadyAuthorized: Signer is currently authorized for a sender
     *               - InvalidSignerProof: The provided signer proof is invalid
     */
    function authorizeSigner(address signer, bytes calldata proof) external {
        if (authorizedSigners[signer].sender != address(0)) {
            revert SignerAlreadyAuthorized(
                signer,
                authorizedSigners[signer].sender
            );
        }

        verifyAuthorizedSignerProof(proof, signer);

        authorizedSigners[signer].sender = msg.sender;
        authorizedSigners[signer].thawEndTimestamp = 0;
        emit AuthorizeSigner(signer, msg.sender);
    }

    /**
     * @dev Starts thawing a signer to be removed from the authorized signers list.
     * @param signer Address of the signer to remove.
     * @notice REVERT with error:
     *               - SignerNotAuthorizedBySender: The provided signer is either not authorized or
     *                 authorized by a different sender
     */
    function thawSigner(address signer) external {
        SenderAuthorization storage authorization = authorizedSigners[signer];

        if (authorization.sender != msg.sender) {
            revert SignerNotAuthorizedBySender(
                signer,
                authorizedSigners[signer].sender
            );
        }

        authorization.thawEndTimestamp =
            block.timestamp +
            revokeSignerThawingPeriod;
        emit ThawSigner(
            authorization.sender,
            signer,
            authorization.thawEndTimestamp
        );
    }

    /**
     * @dev Revokes a signer from the authorized signers list if thawed.
     * @param signer Address of the signer to remove.
     * @notice REVERT with error:
     *               - SignerNotAuthorizedBySender: The provided signer is either not authorized or
     *                 authorized by a different sender
     *               - SignerNotThawing: No thaw was initiated for the provided signer
     *               - SignerStillThawing: ThawEndTimestamp has not been reached
     *                 for provided signer
     */
    function revokeAuthorizedSigner(address signer) external {
        SenderAuthorization storage authorization = authorizedSigners[signer];

        if (authorization.sender != msg.sender) {
            revert SignerNotAuthorizedBySender(
                signer,
                authorizedSigners[signer].sender
            );
        }

        if (authorization.thawEndTimestamp == 0) {
            revert SignerNotThawing();
        }

        if (authorization.thawEndTimestamp > block.timestamp) {
            revert SignerStillThawing({
                currentTimestamp: block.timestamp,
                thawEndTimestamp: authorization.thawEndTimestamp
            });
        }

        delete authorizedSigners[signer];
        emit RevokeAuthorizedSigner(authorization.sender, signer);
    }

    /**
     * @dev Redeems escrow (up to amount available in escrow) for a receiver using a signed RAV.
     * @param signedRAV Signed RAV containing the receiver and escrow amount.
     * @param allocationIDProof Proof of allocationID ownership.
     * @notice REVERT: This function may revert if ECDSA.recover fails, check Open Zeppelin ECDSA library for details.
     * @notice REVERT with error:
     *               - InvalidRAVSigner: If the RAV is signed by a signer who is not authorized by any sender
     *               - AllocationIDTracker.AllocationIDPreviouslyClaimed: If the allocation ID was previously claimed
     *               - AllocationIDTracker.InvalidProof: If the allocation ID ownership proof is not valid
     */
    function redeem(
        TAPVerifier.SignedRAV calldata signedRAV,
        bytes calldata allocationIDProof
    ) external {
        address signer = tapVerifier.recoverRAVSigner(signedRAV);

        if (authorizedSigners[signer].sender == address(0)) {
            revert InvalidRAVSigner();
        }

        address sender = authorizedSigners[signer].sender;
        address receiver = msg.sender;
        address allocationId = signedRAV.rav.allocationId;

        // Amount is the minimum between the amount owed on rav and the actual balance
        uint256 amount = signedRAV.rav.valueAggregate >
            escrowAccounts[sender][receiver].balance
            ? escrowAccounts[sender][receiver].balance
            : signedRAV.rav.valueAggregate;

        escrowAccounts[sender][receiver].balance -= amount;

        allocationIDTracker.useAllocationID(
            sender,
            allocationId,
            allocationIDProof
        );
        staking.collect(amount, allocationId);
        emit Redeem(
            sender,
            msg.sender,
            signedRAV.rav.allocationId,
            signedRAV.rav.valueAggregate,
            amount
        );
    }

    /**
     * @dev Retrieves the amount of escrow deposited by a sender for a receiver.
     * @param sender Address of the sender.
     * @param receiver Address of the receiver.
     * @return The amount of escrow deposited.
     */
    function getEscrowAmount(
        address sender,
        address receiver
    ) external view returns (uint256) {
        return escrowAccounts[sender][receiver].balance;
    }

    /**
     * @dev Retrieves the escrow account details for a sender-receiver pair of the sender that a signer is authorized for.
     * @param signer Address of the authorized signer.
     * @param receiver Address of the receiver.
     * @return The escrow account details.
     */
    function getEscrowAccountFromSignerAddress(
        address signer,
        address receiver
    ) external view returns (EscrowAccount memory) {
        return escrowAccounts[authorizedSigners[signer].sender][receiver];
    }

    /**
     * @dev Verifies a proof that authorizes the sender to authorize the signer.
     * @param proof The proof provided by the signer to authorize the sender.
     * @param signer The address of the signer being authorized.
     * @notice REVERT with error:
     *               - InvalidSignerProof: If the given proof is not valid
     */
    function verifyAuthorizedSignerProof(
        bytes calldata proof,
        address signer
    ) private view {
        // Generate the hash of the sender's address
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender));

        // Generate the digest to be signed by the signer
        bytes32 digest = ECDSA.toEthSignedMessageHash(messageHash);

        // Verify that the recovered signer matches the expected signer
        if (ECDSA.recover(digest, proof) != signer) {
            revert InvalidSignerProof();
        }
    }
}
