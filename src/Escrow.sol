// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.18;

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
 * @notice CAUTIONARY NOTE: Upon observing a thaw event, indexers should act promptly. If the thaw concerns an authorized signer,
 *         treat it as no longer valid for initiating new engagements. For ongoing engagements, efforts should be made to conclude
 *         them swiftly. If funds are in a thawing state, anticipate an imminent withdrawal. Even if actions post-thaw are postponed,
 *         it's prudent to act as though they've already taken place to sidestep potential pitfalls.
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

    // Tracks unassigned escrow balance for each sender, this is escrow deposited to the contract
    // that has not been assigned to a receiver
    mapping(address sender => uint256 balance) public unassignedAccounts;

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

    // Custom error to indicate insufficient unassigned escrow balance
    error InsufficientUnassignedEscrow(uint256 available, uint256 required);

    // Custom error to indicate insufficient thaw amount (must be greater than 0)
    error InsufficientThawAmount();

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

    // Custom error to indicate the signer is not currently authorized by any sender
    error SignerNotAuthorized();

    // Custom error to indicate inputs length mismatch
    error InputsLengthMismatch();

    /**
     * @dev Emitted when escrow is deposited for a receiver.
     */
    event Deposit(
        address indexed sender,
        address indexed receiver,
        uint256 amount
    );

    /**
     * @dev Emitted when escrow is deposited on a sender's unassigned account.
     */
    event UnassignedDeposit(
        address indexed depositor,
        address indexed sender,
        uint256 amount
    );

    /**
     * @dev Emitted when unassigned escrow is assigned to a receiver.
     */
    event DepositAssigned(
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
     * @dev Emitted when a thaw request is cancelled for escrow.
     */
    event CancelThaw(address indexed sender, address indexed receiver);

    /**
     * @dev Emitted when a thaw request is made for authorized signer
     */
    event ThawSigner(
        address indexed sender,
        address indexed authorizedSigner,
        uint256 thawEndTimestamp
    );

    /**
     * @dev Emitted when the thawing of a signer is cancelled
     */
    event CancelThawSigner(
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
     * @dev Deposits escrow for multiple receivers.
     * @param receivers Array of addresses of the receivers.
     * @param amounts Array of amounts of escrow to deposit.
     * @notice The escrow must be approved for transfer by the sender.
     * @notice REVERT: this function will revert if the escrow transfer fails.
     * @notice REVERT: if the length of the receivers and amounts arrays do not match.
     */
    function depositMany(
        address[] calldata receivers,
        uint256[] calldata amounts
    ) external {
        if (receivers.length != amounts.length) {
            revert InputsLengthMismatch();
        }

        uint256 totalAmount = 0;
        for (uint i = 0; i < receivers.length; i++) {
            address receiver = receivers[i];
            uint256 amount = amounts[i];

            totalAmount += amount;
            escrowAccounts[msg.sender][receiver].balance += amount;
            emit Deposit(msg.sender, receiver, amount);
        }

        escrowToken.safeTransferFrom(msg.sender, address(this), totalAmount);
    }

    /**
     * @notice Deposits escrow without assigning a receiver.
     * @param sender Address of the sender to be credited with the deposited amount.
     * @param amount Amount of escrow to deposit.
     * @dev The escrow must be approved for transfer by the caller.
     * @dev REVERT: this function will revert if the escrow transfer fails.
     */
    function depositUnassigned(address sender, uint256 amount) external {
        unassignedAccounts[sender] += amount;
        escrowToken.safeTransferFrom(msg.sender, address(this), amount);
        emit UnassignedDeposit(msg.sender, sender, amount);
    }

    /**
     * @notice Assigns unassigned escrow to a receiver.
     * @param receiver Address of the receiver.
     * @param amount Amount of escrow to assign.
     * @dev Unassigned escrow must be previously deposited via `depositUnassigned()`.
     * @dev REVERT: this function will revert if the sender does not have enough unassigned escrow.
     */
    function assignDeposit(address receiver, uint256 amount) external {
        address sender = msg.sender;
        uint256 unassignedBalance = unassignedAccounts[sender];

        // Check sender has enough unassigned balance
        if (unassignedBalance < amount) {
            revert InsufficientUnassignedEscrow({
                available: unassignedBalance,
                required: amount
            });
        }

        // Assign deposit
        unassignedAccounts[sender] -= amount;
        escrowAccounts[sender][receiver].balance += amount;

        emit DepositAssigned(sender, receiver, amount);
    }

    /**
     * @notice Assigns unassigned escrow for multiple receivers.
     * @param receivers Array of addresses of the receivers.
     * @param amounts Array of amounts of escrow to deposit.
     * @notice Unassigned escrow must be previously deposited via `depositUnassigned()`.
     * @dev REVERT: this function will revert if the sender does not have enough unassigned escrow.
     * @dev REVERT: if the length of the receivers and amounts arrays do not match.
     */
    function assignDepositMany(
        address[] calldata receivers,
        uint256[] calldata amounts
    ) external {
        if (receivers.length != amounts.length) {
            revert InputsLengthMismatch();
        }

        address sender = msg.sender;
        uint256 unassignedBalance = unassignedAccounts[sender];

        // Assign deposits
        uint256 totalAssigned = 0;
        for (uint256 i = 0; i < receivers.length; i++) {
            totalAssigned += amounts[i];
            escrowAccounts[sender][receivers[i]].balance += amounts[i];
            emit DepositAssigned(sender, receivers[i], amounts[i]);
        }

        // Check sender has enough unassigned balance
        // NOTE: this check is done after the deposits are assigned to avoid looping 
        //       twice. It's expected the sender will know it's unassigned balance.
        if (unassignedBalance < totalAssigned) {
            revert InsufficientUnassignedEscrow({
                available: unassignedBalance,
                required: totalAssigned
            });
        }

        unassignedAccounts[sender] -= totalAssigned;
    }

    /**
     * @dev Requests to thaw a specific amount of escrow from a receiver's escrow account.
     *      if requested amount is zero any thawing in progress will be cancelled. If requested
     *      amount is greater than zero any thawing in progress will be cancelled and a new
     *     thawing request will be initiated.
     * @param receiver Address of the receiver the escrow account is for.
     * @param amount Amount of escrow to thaw.
     * @notice WARNING: Requesting to thaw escrow funds serves as an indication that these funds are soon to be withdrawn.
     * Receivers with commitments linked to the thawing funds should quickly wrap up those commitments.
     * At the same time, receivers should avoid starting new engagements tied to the thawing funds.
     * After the thawing process, the funds should be viewed as withdrawn, irrespective of the actual withdrawal status.
     * @notice REVERT with error:
     *               - InsufficientThawAmount: if the requested amount is zero and there is no
     *                 escrow currently thawing
     *               - InsufficientEscrow: if the sender receiver escrow account does
     *                 not have enough escrow (greater than `amount`)
     */
    function thaw(address receiver, uint256 amount) external {
        EscrowAccount storage account = escrowAccounts[msg.sender][receiver];
        if (amount == 0) {
            // if amount thawing is zero and requested amount is zero this is an invalid request(#36).
            // otherwise if amount thawing is greater than zero and requested amount is zero this
            // is a cancel thaw request.
            if (account.amountThawing == 0) {
                revert InsufficientThawAmount();
            }
            account.amountThawing = 0;
            account.thawEndTimestamp = 0;
            emit CancelThaw(msg.sender, receiver);
            return;
        }

        // Check if the escrow balance is sufficient
        if (account.balance < amount) {
            revert InsufficientEscrow({
                available: account.balance,
                required: amount
            });
        }

        // Set amount to thaw
        account.amountThawing = amount;
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
        EscrowAccount storage account = escrowAccounts[msg.sender][receiver];
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
     * @param proof The proof provided by the signer to authorize the sender, consisting of packed (chainID, proof deadline, sender address).
     * @dev The proof deadline is the timestamp at which the proof expires. The proof is susceptible to replay attacks until the deadline is reached.
     * @notice REVERT with error:
     *               - SignerAlreadyAuthorized: Signer is currently authorized for a sender
     *               - InvalidSignerProof: The provided signer proof is invalid
     */
    function authorizeSigner(
        address signer,
        uint256 proofDeadline,
        bytes calldata proof
    ) external {
        if (authorizedSigners[signer].sender != address(0)) {
            revert SignerAlreadyAuthorized(
                signer,
                authorizedSigners[signer].sender
            );
        }

        verifyAuthorizedSignerProof(proof, proofDeadline, signer);

        authorizedSigners[signer].sender = msg.sender;
        authorizedSigners[signer].thawEndTimestamp = 0;
        emit AuthorizeSigner(signer, msg.sender);
    }

    /**
     * @dev Starts thawing a signer to be removed from the authorized signers list.
     * @param signer Address of the signer to remove.
     * @notice WARNING: Thawing a signer alerts receivers that signatures from that signer will soon be deemed invalid.
     * Receivers without existing signed receipts or RAVs from this signer should treat them as unauthorized.
     * Those with existing signed documents from this signer should work towards settling their engagements.
     * Once a signer is thawed, they should be viewed as revoked regardless of their revocation status.
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
     * @dev stops thawing a signer.
     * @param signer Address of the signer to stop thawing.
     * @notice REVERT with error:
     *               - SignerNotAuthorizedBySender: The provided signer is either not authorized or
     *                 authorized by a different sender
     */
    function cancelThawSigner(address signer) external {
        SenderAuthorization storage authorization = authorizedSigners[signer];

        if (authorization.sender != msg.sender) {
            revert SignerNotAuthorizedBySender(
                signer,
                authorizedSigners[signer].sender
            );
        }

        authorization.thawEndTimestamp = 0;
        emit CancelThawSigner(
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
     * @notice If a signer or funds are in the thawing process, exercise caution. Thawing indicates upcoming removals.
     *         For in-depth understanding, refer to the respective documentation sections on thawing signers and funds.
     * @notice will accept redeem even if escrow account balance is below RAV valueAggregate. Check escrow balance before
     *         redeeming to ensure expected funds are available. Only one succesfully redeem is allowed for
     *         (sender, allocationID) pair.
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
        address receiver = staking
            .getAllocation(signedRAV.rav.allocationId)
            .indexer;
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
            receiver,
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
        address sender = authorizedSigners[signer].sender;
        if (sender == address(0)) {
            revert SignerNotAuthorized();
        }
        return escrowAccounts[sender][receiver];
    }

    /**
     * @dev Retrieves the amount of unassigned escrow deposited for a sender.
     * @param sender Address of the sender.
     * @return The amount of escrow deposited.
     */
    function getUnassignedEscrowAmount(
        address sender
    ) external view returns (uint256) {
        return unassignedAccounts[sender];
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
        uint256 proofDeadline,
        address signer
    ) private view {
        // Verify that the proof deadline has not passed
        if (block.timestamp > proofDeadline) {
            revert InvalidSignerProof();
        }

        // Generate the hash of the sender's address
        bytes32 messageHash = keccak256(
            abi.encodePacked(block.chainid, proofDeadline, msg.sender)
        );

        // Generate the digest to be signed by the signer
        bytes32 digest = ECDSA.toEthSignedMessageHash(messageHash);

        // Verify that the recovered signer matches the expected signer
        if (ECDSA.recover(digest, proof) != signer) {
            revert InvalidSignerProof();
        }
    }
}
