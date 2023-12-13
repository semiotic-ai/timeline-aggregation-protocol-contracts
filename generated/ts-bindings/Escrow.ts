/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  ContractTransaction,
  Overrides,
  PopulatedTransaction,
  Signer,
  utils,
} from "ethers";
import type {
  FunctionFragment,
  Result,
  EventFragment,
} from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
} from "./common";

export declare namespace Escrow {
  export type EscrowAccountStruct = {
    balance: BigNumberish;
    amountThawing: BigNumberish;
    thawEndTimestamp: BigNumberish;
  };

  export type EscrowAccountStructOutput = [BigNumber, BigNumber, BigNumber] & {
    balance: BigNumber;
    amountThawing: BigNumber;
    thawEndTimestamp: BigNumber;
  };
}

export declare namespace TAPVerifier {
  export type ReceiptAggregateVoucherStruct = {
    allocationId: string;
    timestampNs: BigNumberish;
    valueAggregate: BigNumberish;
  };

  export type ReceiptAggregateVoucherStructOutput = [
    string,
    BigNumber,
    BigNumber
  ] & {
    allocationId: string;
    timestampNs: BigNumber;
    valueAggregate: BigNumber;
  };

  export type SignedRAVStruct = {
    rav: TAPVerifier.ReceiptAggregateVoucherStruct;
    signature: BytesLike;
  };

  export type SignedRAVStructOutput = [
    TAPVerifier.ReceiptAggregateVoucherStructOutput,
    string
  ] & {
    rav: TAPVerifier.ReceiptAggregateVoucherStructOutput;
    signature: string;
  };
}

export interface EscrowInterface extends utils.Interface {
  functions: {
    "MAX_THAWING_PERIOD()": FunctionFragment;
    "allocationIDTracker()": FunctionFragment;
    "authorizeSigner(address,uint256,bytes)": FunctionFragment;
    "authorizedSigners(address)": FunctionFragment;
    "cancelThawSigner(address)": FunctionFragment;
    "deposit(address,uint256)": FunctionFragment;
    "depositMany(address[],uint256[])": FunctionFragment;
    "escrowAccounts(address,address)": FunctionFragment;
    "escrowToken()": FunctionFragment;
    "getEscrowAccountFromSignerAddress(address,address)": FunctionFragment;
    "getEscrowAmount(address,address)": FunctionFragment;
    "redeem(((address,uint64,uint128),bytes),bytes)": FunctionFragment;
    "revokeAuthorizedSigner(address)": FunctionFragment;
    "revokeSignerThawingPeriod()": FunctionFragment;
    "staking()": FunctionFragment;
    "tapVerifier()": FunctionFragment;
    "thaw(address,uint256)": FunctionFragment;
    "thawSigner(address)": FunctionFragment;
    "withdraw(address)": FunctionFragment;
    "withdrawEscrowThawingPeriod()": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | "MAX_THAWING_PERIOD"
      | "allocationIDTracker"
      | "authorizeSigner"
      | "authorizedSigners"
      | "cancelThawSigner"
      | "deposit"
      | "depositMany"
      | "escrowAccounts"
      | "escrowToken"
      | "getEscrowAccountFromSignerAddress"
      | "getEscrowAmount"
      | "redeem"
      | "revokeAuthorizedSigner"
      | "revokeSignerThawingPeriod"
      | "staking"
      | "tapVerifier"
      | "thaw"
      | "thawSigner"
      | "withdraw"
      | "withdrawEscrowThawingPeriod"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "MAX_THAWING_PERIOD",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "allocationIDTracker",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "authorizeSigner",
    values: [string, BigNumberish, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "authorizedSigners",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "cancelThawSigner",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "deposit",
    values: [string, BigNumberish]
  ): string;
  encodeFunctionData(
    functionFragment: "depositMany",
    values: [string[], BigNumberish[]]
  ): string;
  encodeFunctionData(
    functionFragment: "escrowAccounts",
    values: [string, string]
  ): string;
  encodeFunctionData(
    functionFragment: "escrowToken",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "getEscrowAccountFromSignerAddress",
    values: [string, string]
  ): string;
  encodeFunctionData(
    functionFragment: "getEscrowAmount",
    values: [string, string]
  ): string;
  encodeFunctionData(
    functionFragment: "redeem",
    values: [TAPVerifier.SignedRAVStruct, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "revokeAuthorizedSigner",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "revokeSignerThawingPeriod",
    values?: undefined
  ): string;
  encodeFunctionData(functionFragment: "staking", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "tapVerifier",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "thaw",
    values: [string, BigNumberish]
  ): string;
  encodeFunctionData(functionFragment: "thawSigner", values: [string]): string;
  encodeFunctionData(functionFragment: "withdraw", values: [string]): string;
  encodeFunctionData(
    functionFragment: "withdrawEscrowThawingPeriod",
    values?: undefined
  ): string;

  decodeFunctionResult(
    functionFragment: "MAX_THAWING_PERIOD",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "allocationIDTracker",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "authorizeSigner",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "authorizedSigners",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "cancelThawSigner",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "deposit", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "depositMany",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "escrowAccounts",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "escrowToken",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getEscrowAccountFromSignerAddress",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "getEscrowAmount",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "redeem", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "revokeAuthorizedSigner",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "revokeSignerThawingPeriod",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "staking", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "tapVerifier",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "thaw", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "thawSigner", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "withdraw", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "withdrawEscrowThawingPeriod",
    data: BytesLike
  ): Result;

  events: {
    "AuthorizeSigner(address,address)": EventFragment;
    "CancelThaw(address,address)": EventFragment;
    "CancelThawSigner(address,address,uint256)": EventFragment;
    "Deposit(address,address,uint256)": EventFragment;
    "Redeem(address,address,address,uint256,uint256)": EventFragment;
    "RevokeAuthorizedSigner(address,address)": EventFragment;
    "Thaw(address,address,uint256,uint256,uint256)": EventFragment;
    "ThawSigner(address,address,uint256)": EventFragment;
    "Withdraw(address,address,uint256)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "AuthorizeSigner"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "CancelThaw"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "CancelThawSigner"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Deposit"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Redeem"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "RevokeAuthorizedSigner"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Thaw"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "ThawSigner"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Withdraw"): EventFragment;
}

export interface AuthorizeSignerEventObject {
  signer: string;
  sender: string;
}
export type AuthorizeSignerEvent = TypedEvent<
  [string, string],
  AuthorizeSignerEventObject
>;

export type AuthorizeSignerEventFilter = TypedEventFilter<AuthorizeSignerEvent>;

export interface CancelThawEventObject {
  sender: string;
  receiver: string;
}
export type CancelThawEvent = TypedEvent<
  [string, string],
  CancelThawEventObject
>;

export type CancelThawEventFilter = TypedEventFilter<CancelThawEvent>;

export interface CancelThawSignerEventObject {
  sender: string;
  authorizedSigner: string;
  thawEndTimestamp: BigNumber;
}
export type CancelThawSignerEvent = TypedEvent<
  [string, string, BigNumber],
  CancelThawSignerEventObject
>;

export type CancelThawSignerEventFilter =
  TypedEventFilter<CancelThawSignerEvent>;

export interface DepositEventObject {
  sender: string;
  receiver: string;
  amount: BigNumber;
}
export type DepositEvent = TypedEvent<
  [string, string, BigNumber],
  DepositEventObject
>;

export type DepositEventFilter = TypedEventFilter<DepositEvent>;

export interface RedeemEventObject {
  sender: string;
  receiver: string;
  allocationID: string;
  expectedAmount: BigNumber;
  actualAmount: BigNumber;
}
export type RedeemEvent = TypedEvent<
  [string, string, string, BigNumber, BigNumber],
  RedeemEventObject
>;

export type RedeemEventFilter = TypedEventFilter<RedeemEvent>;

export interface RevokeAuthorizedSignerEventObject {
  sender: string;
  authorizedSigner: string;
}
export type RevokeAuthorizedSignerEvent = TypedEvent<
  [string, string],
  RevokeAuthorizedSignerEventObject
>;

export type RevokeAuthorizedSignerEventFilter =
  TypedEventFilter<RevokeAuthorizedSignerEvent>;

export interface ThawEventObject {
  sender: string;
  receiver: string;
  amount: BigNumber;
  totalAmountThawing: BigNumber;
  thawEndTimestamp: BigNumber;
}
export type ThawEvent = TypedEvent<
  [string, string, BigNumber, BigNumber, BigNumber],
  ThawEventObject
>;

export type ThawEventFilter = TypedEventFilter<ThawEvent>;

export interface ThawSignerEventObject {
  sender: string;
  authorizedSigner: string;
  thawEndTimestamp: BigNumber;
}
export type ThawSignerEvent = TypedEvent<
  [string, string, BigNumber],
  ThawSignerEventObject
>;

export type ThawSignerEventFilter = TypedEventFilter<ThawSignerEvent>;

export interface WithdrawEventObject {
  sender: string;
  receiver: string;
  amount: BigNumber;
}
export type WithdrawEvent = TypedEvent<
  [string, string, BigNumber],
  WithdrawEventObject
>;

export type WithdrawEventFilter = TypedEventFilter<WithdrawEvent>;

export interface Escrow extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: EscrowInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    MAX_THAWING_PERIOD(overrides?: CallOverrides): Promise<[BigNumber]>;

    allocationIDTracker(overrides?: CallOverrides): Promise<[string]>;

    authorizeSigner(
      signer: string,
      proofDeadline: BigNumberish,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    authorizedSigners(
      signer: string,
      overrides?: CallOverrides
    ): Promise<
      [string, BigNumber] & { sender: string; thawEndTimestamp: BigNumber }
    >;

    cancelThawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    deposit(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    depositMany(
      receivers: string[],
      amounts: BigNumberish[],
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    escrowAccounts(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<
      [BigNumber, BigNumber, BigNumber] & {
        balance: BigNumber;
        amountThawing: BigNumber;
        thawEndTimestamp: BigNumber;
      }
    >;

    escrowToken(overrides?: CallOverrides): Promise<[string]>;

    getEscrowAccountFromSignerAddress(
      signer: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<[Escrow.EscrowAccountStructOutput]>;

    getEscrowAmount(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    redeem(
      signedRAV: TAPVerifier.SignedRAVStruct,
      allocationIDProof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    revokeAuthorizedSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    revokeSignerThawingPeriod(overrides?: CallOverrides): Promise<[BigNumber]>;

    staking(overrides?: CallOverrides): Promise<[string]>;

    tapVerifier(overrides?: CallOverrides): Promise<[string]>;

    thaw(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    thawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    withdraw(
      receiver: string,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    withdrawEscrowThawingPeriod(
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;
  };

  MAX_THAWING_PERIOD(overrides?: CallOverrides): Promise<BigNumber>;

  allocationIDTracker(overrides?: CallOverrides): Promise<string>;

  authorizeSigner(
    signer: string,
    proofDeadline: BigNumberish,
    proof: BytesLike,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  authorizedSigners(
    signer: string,
    overrides?: CallOverrides
  ): Promise<
    [string, BigNumber] & { sender: string; thawEndTimestamp: BigNumber }
  >;

  cancelThawSigner(
    signer: string,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  deposit(
    receiver: string,
    amount: BigNumberish,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  depositMany(
    receivers: string[],
    amounts: BigNumberish[],
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  escrowAccounts(
    sender: string,
    receiver: string,
    overrides?: CallOverrides
  ): Promise<
    [BigNumber, BigNumber, BigNumber] & {
      balance: BigNumber;
      amountThawing: BigNumber;
      thawEndTimestamp: BigNumber;
    }
  >;

  escrowToken(overrides?: CallOverrides): Promise<string>;

  getEscrowAccountFromSignerAddress(
    signer: string,
    receiver: string,
    overrides?: CallOverrides
  ): Promise<Escrow.EscrowAccountStructOutput>;

  getEscrowAmount(
    sender: string,
    receiver: string,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  redeem(
    signedRAV: TAPVerifier.SignedRAVStruct,
    allocationIDProof: BytesLike,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  revokeAuthorizedSigner(
    signer: string,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  revokeSignerThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;

  staking(overrides?: CallOverrides): Promise<string>;

  tapVerifier(overrides?: CallOverrides): Promise<string>;

  thaw(
    receiver: string,
    amount: BigNumberish,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  thawSigner(
    signer: string,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  withdraw(
    receiver: string,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  withdrawEscrowThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;

  callStatic: {
    MAX_THAWING_PERIOD(overrides?: CallOverrides): Promise<BigNumber>;

    allocationIDTracker(overrides?: CallOverrides): Promise<string>;

    authorizeSigner(
      signer: string,
      proofDeadline: BigNumberish,
      proof: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>;

    authorizedSigners(
      signer: string,
      overrides?: CallOverrides
    ): Promise<
      [string, BigNumber] & { sender: string; thawEndTimestamp: BigNumber }
    >;

    cancelThawSigner(signer: string, overrides?: CallOverrides): Promise<void>;

    deposit(
      receiver: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    depositMany(
      receivers: string[],
      amounts: BigNumberish[],
      overrides?: CallOverrides
    ): Promise<void>;

    escrowAccounts(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<
      [BigNumber, BigNumber, BigNumber] & {
        balance: BigNumber;
        amountThawing: BigNumber;
        thawEndTimestamp: BigNumber;
      }
    >;

    escrowToken(overrides?: CallOverrides): Promise<string>;

    getEscrowAccountFromSignerAddress(
      signer: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<Escrow.EscrowAccountStructOutput>;

    getEscrowAmount(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    redeem(
      signedRAV: TAPVerifier.SignedRAVStruct,
      allocationIDProof: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>;

    revokeAuthorizedSigner(
      signer: string,
      overrides?: CallOverrides
    ): Promise<void>;

    revokeSignerThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;

    staking(overrides?: CallOverrides): Promise<string>;

    tapVerifier(overrides?: CallOverrides): Promise<string>;

    thaw(
      receiver: string,
      amount: BigNumberish,
      overrides?: CallOverrides
    ): Promise<void>;

    thawSigner(signer: string, overrides?: CallOverrides): Promise<void>;

    withdraw(receiver: string, overrides?: CallOverrides): Promise<void>;

    withdrawEscrowThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;
  };

  filters: {
    "AuthorizeSigner(address,address)"(
      signer?: string | null,
      sender?: string | null
    ): AuthorizeSignerEventFilter;
    AuthorizeSigner(
      signer?: string | null,
      sender?: string | null
    ): AuthorizeSignerEventFilter;

    "CancelThaw(address,address)"(
      sender?: string | null,
      receiver?: string | null
    ): CancelThawEventFilter;
    CancelThaw(
      sender?: string | null,
      receiver?: string | null
    ): CancelThawEventFilter;

    "CancelThawSigner(address,address,uint256)"(
      sender?: string | null,
      authorizedSigner?: string | null,
      thawEndTimestamp?: null
    ): CancelThawSignerEventFilter;
    CancelThawSigner(
      sender?: string | null,
      authorizedSigner?: string | null,
      thawEndTimestamp?: null
    ): CancelThawSignerEventFilter;

    "Deposit(address,address,uint256)"(
      sender?: string | null,
      receiver?: string | null,
      amount?: null
    ): DepositEventFilter;
    Deposit(
      sender?: string | null,
      receiver?: string | null,
      amount?: null
    ): DepositEventFilter;

    "Redeem(address,address,address,uint256,uint256)"(
      sender?: string | null,
      receiver?: string | null,
      allocationID?: string | null,
      expectedAmount?: null,
      actualAmount?: null
    ): RedeemEventFilter;
    Redeem(
      sender?: string | null,
      receiver?: string | null,
      allocationID?: string | null,
      expectedAmount?: null,
      actualAmount?: null
    ): RedeemEventFilter;

    "RevokeAuthorizedSigner(address,address)"(
      sender?: string | null,
      authorizedSigner?: string | null
    ): RevokeAuthorizedSignerEventFilter;
    RevokeAuthorizedSigner(
      sender?: string | null,
      authorizedSigner?: string | null
    ): RevokeAuthorizedSignerEventFilter;

    "Thaw(address,address,uint256,uint256,uint256)"(
      sender?: string | null,
      receiver?: string | null,
      amount?: null,
      totalAmountThawing?: null,
      thawEndTimestamp?: null
    ): ThawEventFilter;
    Thaw(
      sender?: string | null,
      receiver?: string | null,
      amount?: null,
      totalAmountThawing?: null,
      thawEndTimestamp?: null
    ): ThawEventFilter;

    "ThawSigner(address,address,uint256)"(
      sender?: string | null,
      authorizedSigner?: string | null,
      thawEndTimestamp?: null
    ): ThawSignerEventFilter;
    ThawSigner(
      sender?: string | null,
      authorizedSigner?: string | null,
      thawEndTimestamp?: null
    ): ThawSignerEventFilter;

    "Withdraw(address,address,uint256)"(
      sender?: string | null,
      receiver?: string | null,
      amount?: null
    ): WithdrawEventFilter;
    Withdraw(
      sender?: string | null,
      receiver?: string | null,
      amount?: null
    ): WithdrawEventFilter;
  };

  estimateGas: {
    MAX_THAWING_PERIOD(overrides?: CallOverrides): Promise<BigNumber>;

    allocationIDTracker(overrides?: CallOverrides): Promise<BigNumber>;

    authorizeSigner(
      signer: string,
      proofDeadline: BigNumberish,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    authorizedSigners(
      signer: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    cancelThawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    deposit(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    depositMany(
      receivers: string[],
      amounts: BigNumberish[],
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    escrowAccounts(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    escrowToken(overrides?: CallOverrides): Promise<BigNumber>;

    getEscrowAccountFromSignerAddress(
      signer: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    getEscrowAmount(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    redeem(
      signedRAV: TAPVerifier.SignedRAVStruct,
      allocationIDProof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    revokeAuthorizedSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    revokeSignerThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;

    staking(overrides?: CallOverrides): Promise<BigNumber>;

    tapVerifier(overrides?: CallOverrides): Promise<BigNumber>;

    thaw(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    thawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    withdraw(
      receiver: string,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    withdrawEscrowThawingPeriod(overrides?: CallOverrides): Promise<BigNumber>;
  };

  populateTransaction: {
    MAX_THAWING_PERIOD(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    allocationIDTracker(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    authorizeSigner(
      signer: string,
      proofDeadline: BigNumberish,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    authorizedSigners(
      signer: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    cancelThawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    deposit(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    depositMany(
      receivers: string[],
      amounts: BigNumberish[],
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    escrowAccounts(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    escrowToken(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    getEscrowAccountFromSignerAddress(
      signer: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    getEscrowAmount(
      sender: string,
      receiver: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    redeem(
      signedRAV: TAPVerifier.SignedRAVStruct,
      allocationIDProof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    revokeAuthorizedSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    revokeSignerThawingPeriod(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    staking(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    tapVerifier(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    thaw(
      receiver: string,
      amount: BigNumberish,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    thawSigner(
      signer: string,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    withdraw(
      receiver: string,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    withdrawEscrowThawingPeriod(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
