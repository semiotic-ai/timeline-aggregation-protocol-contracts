/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
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

export interface AllocationIDTrackerInterface extends utils.Interface {
  functions: {
    "isAllocationIDUsed(address,address)": FunctionFragment;
    "useAllocationID(address,address,bytes)": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic: "isAllocationIDUsed" | "useAllocationID"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "isAllocationIDUsed",
    values: [string, string]
  ): string;
  encodeFunctionData(
    functionFragment: "useAllocationID",
    values: [string, string, BytesLike]
  ): string;

  decodeFunctionResult(
    functionFragment: "isAllocationIDUsed",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "useAllocationID",
    data: BytesLike
  ): Result;

  events: {
    "AllocationIDUsed(address,address)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "AllocationIDUsed"): EventFragment;
}

export interface AllocationIDUsedEventObject {
  sender: string;
  allocationID: string;
}
export type AllocationIDUsedEvent = TypedEvent<
  [string, string],
  AllocationIDUsedEventObject
>;

export type AllocationIDUsedEventFilter =
  TypedEventFilter<AllocationIDUsedEvent>;

export interface AllocationIDTracker extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: AllocationIDTrackerInterface;

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
    isAllocationIDUsed(
      sender: string,
      allocationID: string,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    useAllocationID(
      sender: string,
      allocationID: string,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;
  };

  isAllocationIDUsed(
    sender: string,
    allocationID: string,
    overrides?: CallOverrides
  ): Promise<boolean>;

  useAllocationID(
    sender: string,
    allocationID: string,
    proof: BytesLike,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  callStatic: {
    isAllocationIDUsed(
      sender: string,
      allocationID: string,
      overrides?: CallOverrides
    ): Promise<boolean>;

    useAllocationID(
      sender: string,
      allocationID: string,
      proof: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>;
  };

  filters: {
    "AllocationIDUsed(address,address)"(
      sender?: string | null,
      allocationID?: string | null
    ): AllocationIDUsedEventFilter;
    AllocationIDUsed(
      sender?: string | null,
      allocationID?: string | null
    ): AllocationIDUsedEventFilter;
  };

  estimateGas: {
    isAllocationIDUsed(
      sender: string,
      allocationID: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    useAllocationID(
      sender: string,
      allocationID: string,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    isAllocationIDUsed(
      sender: string,
      allocationID: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    useAllocationID(
      sender: string,
      allocationID: string,
      proof: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;
  };
}