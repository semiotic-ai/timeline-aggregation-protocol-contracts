/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, ContractTransaction, EventFilter, Signer } from "ethers";
import { Listener, Provider } from "ethers/providers";
import { Arrayish, BigNumber, BigNumberish, Interface } from "ethers/utils";
import { UnsignedTransaction } from "ethers/utils/transaction";
import { TypedEventDescription, TypedFunctionDescription } from ".";

interface IERC20Interface extends Interface {
  functions: {
    allowance: TypedFunctionDescription<{
      encode([owner, spender]: [string, string]): string;
    }>;

    approve: TypedFunctionDescription<{
      encode([spender, amount]: [string, BigNumberish]): string;
    }>;

    balanceOf: TypedFunctionDescription<{
      encode([account]: [string]): string;
    }>;

    totalSupply: TypedFunctionDescription<{ encode([]: []): string }>;

    transfer: TypedFunctionDescription<{
      encode([to, amount]: [string, BigNumberish]): string;
    }>;

    transferFrom: TypedFunctionDescription<{
      encode([from, to, amount]: [string, string, BigNumberish]): string;
    }>;
  };

  events: {
    Approval: TypedEventDescription<{
      encodeTopics([owner, spender, value]: [
        string | null,
        string | null,
        null
      ]): string[];
    }>;

    Transfer: TypedEventDescription<{
      encodeTopics([from, to, value]: [
        string | null,
        string | null,
        null
      ]): string[];
    }>;
  };
}

export class IERC20 extends Contract {
  connect(signerOrProvider: Signer | Provider | string): IERC20;
  attach(addressOrName: string): IERC20;
  deployed(): Promise<IERC20>;

  on(event: EventFilter | string, listener: Listener): IERC20;
  once(event: EventFilter | string, listener: Listener): IERC20;
  addListener(eventName: EventFilter | string, listener: Listener): IERC20;
  removeAllListeners(eventName: EventFilter | string): IERC20;
  removeListener(eventName: any, listener: Listener): IERC20;

  interface: IERC20Interface;

  functions: {
    allowance(
      owner: string,
      spender: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "allowance(address,address)"(
      owner: string,
      spender: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;

    "approve(address,uint256)"(
      spender: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;

    balanceOf(
      account: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "balanceOf(address)"(
      account: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    totalSupply(overrides?: UnsignedTransaction): Promise<BigNumber>;

    "totalSupply()"(overrides?: UnsignedTransaction): Promise<BigNumber>;

    transfer(
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;

    "transfer(address,uint256)"(
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;

    transferFrom(
      from: string,
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;

    "transferFrom(address,address,uint256)"(
      from: string,
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<ContractTransaction>;
  };

  allowance(
    owner: string,
    spender: string,
    overrides?: UnsignedTransaction
  ): Promise<BigNumber>;

  "allowance(address,address)"(
    owner: string,
    spender: string,
    overrides?: UnsignedTransaction
  ): Promise<BigNumber>;

  approve(
    spender: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  "approve(address,uint256)"(
    spender: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  balanceOf(
    account: string,
    overrides?: UnsignedTransaction
  ): Promise<BigNumber>;

  "balanceOf(address)"(
    account: string,
    overrides?: UnsignedTransaction
  ): Promise<BigNumber>;

  totalSupply(overrides?: UnsignedTransaction): Promise<BigNumber>;

  "totalSupply()"(overrides?: UnsignedTransaction): Promise<BigNumber>;

  transfer(
    to: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  "transfer(address,uint256)"(
    to: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  transferFrom(
    from: string,
    to: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  "transferFrom(address,address,uint256)"(
    from: string,
    to: string,
    amount: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<ContractTransaction>;

  filters: {
    Approval(
      owner: string | null,
      spender: string | null,
      value: null
    ): EventFilter;

    Transfer(from: string | null, to: string | null, value: null): EventFilter;
  };

  estimate: {
    allowance(
      owner: string,
      spender: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "allowance(address,address)"(
      owner: string,
      spender: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    approve(
      spender: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "approve(address,uint256)"(
      spender: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    balanceOf(
      account: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "balanceOf(address)"(
      account: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    totalSupply(overrides?: UnsignedTransaction): Promise<BigNumber>;

    "totalSupply()"(overrides?: UnsignedTransaction): Promise<BigNumber>;

    transfer(
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "transfer(address,uint256)"(
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    transferFrom(
      from: string,
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "transferFrom(address,address,uint256)"(
      from: string,
      to: string,
      amount: BigNumberish,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;
  };
}
