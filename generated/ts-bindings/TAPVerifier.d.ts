/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, ContractTransaction, EventFilter, Signer } from "ethers";
import { Listener, Provider } from "ethers/providers";
import { Arrayish, BigNumber, BigNumberish, Interface } from "ethers/utils";
import { UnsignedTransaction } from "ethers/utils/transaction";
import { TypedEventDescription, TypedFunctionDescription } from ".";

interface TAPVerifierInterface extends Interface {
  functions: {
    eip712Domain: TypedFunctionDescription<{ encode([]: []): string }>;

    hashRAV: TypedFunctionDescription<{
      encode([rav]: [
        {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        }
      ]): string;
    }>;

    recoverRAVSigner: TypedFunctionDescription<{
      encode([signedRAV]: [
        {
          rav: {
            allocationId: string;
            timestampNs: BigNumberish;
            valueAggregate: BigNumberish;
          };
          signature: Arrayish;
        }
      ]): string;
    }>;

    verifyRAVSignature: TypedFunctionDescription<{
      encode([signedRAV, expectedAddress]: [
        {
          rav: {
            allocationId: string;
            timestampNs: BigNumberish;
            valueAggregate: BigNumberish;
          };
          signature: Arrayish;
        },
        string
      ]): string;
    }>;
  };

  events: {
    EIP712DomainChanged: TypedEventDescription<{
      encodeTopics([]: []): string[];
    }>;
  };
}

export class TAPVerifier extends Contract {
  connect(signerOrProvider: Signer | Provider | string): TAPVerifier;
  attach(addressOrName: string): TAPVerifier;
  deployed(): Promise<TAPVerifier>;

  on(event: EventFilter | string, listener: Listener): TAPVerifier;
  once(event: EventFilter | string, listener: Listener): TAPVerifier;
  addListener(eventName: EventFilter | string, listener: Listener): TAPVerifier;
  removeAllListeners(eventName: EventFilter | string): TAPVerifier;
  removeListener(eventName: any, listener: Listener): TAPVerifier;

  interface: TAPVerifierInterface;

  functions: {
    eip712Domain(
      overrides?: UnsignedTransaction
    ): Promise<
      [string, string, string, BigNumber, string, string, BigNumber[]] & {
        fields: string;
        name: string;
        version: string;
        chainId: BigNumber;
        verifyingContract: string;
        salt: string;
        extensions: BigNumber[];
      }
    >;

    "eip712Domain()"(
      overrides?: UnsignedTransaction
    ): Promise<
      [string, string, string, BigNumber, string, string, BigNumber[]] & {
        fields: string;
        name: string;
        version: string;
        chainId: BigNumber;
        verifyingContract: string;
        salt: string;
        extensions: BigNumber[];
      }
    >;

    hashRAV(
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      },
      overrides?: UnsignedTransaction
    ): Promise<string>;

    "hashRAV((address,uint64,uint128))"(
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      },
      overrides?: UnsignedTransaction
    ): Promise<string>;

    recoverRAVSigner(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      overrides?: UnsignedTransaction
    ): Promise<string>;

    "recoverRAVSigner(((address,uint64,uint128),bytes))"(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      overrides?: UnsignedTransaction
    ): Promise<string>;

    verifyRAVSignature(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      expectedAddress: string,
      overrides?: UnsignedTransaction
    ): Promise<boolean>;

    "verifyRAVSignature(((address,uint64,uint128),bytes),address)"(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      expectedAddress: string,
      overrides?: UnsignedTransaction
    ): Promise<boolean>;
  };

  eip712Domain(
    overrides?: UnsignedTransaction
  ): Promise<
    [string, string, string, BigNumber, string, string, BigNumber[]] & {
      fields: string;
      name: string;
      version: string;
      chainId: BigNumber;
      verifyingContract: string;
      salt: string;
      extensions: BigNumber[];
    }
  >;

  "eip712Domain()"(
    overrides?: UnsignedTransaction
  ): Promise<
    [string, string, string, BigNumber, string, string, BigNumber[]] & {
      fields: string;
      name: string;
      version: string;
      chainId: BigNumber;
      verifyingContract: string;
      salt: string;
      extensions: BigNumber[];
    }
  >;

  hashRAV(
    rav: {
      allocationId: string;
      timestampNs: BigNumberish;
      valueAggregate: BigNumberish;
    },
    overrides?: UnsignedTransaction
  ): Promise<string>;

  "hashRAV((address,uint64,uint128))"(
    rav: {
      allocationId: string;
      timestampNs: BigNumberish;
      valueAggregate: BigNumberish;
    },
    overrides?: UnsignedTransaction
  ): Promise<string>;

  recoverRAVSigner(
    signedRAV: {
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      };
      signature: Arrayish;
    },
    overrides?: UnsignedTransaction
  ): Promise<string>;

  "recoverRAVSigner(((address,uint64,uint128),bytes))"(
    signedRAV: {
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      };
      signature: Arrayish;
    },
    overrides?: UnsignedTransaction
  ): Promise<string>;

  verifyRAVSignature(
    signedRAV: {
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      };
      signature: Arrayish;
    },
    expectedAddress: string,
    overrides?: UnsignedTransaction
  ): Promise<boolean>;

  "verifyRAVSignature(((address,uint64,uint128),bytes),address)"(
    signedRAV: {
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      };
      signature: Arrayish;
    },
    expectedAddress: string,
    overrides?: UnsignedTransaction
  ): Promise<boolean>;

  filters: {
    EIP712DomainChanged(): EventFilter;
  };

  estimate: {
    eip712Domain(overrides?: UnsignedTransaction): Promise<BigNumber>;

    "eip712Domain()"(overrides?: UnsignedTransaction): Promise<BigNumber>;

    hashRAV(
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      },
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "hashRAV((address,uint64,uint128))"(
      rav: {
        allocationId: string;
        timestampNs: BigNumberish;
        valueAggregate: BigNumberish;
      },
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    recoverRAVSigner(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "recoverRAVSigner(((address,uint64,uint128),bytes))"(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    verifyRAVSignature(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      expectedAddress: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;

    "verifyRAVSignature(((address,uint64,uint128),bytes),address)"(
      signedRAV: {
        rav: {
          allocationId: string;
          timestampNs: BigNumberish;
          valueAggregate: BigNumberish;
        };
        signature: Arrayish;
      },
      expectedAddress: string,
      overrides?: UnsignedTransaction
    ): Promise<BigNumber>;
  };
}
