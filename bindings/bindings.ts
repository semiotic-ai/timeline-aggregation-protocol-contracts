// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
import { providers, Signer } from "ethers";

// Contract addresses
import * as DEPLOYED_CONTRACTS from "../addresses.json";

// Contract ABIs
import { TAPVerifier } from "./generated/ts-bindings/TAPVerifier";
import { AllocationIDTracker } from "./generated/ts-bindings/AllocationIDTracker";
import { Escrow } from "./generated/ts-bindings/Escrow";

// Contract factories
import { TAPVerifier__factory } from "./generated/ts-bindings/factories/TAPVerifier__factory";
import { AllocationIDTracker__factory } from "./generated/ts-bindings/factories/AllocationIDTracker__factory";
import { Escrow__factory } from "./generated/ts-bindings/factories/Escrow__factory";

export * from "./generated/ts-bindings";

export { connectContracts };
export type { NetworkContracts, DeployedContracts };

type DeployedContracts = typeof DEPLOYED_CONTRACTS;
type AddressBook = Record<
  string,
  { TAPVerifier: string; AllocationIDTracker: string; Escrow: string }
>;

interface NetworkContracts {
  escrow: Escrow;
  tapVerifier: TAPVerifier;
  allocationIDTracker: AllocationIDTracker;
}

const connectContracts = async (
  providerOrSigner: providers.Provider | Signer,
  chainId: number,
  addressBook: AddressBook | undefined
): Promise<NetworkContracts> => {
  const stringifiedChainId = `${chainId}`;
  if( addressBook == undefined && !(stringifiedChainId in DEPLOYED_CONTRACTS) )
    throw new Error(`chainId: '${chainId}' has no deployed contracts`);

  const deployedContracts = addressBook
    ? addressBook[stringifiedChainId]
    : DEPLOYED_CONTRACTS[stringifiedChainId as keyof typeof DEPLOYED_CONTRACTS];

  const getContractAddress = (contractName: keyof typeof deployedContracts) => {
    if (!deployedContracts[contractName]) {
      throw new Error(
        `Deployed contract '${contractName}' is undefined for chainId: '${chainId}'`
      );
    }
    const address = deployedContracts[contractName];

    if (!address) {
      throw new Error(
        `Deployed contract '${contractName}' address is undefined for chainId: '${chainId}'`
      );
    }
    return address;
  };

  const contracts: NetworkContracts = {
    escrow: Escrow__factory.connect(
      getContractAddress("Escrow"),
      providerOrSigner
    ),
    tapVerifier: TAPVerifier__factory.connect(
      getContractAddress("TAPVerifier"),
      providerOrSigner
    ),
    allocationIDTracker: AllocationIDTracker__factory.connect(
      getContractAddress("AllocationIDTracker"),
      providerOrSigner
    ),
  };

  return contracts;
};
