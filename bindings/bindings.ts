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
export type AddressBook = Record<
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

  const deployedContracts = (() => {
    if (addressBook !== undefined) return addressBook[stringifiedChainId];

    if (chainIdHasContracts(stringifiedChainId))
      return DEPLOYED_CONTRACTS[stringifiedChainId];

    throw new Error(`chainId: '${chainId}' has no deployed contracts`);
  })();

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

/**
 * Checks if a given chainId has contracts deployed.
 * @param chainId The chainId to check.
 * @returns A boolean indicating if the chainId has contracts deployed.
 */
const chainIdHasContracts = (
  chainId: string
): chainId is keyof DeployedContracts => chainId in DEPLOYED_CONTRACTS;
