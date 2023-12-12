// Copyright 2023-, Semiotic AI, Inc.
// SPDX-License-Identifier: Apache-2.0
import { providers, Signer } from "ethers";

// Contract addresses
import * as DEPLOYED_CONTRACTS from "../addresses.json";

// Contract ABIs
import { TAPVerifier } from "../generated/ts-bindings/TAPVerifier";
import { AllocationIDTracker } from "../generated/ts-bindings/AllocationIDTracker";
import { Escrow } from "../generated/ts-bindings/Escrow";

// Contract factories
import { TAPVerifier__factory } from "../generated/ts-bindings/factories/TAPVerifier__factory";
import { AllocationIDTracker__factory } from "../generated/ts-bindings/factories/AllocationIDTracker__factory";
import { Escrow__factory } from "../generated/ts-bindings/factories/Escrow__factory";

export { connectContracts };

interface NetworkContracts {
  escrow: Escrow;
  tapVerifier: TAPVerifier;
  allocationIDTracker: AllocationIDTracker;
}

type DeployedContracts = {
  421614: {
    TAPVerifier: "0xfC24cE7a4428A6B89B52645243662A02BA734ECF";
    AllocationIDTracker: "0xAaC28a10d707bbc6e02029f1bfDAEB5084b2aD11";
    Escrow: "0x1e4dC4f9F95E102635D8F7ED71c5CdbFa20e2d02";
  };
};

const connectContracts = async (
  providerOrSigner: providers.Provider | Signer,
  chainId: keyof DeployedContracts
): Promise<NetworkContracts> => {
  const deployedContracts = (DEPLOYED_CONTRACTS as DeployedContracts)[
    `${chainId}`
  ];

  if (!deployedContracts) {
    throw new Error(`chainId: '${chainId}' has no deployed contracts`);
  }

  const getContractAddress = (contractName: string) => {
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
