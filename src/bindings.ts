import { Provider, Signer } from "ethers";

// Contract addresses
import * as DEPLOYED_CONTRACTS from "../addresses.json";

// Contract ABIs
import { TAPVerifier } from "../out/ts-bindings/TAPVerifier";
import { AllocationIDTracker } from "../out/ts-bindings/AllocationIDTracker";
import { Escrow } from "../out/ts-bindings/Escrow";

// Contract factories
import { TAPVerifier__factory } from "../out/ts-bindings/factories/TAPVerifier__factory";
import { AllocationIDTracker__factory } from "../out/ts-bindings/factories/AllocationIDTracker__factory";
import { Escrow__factory } from "../out/ts-bindings/factories/Escrow__factory";

export { connectContracts };

interface NetworkContracts {
  escrow: Escrow;
  tapVerifier: TAPVerifier;
  allocationIDTracker: AllocationIDTracker;
}

type AddressBook = {
  [key: string]: { [key: string]: { address: string } };
};

const connectContracts = async (
  providerOrSigner: Provider | Signer,
  chainId: number,
  addressBook: AddressBook | undefined
): Promise<NetworkContracts> => {
  const deployedContracts = addressBook
    ? addressBook[`${chainId}`]
    : // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (DEPLOYED_CONTRACTS as any)[`${chainId}`];
  if (!deployedContracts) {
    throw new Error(`chainId: '${chainId}' has no deployed contracts`);
  }

  const getContractAddress = (contractName: string) => {
    if (!deployedContracts[contractName]) {
      throw new Error(
        `Deployed contract '${contractName}' is undefined for chainId: '${chainId}'`
      );
    }
    const address = deployedContracts[contractName].address;
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
      getContractAddress("AllocationIdTracker"),
      providerOrSigner
    ),
  };

  return contracts;
};
