/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, ContractFactory, Signer } from "ethers";
import { Provider } from "ethers/providers";
import { UnsignedTransaction } from "ethers/utils/transaction";
import { BigNumberish } from "ethers/utils";

import { Escrow } from "../Escrow";

export class Escrow__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    escrowToken_: string,
    staking_: string,
    tapVerifier_: string,
    allocationIDTracker_: string,
    withdrawEscrowThawingPeriod_: BigNumberish,
    revokeSignerThawingPeriod_: BigNumberish,
    overrides?: UnsignedTransaction
  ): Promise<Escrow> {
    return super.deploy(
      escrowToken_,
      staking_,
      tapVerifier_,
      allocationIDTracker_,
      withdrawEscrowThawingPeriod_,
      revokeSignerThawingPeriod_,
      overrides
    ) as Promise<Escrow>;
  }
  getDeployTransaction(
    escrowToken_: string,
    staking_: string,
    tapVerifier_: string,
    allocationIDTracker_: string,
    withdrawEscrowThawingPeriod_: BigNumberish,
    revokeSignerThawingPeriod_: BigNumberish,
    overrides?: UnsignedTransaction
  ): UnsignedTransaction {
    return super.getDeployTransaction(
      escrowToken_,
      staking_,
      tapVerifier_,
      allocationIDTracker_,
      withdrawEscrowThawingPeriod_,
      revokeSignerThawingPeriod_,
      overrides
    );
  }
  attach(address: string): Escrow {
    return super.attach(address) as Escrow;
  }
  connect(signer: Signer): Escrow__factory {
    return super.connect(signer) as Escrow__factory;
  }
  static connect(address: string, signerOrProvider: Signer | Provider): Escrow {
    return new Contract(address, _abi, signerOrProvider) as Escrow;
  }
}

const _abi = [
  {
    type: "constructor",
    inputs: [
      {
        name: "escrowToken_",
        type: "address",
        internalType: "address",
      },
      {
        name: "staking_",
        type: "address",
        internalType: "address",
      },
      {
        name: "tapVerifier_",
        type: "address",
        internalType: "address",
      },
      {
        name: "allocationIDTracker_",
        type: "address",
        internalType: "address",
      },
      {
        name: "withdrawEscrowThawingPeriod_",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "revokeSignerThawingPeriod_",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "MAX_THAWING_PERIOD",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "allocationIDTracker",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract AllocationIDTracker",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "authorizeSigner",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
      {
        name: "proofDeadline",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "proof",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "authorizedSigners",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "sender",
        type: "address",
        internalType: "address",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "cancelThawSigner",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "deposit",
    inputs: [
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "depositMany",
    inputs: [
      {
        name: "receivers",
        type: "address[]",
        internalType: "address[]",
      },
      {
        name: "amounts",
        type: "uint256[]",
        internalType: "uint256[]",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "escrowAccounts",
    inputs: [
      {
        name: "sender",
        type: "address",
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "balance",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "amountThawing",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "escrowToken",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract IERC20",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getEscrowAccountFromSignerAddress",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "tuple",
        internalType: "struct Escrow.EscrowAccount",
        components: [
          {
            name: "balance",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "amountThawing",
            type: "uint256",
            internalType: "uint256",
          },
          {
            name: "thawEndTimestamp",
            type: "uint256",
            internalType: "uint256",
          },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getEscrowAmount",
    inputs: [
      {
        name: "sender",
        type: "address",
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "redeem",
    inputs: [
      {
        name: "signedRAV",
        type: "tuple",
        internalType: "struct TAPVerifier.SignedRAV",
        components: [
          {
            name: "rav",
            type: "tuple",
            internalType: "struct TAPVerifier.ReceiptAggregateVoucher",
            components: [
              {
                name: "allocationId",
                type: "address",
                internalType: "address",
              },
              {
                name: "timestampNs",
                type: "uint64",
                internalType: "uint64",
              },
              {
                name: "valueAggregate",
                type: "uint128",
                internalType: "uint128",
              },
            ],
          },
          {
            name: "signature",
            type: "bytes",
            internalType: "bytes",
          },
        ],
      },
      {
        name: "allocationIDProof",
        type: "bytes",
        internalType: "bytes",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeAuthorizedSigner",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "revokeSignerThawingPeriod",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "staking",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract IStaking",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "tapVerifier",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "address",
        internalType: "contract TAPVerifier",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "thaw",
    inputs: [
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "thawSigner",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "withdraw",
    inputs: [
      {
        name: "receiver",
        type: "address",
        internalType: "address",
      },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "withdrawEscrowThawingPeriod",
    inputs: [],
    outputs: [
      {
        name: "",
        type: "uint256",
        internalType: "uint256",
      },
    ],
    stateMutability: "view",
  },
  {
    type: "event",
    name: "AuthorizeSigner",
    inputs: [
      {
        name: "signer",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "CancelThaw",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "CancelThawSigner",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "authorizedSigner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Deposit",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Redeem",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "allocationID",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "expectedAmount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "actualAmount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "RevokeAuthorizedSigner",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "authorizedSigner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Thaw",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "totalAmountThawing",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "ThawSigner",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "authorizedSigner",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "event",
    name: "Withdraw",
    inputs: [
      {
        name: "sender",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "receiver",
        type: "address",
        indexed: true,
        internalType: "address",
      },
      {
        name: "amount",
        type: "uint256",
        indexed: false,
        internalType: "uint256",
      },
    ],
    anonymous: false,
  },
  {
    type: "error",
    name: "EscrowNotThawing",
    inputs: [],
  },
  {
    type: "error",
    name: "EscrowStillThawing",
    inputs: [
      {
        name: "currentTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "InputsLengthMismatch",
    inputs: [],
  },
  {
    type: "error",
    name: "InsufficientEscrow",
    inputs: [
      {
        name: "available",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "required",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "InsufficientThawAmount",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidRAVSigner",
    inputs: [],
  },
  {
    type: "error",
    name: "InvalidSignerProof",
    inputs: [],
  },
  {
    type: "error",
    name: "RevokeSignerThawingTooLong",
    inputs: [
      {
        name: "thawingPeriod",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "maxThawingPeriod",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "SignerAlreadyAuthorized",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
      {
        name: "authorizingSender",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "SignerNotAuthorized",
    inputs: [],
  },
  {
    type: "error",
    name: "SignerNotAuthorizedBySender",
    inputs: [
      {
        name: "signer",
        type: "address",
        internalType: "address",
      },
      {
        name: "sender",
        type: "address",
        internalType: "address",
      },
    ],
  },
  {
    type: "error",
    name: "SignerNotThawing",
    inputs: [],
  },
  {
    type: "error",
    name: "SignerStillThawing",
    inputs: [
      {
        name: "currentTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "thawEndTimestamp",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
  {
    type: "error",
    name: "WithdrawEscrowThawingTooLong",
    inputs: [
      {
        name: "thawingPeriod",
        type: "uint256",
        internalType: "uint256",
      },
      {
        name: "maxThawingPeriod",
        type: "uint256",
        internalType: "uint256",
      },
    ],
  },
];

const _bytecode =
  "0x6101406040523480156200001257600080fd5b5060405162001f5d38038062001f5d833981016040819052620000359162000164565b6276a7008211156200006b5760405163187cb4af60e31b8152600481018390526276a70060248201526044015b60405180910390fd5b6276a7008111156200009d57604051637224233360e11b8152600481018290526276a700602482015260440162000062565b6001600160a01b03868116608081905286821660a081905286831660c05291851660e05261010084905261012083905260405163095ea7b360e01b8152600481019290925260001960248301529063095ea7b3906044016020604051808303816000875af115801562000114573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906200013a9190620001d3565b50505050505050620001fe565b80516001600160a01b03811681146200015f57600080fd5b919050565b60008060008060008060c087890312156200017e57600080fd5b620001898762000147565b9550620001996020880162000147565b9450620001a96040880162000147565b9350620001b96060880162000147565b92506080870151915060a087015190509295509295509295565b600060208284031215620001e657600080fd5b81518015158114620001f757600080fd5b9392505050565b60805160a05160c05160e0516101005161012051611cd06200028d6000396000818161037f015261050d0152600081816103580152610eab01526000818161030a015261091201526000818161033101526106b10152600081816102060152818161078301526109a301526000818161017b01528181610ac101528181610c1f0152610daa0152611cd06000f3fe608060405234801561001057600080fd5b506004361061012c5760003560e01c80635d2b6a4e116100ad578063ba5fa36c11610071578063ba5fa36c1461032c578063c0c183cc14610353578063d780b2621461037a578063f95fadd4146103a1578063fee9f01f146103d657600080fd5b80635d2b6a4e1461023b578063638c079a1461028d57806371ece3aa146102a057806388e58443146102b3578063a156fa831461030557600080fd5b8063456b4316116100f4578063456b4316146101c857806347e7ef24146101db578063498df116146101ee5780634cf088d91461020157806351cff8d91461022857600080fd5b8063015cdd8014610131578063071b214c146101465780631354f019146101635780632fe319da1461017657806339aa7416146101b5575b600080fd5b61014461013f366004611752565b6103e9565b005b6101506276a70081565b6040519081526020015b60405180910390f35b610144610171366004611752565b6104a4565b61019d7f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b03909116815260200161015a565b6101446101c3366004611752565b61057a565b6101446101d63660046117b8565b610697565b6101446101e9366004611829565b610a7d565b6101506101fc366004611855565b610b26565b61019d7f000000000000000000000000000000000000000000000000000000000000000081565b610144610236366004611752565b610b51565b61026e610249366004611752565b600160208190526000918252604090912080549101546001600160a01b039091169082565b604080516001600160a01b03909316835260208301919091520161015a565b61014461029b3660046118d3565b610c8c565b6101446102ae366004611829565b610dd9565b6102ea6102c1366004611855565b600060208181529281526040808220909352908152208054600182015460029092015490919083565b6040805193845260208401929092529082015260600161015a565b61019d7f000000000000000000000000000000000000000000000000000000000000000081565b61019d7f000000000000000000000000000000000000000000000000000000000000000081565b6101507f000000000000000000000000000000000000000000000000000000000000000081565b6101507f000000000000000000000000000000000000000000000000000000000000000081565b6103b46103af366004611855565b610f28565b604080518251815260208084015190820152918101519082015260600161015a565b6101446103e436600461193f565b610fd1565b6001600160a01b03808216600090815260016020526040902080549091163314610452576001600160a01b0382811660008181526001602052604090819020549051634011883160e01b8152600481019290925290911660248201526044015b60405180910390fd5b60006001820181905581546040519182526001600160a01b03848116929116907fd8b6b01df10c3d082a614f3d21c7e68ecadf639beea68c244202152395285417906020015b60405180910390a35050565b6001600160a01b03808216600090815260016020526040902080549091163314610508576001600160a01b0382811660008181526001602052604090819020549051634011883160e01b815260048101929092529091166024820152604401610449565b6105327f0000000000000000000000000000000000000000000000000000000000000000426119a5565b6001820181905581546040519182526001600160a01b03848116929116907f2f0042c382a530431e38e20757092077c8ebe2988a9356a2d6cf042a620f69e990602001610498565b6001600160a01b038082166000908152600160205260409020805490911633146105de576001600160a01b0382811660008181526001602052604090819020549051634011883160e01b815260048101929092529091166024820152604401610449565b806001015460000361060357604051634f5388a960e11b815260040160405180910390fd5b428160010154111561063757600181015460405163cab2b4ed60e01b81524260048201526024810191909152604401610449565b6001600160a01b03808316600081815260016020819052604080832080546001600160a01b031916815590910182905584549051929316917ff91f0ecacc1bd2b3f1089fe11bb21ebc74002e429b7e4e52479c2cf9f418026d9190a35050565b6040516317ca930f60e31b81526000906001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000169063be549878906106e69087906004016119fd565b602060405180830381865afa158015610703573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906107279190611ab9565b6001600160a01b038082166000908152600160205260409020549192501661076257604051631291c84560e31b815260040160405180910390fd5b6001600160a01b0380821660009081526001602090815260408220548316927f00000000000000000000000000000000000000000000000000000000000000001690630e022923906107b690890189611752565b6040516001600160e01b031960e084901b1681526001600160a01b03909116600482015260240160a060405180830381865afa1580156107fa573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061081e9190611ad6565b51905060006108306020880188611752565b6001600160a01b03808516600090815260208181526040808320938716835292905281812054929350919061086b9060608b01908b01611b65565b6001600160801b031611610897576108896060890160408a01611b65565b6001600160801b03166108bc565b6001600160a01b03808516600090815260208181526040808320938716835292905220545b6001600160a01b038086166000908152602081815260408083209388168352929052908120805492935083929091906108f6908490611b80565b9091555050604051630f60f69960e01b81526001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001690630f60f6999061094d90879086908c908c90600401611b93565b600060405180830381600087803b15801561096757600080fd5b505af115801561097b573d6000803e3d6000fd5b505060405163469e080560e11b8152600481018490526001600160a01b0385811660248301527f0000000000000000000000000000000000000000000000000000000000000000169250638d3c100a9150604401600060405180830381600087803b1580156109e957600080fd5b505af11580156109fd573d6000803e3d6000fd5b50610a0f925050506020890189611752565b6001600160a01b03908116908481169086167faee47cdf925cf525fdae94f9777ee5a06cac37e1c41220d0a8a89ed154f62d1c610a5260608d0160408e01611b65565b604080516001600160801b039092168252602082018790520160405180910390a45050505050505050565b336000908152602081815260408083206001600160a01b038616845290915281208054839290610aae9084906119a5565b90915550610ae990506001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001633308461109c565b6040518181526001600160a01b0383169033907f5548c837ab068cf56a2c2479df0882a4922fd203edb7517321831d95078c5f6290602001610498565b6001600160a01b03808316600090815260208181526040808320938516835292905220545b92915050565b336000908152602081815260408083206001600160a01b038516845290915281206002810154909103610b97576040516358b8142560e01b815260040160405180910390fd5b4281600201541115610bcb576002810154604051635b2812bd60e11b81524260048201526024810191909152604401610449565b60008160000154826001015411610be6578160010154610be9565b81545b905080826000016000828254610bff9190611b80565b90915550506000600183018190556002830155610c466001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016338361110d565b6040518181526001600160a01b0384169033907f9b1bfa7fa9ee420a16e124f794c35ac9f90472acc99140eb2f6447c714cad8eb906020015b60405180910390a3505050565b828114610cac576040516371e9143160e01b815260040160405180910390fd5b6000805b84811015610d9c576000868683818110610ccc57610ccc611bc0565b9050602002016020810190610ce19190611752565b90506000858584818110610cf757610cf7611bc0565b9050602002013590508084610d0c91906119a5565b336000908152602081815260408083206001600160a01b0387168452909152812080549296508392909190610d429084906119a5565b90915550506040518181526001600160a01b0383169033907f5548c837ab068cf56a2c2479df0882a4922fd203edb7517321831d95078c5f629060200160405180910390a350508080610d9490611bd6565b915050610cb0565b50610dd26001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001633308461109c565b5050505050565b336000908152602081815260408083206001600160a01b0386168452909152812090829003610e70578060010154600003610e27576040516372b3382360e01b815260040160405180910390fd5b600060018201819055600282018190556040516001600160a01b0385169133917fb2486c13d5da6cdbddffe9f9ec53350f7f15033cec803877fd75ff89d734c9489190a3505050565b8054821115610e9f57805460405163180e21d960e31b8152600481019190915260248101839052604401610449565b60018101829055610ed07f0000000000000000000000000000000000000000000000000000000000000000426119a5565b6002820181905560018201546040805185815260208101929092528101919091526001600160a01b0384169033907f7f0b58772849ac31b2ed8c4369023242b80db5cb351a636850aa4eabb3a2850e90606001610c7f565b610f4c60405180606001604052806000815260200160008152602001600081525090565b6001600160a01b038084166000908152600160205260409020541680610f85576040516311c3376b60e11b815260040160405180910390fd5b6001600160a01b03908116600090815260208181526040808320959093168252938452819020815160608101835281548152600182015494810194909452600201549083015250919050565b6001600160a01b038481166000908152600160205260409020541615611031576001600160a01b0384811660008181526001602052604090819020549051635cc23d1560e01b815260048101929092529091166024820152604401610449565b61103d82828587611142565b6001600160a01b038416600081815260016020819052604080832080546001600160a01b0319163390811782559201839055519092917fb9bdd0621c52f9a047fe2a048fa04cdf987438d068ac524be8ea382aa3e94d2c91a350505050565b6040516001600160a01b03808516602483015283166044820152606481018290526111079085906323b872dd60e01b906084015b60408051601f198184030181529190526020810180516001600160e01b03166001600160e01b03199093169290921790915261125e565b50505050565b6040516001600160a01b03831660248201526044810182905261113d90849063a9059cbb60e01b906064016110d0565b505050565b814211156111635760405163110c1bd560e01b815260040160405180910390fd5b6040805146602082015290810183905233606090811b6bffffffffffffffffffffffff19169082015260009060740160405160208183030381529060405280519060200120905060006111e3827f19457468657265756d205369676e6564204d6573736167653a0a3332000000006000908152601c91909152603c902090565b9050826001600160a01b031661122f8288888080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061133392505050565b6001600160a01b0316146112565760405163110c1bd560e01b815260040160405180910390fd5b505050505050565b60006112b3826040518060400160405280602081526020017f5361666545524332303a206c6f772d6c6576656c2063616c6c206661696c6564815250856001600160a01b03166113579092919063ffffffff16565b90508051600014806112d45750808060200190518101906112d49190611bef565b61113d5760405162461bcd60e51b815260206004820152602a60248201527f5361666545524332303a204552433230206f7065726174696f6e20646964206e6044820152691bdd081cdd58d8d9595960b21b6064820152608401610449565b6000806000611342858561136e565b9150915061134f816113b3565b509392505050565b60606113668484600085611500565b949350505050565b60008082516041036113a45760208301516040840151606085015160001a611398878285856115db565b945094505050506113ac565b506000905060025b9250929050565b60008160048111156113c7576113c7611c11565b036113cf5750565b60018160048111156113e3576113e3611c11565b036114305760405162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e617475726500000000000000006044820152606401610449565b600281600481111561144457611444611c11565b036114915760405162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e677468006044820152606401610449565b60038160048111156114a5576114a5611c11565b036114fd5760405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202773272076616c604482015261756560f01b6064820152608401610449565b50565b6060824710156115615760405162461bcd60e51b815260206004820152602660248201527f416464726573733a20696e73756666696369656e742062616c616e636520666f6044820152651c8818d85b1b60d21b6064820152608401610449565b600080866001600160a01b0316858760405161157d9190611c4b565b60006040518083038185875af1925050503d80600081146115ba576040519150601f19603f3d011682016040523d82523d6000602084013e6115bf565b606091505b50915091506115d08783838761169f565b979650505050505050565b6000807f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08311156116125750600090506003611696565b6040805160008082526020820180845289905260ff881692820192909252606081018690526080810185905260019060a0016020604051602081039080840390855afa158015611666573d6000803e3d6000fd5b5050604051601f1901519150506001600160a01b03811661168f57600060019250925050611696565b9150600090505b94509492505050565b6060831561170e578251600003611707576001600160a01b0385163b6117075760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e74726163740000006044820152606401610449565b5081611366565b61136683838151156117235781518083602001fd5b8060405162461bcd60e51b81526004016104499190611c67565b6001600160a01b03811681146114fd57600080fd5b60006020828403121561176457600080fd5b813561176f8161173d565b9392505050565b60008083601f84011261178857600080fd5b50813567ffffffffffffffff8111156117a057600080fd5b6020830191508360208285010111156113ac57600080fd5b6000806000604084860312156117cd57600080fd5b833567ffffffffffffffff808211156117e557600080fd5b90850190608082880312156117f957600080fd5b9093506020850135908082111561180f57600080fd5b5061181c86828701611776565b9497909650939450505050565b6000806040838503121561183c57600080fd5b82356118478161173d565b946020939093013593505050565b6000806040838503121561186857600080fd5b82356118738161173d565b915060208301356118838161173d565b809150509250929050565b60008083601f8401126118a057600080fd5b50813567ffffffffffffffff8111156118b857600080fd5b6020830191508360208260051b85010111156113ac57600080fd5b600080600080604085870312156118e957600080fd5b843567ffffffffffffffff8082111561190157600080fd5b61190d8883890161188e565b9096509450602087013591508082111561192657600080fd5b506119338782880161188e565b95989497509550505050565b6000806000806060858703121561195557600080fd5b84356119608161173d565b935060208501359250604085013567ffffffffffffffff81111561198357600080fd5b61193387828801611776565b634e487b7160e01b600052601160045260246000fd5b80820180821115610b4b57610b4b61198f565b80356001600160801b03811681146119cf57600080fd5b919050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b6020815260008235611a0e8161173d565b6001600160a01b031660208381019190915283013567ffffffffffffffff808216808314611a3b57600080fd5b806040860152506001600160801b03611a56604087016119b8565b16606085015260608501359150601e19853603018212611a7557600080fd5b6020918501918201913581811115611a8c57600080fd5b803603831315611a9b57600080fd5b608080860152611aaf60a0860182856119d4565b9695505050505050565b600060208284031215611acb57600080fd5b815161176f8161173d565b600060a08284031215611ae857600080fd5b60405160a0810181811067ffffffffffffffff82111715611b1957634e487b7160e01b600052604160045260246000fd5b6040528251611b278161173d565b8082525060208301516020820152604083015160408201526060830151611b4d8161173d565b60608201526080928301519281019290925250919050565b600060208284031215611b7757600080fd5b61176f826119b8565b81810381811115610b4b57610b4b61198f565b6001600160a01b03858116825284166020820152606060408201819052600090611aaf90830184866119d4565b634e487b7160e01b600052603260045260246000fd5b600060018201611be857611be861198f565b5060010190565b600060208284031215611c0157600080fd5b8151801515811461176f57600080fd5b634e487b7160e01b600052602160045260246000fd5b60005b83811015611c42578181015183820152602001611c2a565b50506000910152565b60008251611c5d818460208701611c27565b9190910192915050565b6020815260008251806020840152611c86816040850160208701611c27565b601f01601f1916919091016040019291505056fea26469706673582212202b9fd767bfcf98098a814ceb721457836a9270c0918af5b07b0eaf216f870e6664736f6c63430008120033";
