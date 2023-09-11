const DEFAULT_TEST_MNEMONIC =
  'myth like bonus scare over problem client lizard pioneer submit female collect'
/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.19",
  networks: {
    hardhat: {
      chainId: 1337,
      loggingEnabled: false,
      gas: 12000000,
      gasPrice: 'auto',
      initialBaseFeePerGas: 0,
      blockGasLimit: 12000000,
      accounts: {
        mnemonic: DEFAULT_TEST_MNEMONIC,
      },
      mining: {
        auto: false,
        interval: 13000,
      },
      hardfork: 'london',
    },
  }
};

