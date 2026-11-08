// Hardhat config for the ThreatRegistry contract. Reads secrets from the repo-root .env (never committed).
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config({ path: require("path").join(__dirname, "..", ".env") });

const { SEPOLIA_RPC_URL, REGISTRY_PRIVATE_KEY } = process.env;
const isRealSepolia = SEPOLIA_RPC_URL && !/127\.0\.0\.1|localhost/.test(SEPOLIA_RPC_URL);

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    // `npm run chain` starts this local blockchain on http://127.0.0.1:8545 (chain id 31337)
    localhost: { url: "http://127.0.0.1:8545" },
    ...(isRealSepolia && REGISTRY_PRIVATE_KEY
      ? { sepolia: { url: SEPOLIA_RPC_URL, accounts: [REGISTRY_PRIVATE_KEY], chainId: 11155111 } }
      : {}),
  },
};
