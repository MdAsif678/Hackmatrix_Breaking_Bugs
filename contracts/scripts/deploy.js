// Deploys ThreatRegistry and writes the files the backend needs:
//   ThreatRegistry.abi.json          (ABI, read by backend/app/registry/chain.py)
//   deployments/<network>.json       (address, tx, chain id, date — proof of deployment)
// Usage:  npm run deploy:local   |   npm run deploy:sepolia
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const net = await hre.ethers.provider.getNetwork();
  console.log(`Deploying ThreatRegistry to ${hre.network.name} (chain ${net.chainId}) from ${deployer.address}`);

  const registry = await hre.ethers.deployContract("ThreatRegistry");
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const tx = registry.deploymentTransaction();

  const artifact = await hre.artifacts.readArtifact("ThreatRegistry");
  fs.writeFileSync(path.join(__dirname, "..", "ThreatRegistry.abi.json"), JSON.stringify(artifact.abi, null, 2) + "\n");

  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const info = {
    network: hre.network.name,
    chain_id: Number(net.chainId),
    address,
    deploy_tx: tx ? tx.hash : null,
    deployer: deployer.address,
    deployed_at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(outDir, `${hre.network.name}.json`), JSON.stringify(info, null, 2) + "\n");

  console.log(`ThreatRegistry deployed at ${address}`);
  console.log(`Put this in .env:  REGISTRY_CONTRACT_ADDRESS=${address}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
