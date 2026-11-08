# contracts/ — On-chain threat-report registry (Owner: P4)

Set up a Hardhat project in this folder:

```bash
cd contracts
npx hardhat --init        # choose a TypeScript or JavaScript project
```

Then implement `contracts/ThreatRegistry.sol` with the interface in AGENTS.md §7,
write tests, and deploy to Sepolia. Put the deployed address in `.env`
(`REGISTRY_CONTRACT_ADDRESS`) and in the root README.

Only hashes + risk level go on-chain. Use a throwaway testnet wallet.
