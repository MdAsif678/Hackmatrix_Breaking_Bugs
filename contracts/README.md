# contracts/ — ThreatRegistry smart contract (Hardhat)

Tamper-evident registry of threat-report fingerprints. Stores **only** a SHA-256 hash + risk level per report;
no URLs, messages or personal data. Interface: AGENTS.md §7. Backend bridge: `backend/app/registry/chain.py`.

| Path | What |
|---|---|
| `contracts/ThreatRegistry.sol` | Contract source (Solidity 0.8.24) |
| `test/ThreatRegistry.test.js` | Contract tests (register, ids, validation, revise + history, disputes) |
| `scripts/deploy.js` | Deploys and writes `ThreatRegistry.abi.json` + `deployments/<network>.json` |
| `ThreatRegistry.abi.json` | ABI loaded by the backend |
| `deployments/sepolia.json` | Proof of the public testnet deployment (address, tx, date) |

```bash
npm install
npm test                 # run the contract tests
npm run chain            # local blockchain at http://127.0.0.1:8545 (keep running)
npm run deploy:local     # deploy to it (prints the address for .env)
npm run deploy:sepolia   # deploy to Sepolia (needs SEPOLIA_RPC_URL + REGISTRY_PRIVATE_KEY in the root .env)
```

The local chain starts empty every time `npm run chain` restarts: run `npm run deploy:local` again (the address
stays `0x5FbDB2315678afecb367f032d93F642f64180aa3`). Reports registered on an earlier local chain can't be verified
afterwards. That's why the demo uses Sepolia.

Step-by-step for P4: [docs/tasks/P4-web3.md](../docs/tasks/P4-web3.md).
