# contracts/ — On-chain threat-report registry (Owner: P4)

Follow the step-by-step guide: [docs/tasks/P4-web3.md](../docs/tasks/P4-web3.md).

The contract is written, tested and deployed with **Remix + MetaMask** (no installs). This folder holds:

| File | What |
|---|---|
| `ThreatRegistry.sol` | Contract source (interface: AGENTS.md §7) |
| `ThreatRegistry.abi.json` | ABI copied from Remix; the backend (`registry/chain.py`) loads it |
| `deployment.json` | `{network, chain_id, address, deploy_tx, deployed_at}` |

Put the deployed address in `.env` (`REGISTRY_CONTRACT_ADDRESS`) and in the root README.

Only hashes + risk level go on-chain. Use a throwaway testnet wallet.
