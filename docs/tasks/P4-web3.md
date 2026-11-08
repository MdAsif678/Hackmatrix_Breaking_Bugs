# P4 — Web3 Registry & Testing: step-by-step guide

## What you're building (plain words)

✅ **Already done by P1:** the smart contract (`contracts/contracts/ThreatRegistry.sol`), its 6 automated tests,
a deploy script, and the backend connection. The whole flow (register → verify ✓ → tamper → ✗) already works on
a **local** blockchain running on a laptop.

Your job:
1. **Put the contract on Sepolia**, the free public practice blockchain, so judges can see it on Etherscan.
   It's one command once your wallet is ready.
2. **Polish the registry screens** in the website: the "Register on-chain" box and the Verify page.
3. **Testing report and demo script**, which are required deliverables.

### Words you'll see
| Word | Meaning |
|---|---|
| **Smart contract** | Small program living on a blockchain. Ours stores report fingerprints (hashes). |
| **Wallet / MetaMask** | Browser extension that holds a blockchain account. It signs transactions. |
| **Sepolia** | Ethereum's free test network. Test ETH has no value. |
| **Faucet** | Website that gives you free test ETH |
| **Gas** | Small fee (in test ETH) paid for every write to the blockchain |
| **Transaction (tx) hash** | Receipt ID of a blockchain write. Shareable proof. |
| **Contract address** | Where the contract lives on the chain (`0x...`) |
| **ABI** | JSON description of the contract's functions, needed by the backend |
| **Etherscan** | Website to look up any address or transaction: https://sepolia.etherscan.io |
| **Hardhat** | Tool we use to compile, test and deploy the contract (`contracts/` folder) |

## Your files

| File | What |
|---|---|
| `contracts/deployments/sepolia.json` | Written automatically by the deploy script (address, tx, date) |
| `frontend/src/features/registry/RegistryPanel.tsx` | "Register on-chain" box on the report page |
| `frontend/src/features/registry/VerifyPage.tsx` | Verify page |
| `docs/testing-report.md` | Test cases and results |
| `docs/demo-script.md` | What to click and say in the live demo |

Don't edit the contract or other files. If you need something changed, ask P1.

---

## Step 0 — Try it locally first (20 min)

This shows you how everything works before touching the real test network. Use 3 terminals:

```bash
cd contracts && npm install && npm test          # 6 contract tests should pass
npm run chain                                    # terminal 1: local blockchain (leave running)
npm run deploy:local                             # terminal 2: deploys, prints the address
```
Then follow "Local blockchain" in the README to point the backend at it, run the app, open any report, and click
**Register report on-chain** → **Verify integrity →**. You should see **✓ Integrity verified**.

## Step 1 — Wallet setup (30 min)

1. Install **MetaMask** in your browser and create a **brand-new wallet just for this hackathon**.
   ⚠️ Never use a wallet that has real money. The backend will use this wallet's key to register reports.
2. In MetaMask, turn on "Show test networks" and switch to **Sepolia**.
3. Get free test ETH from a faucet, e.g. Google Cloud Web3 faucet (search "Google Cloud Sepolia faucet"), Alchemy or Infura.
   About 0.05 ETH is plenty.
4. Get the wallet's private key: MetaMask → account menu → Account details → Show private key.
   **Never paste it in chat, Discord or git.** It only goes in your local `.env` file.

✅ **Done when:** MetaMask shows a Sepolia balance above 0.

## Step 2 — Deploy to Sepolia (15 min)

1. In the repo-root `.env` (copy from `.env.example` if you don't have one), set:
   ```
   SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
   REGISTRY_PRIVATE_KEY=0x<your test wallet's private key>
   ```
2. Deploy:
   ```bash
   cd contracts
   npm run deploy:sepolia
   ```
   It prints the contract address and writes `contracts/deployments/sepolia.json` + `contracts/ThreatRegistry.abi.json`.
3. Put the printed address in `.env` as `REGISTRY_CONTRACT_ADDRESS=0x...`, restart the backend, and register a report
   from the website. It takes ~15 seconds on Sepolia.
4. Open `https://sepolia.etherscan.io/address/<address>` and you'll see the contract and your transactions.
5. Optional but impressive: on Etherscan → Contract → "Verify and Publish" (Solidity 0.8.24, optimizer on, 200 runs,
   paste `contracts/contracts/ThreatRegistry.sol`) so anyone can read the source.
6. Commit `contracts/deployments/sepolia.json` and put the address + a transaction link in the root README
   ("Web3 demo" deliverable). Tell the team the address. Teammates who want to register reports from their laptop
   need the same three `.env` values — share the key **privately** (it's a throwaway test wallet).

✅ **Done when:** the contract shows on Sepolia Etherscan, a report registered from the website shows as a
transaction there, and the Verify page shows ✓.

**Remember:** only the hash and risk level go on-chain. Never URLs, messages or names, because blockchains are public forever.

## Step 3 — Registry UI (React)

The basic versions already work: `RegistryPanel.tsx` and `VerifyPage.tsx`. The verify API also returns
`explorer_url` (Etherscan link on Sepolia, empty on the local chain), `chain_status` (active/disputed/revised),
`block_timestamp` and `submitter` — use them. If the `.env` values are missing, the button shows
"On-chain registry not configured yet (missing: …)". Improve the screens:

1. **Etherscan links:** turn the tx hash into a link to `https://sepolia.etherscan.io/tx/<tx_hash>`, and the
   contract address into `https://sepolia.etherscan.io/address/<address>`.
2. **Copy buttons** next to the hashes (`navigator.clipboard.writeText`).
3. **Verify page:** show the block time (`block_timestamp` is in seconds, so multiply by 1000 for `new Date()`),
   a big green ✓ / red ✗, and **always show `detail`** (a ready-made plain-English sentence). Handle every `status`:
   - `verified` → ✓ green
   - `mismatch` → ✗ "This report was changed after it was sealed"
   - `untrusted_submitter` → ✗ "Sealed by someone other than TrustLens (fake seal)"
   - `registered_late` → ✗ "Sealed long after the report was made (possible edited version)"
   - `not_registered` → grey "Not sealed yet"
   (Right now the page shows "Hash mismatch" for every ✗ — that's the first thing to fix.)
4. **Explain to normal users** in 1–2 sentences what "on-chain" means. Keep it friendly.

Run it: `cd frontend && npm run dev`. To see real results, the backend must be running too (see README).

✅ **Done when:** you can register a report, click through to Etherscan and see the transaction, then verify it
and get a green tick.

## Step 4 — Testing report (`docs/testing-report.md`)

Required: **at least 3 suspicious and 3 genuine cases**. Aim for 10.
Run each one through the app and fill in the table: input, expected result, actual risk level, key findings
and a screenshot. Suggested cases (AGENTS.md §12):

- Genuine: `github.com`, `google.com`, your university website, a genuine bank OTP SMS
- Suspicious: `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com`, `paypa1-secure-login.com`,
  a fresh URL from the OpenPhish feed (copy text only, **never open it**), P3's scam messages
- **Tamper test:** register a report on-chain, then run `python scripts/tamper_report.py <report_id>` (from
  `backend/`, venv active) and verify again. It must show ✗ mismatch. This is a great demo moment.

If a result looks wrong (a false positive or a missed scam), tell the owner of that check.

## Step 5 — Demo script (`docs/demo-script.md`)

A 5-minute script that follows the judges' flow: **Submit → Investigate → Analyse → Risk → Report on-chain → Verify**.
1. Genuine site → Low Risk (show we don't cry wolf)
2. Lookalike phishing URL → High Risk, with evidence
3. Bad certificate (`expired.badssl.com`) → TLS findings
4. Scam SMS → AI explanation with quotes
5. Register on-chain → Etherscan → Verify ✓ → tamper → Verify ✗

Write exactly what to click and one sentence to say at each step. Rehearse it with the team.

---

## Prompt to give your AI

> Read AGENTS.md and docs/tasks/P4-web3.md. I am P4. Help me with Step 3: improve
> frontend/src/features/registry/RegistryPanel.tsx and VerifyPage.tsx as described. Only edit those two files.

For Steps 1–2 just follow the guide; ask your AI if a command fails, and paste the error (never your private key).
