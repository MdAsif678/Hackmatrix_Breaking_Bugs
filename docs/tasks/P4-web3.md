# P4 — Web3 Registry & Testing: step-by-step guide

## What you're building (plain words)

1. **A tiny smart contract.** It's a small program that lives on a blockchain and stores a "fingerprint" (hash)
   of each threat report. Once stored, nobody can change it, so anyone can later check that a report wasn't
   tampered with. You write it in your browser using **Remix**, with no installs.
2. **Deploy it** to **Sepolia**, a free practice blockchain where the money is fake.
3. **The registry screens** in the website: the "Register on-chain" button and the Verify page.
4. **The testing report and demo script**, which are required deliverables.

P1 connects the Python backend to your contract (`chain.py`). You give P1 the contract **address** and **ABI**.
The ABI is a JSON file that describes your contract's functions.

### Words you'll see
| Word | Meaning |
|---|---|
| **Wallet / MetaMask** | Browser extension that holds a blockchain account. It signs transactions. |
| **Sepolia** | Ethereum's free test network. Test ETH has no value. |
| **Faucet** | Website that gives you free test ETH |
| **Gas** | Small fee (in test ETH) paid for every write to the blockchain |
| **Transaction (tx) hash** | Receipt ID of a blockchain write. Shareable proof. |
| **Contract address** | Where your contract lives on the chain (`0x...`) |
| **ABI** | JSON description of the contract's functions, needed by the backend |
| **Etherscan** | Website to look up any address or transaction: https://sepolia.etherscan.io |

## Your files

| File | What |
|---|---|
| `contracts/ThreatRegistry.sol` | The contract source |
| `contracts/ThreatRegistry.abi.json` | ABI copied from Remix |
| `contracts/deployment.json` | Address, tx hash, network and date of the deployment |
| `frontend/src/features/registry/RegistryPanel.tsx` | "Register on-chain" box on the report page |
| `frontend/src/features/registry/VerifyPage.tsx` | Verify page |
| `docs/testing-report.md` | Test cases and results |
| `docs/demo-script.md` | What to click and say in the live demo |

Don't edit any other file. If you need something changed, ask P1.

---

## Step 0 — Wallet setup (30 min)

1. Install **MetaMask** in your browser and create a **brand-new wallet just for this hackathon**.
   ⚠️ Never use a wallet that has real money. We'll share this wallet's key with P1's backend.
2. In MetaMask, turn on "Show test networks" and switch to **Sepolia**.
3. Get free test ETH from a faucet, e.g. Google Cloud Web3 faucet (search "Google Cloud Sepolia faucet"), Alchemy or Infura.
   About 0.05 ETH is plenty.

✅ **Done when:** MetaMask shows a Sepolia balance above 0.

## Step 1 — Write the contract in Remix (2–3 hours)

1. Open https://remix.ethereum.org and create `ThreatRegistry.sol`.
2. It must have **exactly** these functions (from AGENTS.md §7). P1's backend calls them by these names:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatRegistry {
    // status: 0 = Active, 1 = Disputed, 2 = Revised
    struct Report { bytes32 reportHash; address submitter; uint256 timestamp; string riskLevel; uint8 status; uint256 revisions; }

    function submitReport(bytes32 reportHash, string calldata riskLevel) external returns (uint256 id);
    function reviseReport(uint256 id, bytes32 newHash) external;            // only the original submitter
    function disputeReport(uint256 id, string calldata reasonCode) external; // anyone; short code like "FALSE_POSITIVE"
    function getReport(uint256 id) external view returns (bytes32, address, uint256, string memory, uint8, uint256);
    function reportCount() external view returns (uint256);

    event ReportSubmitted(uint256 indexed id, bytes32 reportHash, address indexed submitter, uint256 timestamp);
    event ReportRevised(uint256 indexed id, bytes32 newHash, uint256 revision);
    event ReportDisputed(uint256 indexed id, address indexed by, string reasonCode);
}
```
   Ask your AI to fill in the bodies. Report ids start at **1**. Use `require` to reject a zero hash and
   unknown ids, and only let the original submitter call `reviseReport`.
3. **Compile** (Solidity compiler tab).
4. **Test in the fake chain first:** in the Deploy tab pick **"Remix VM"**, deploy, then click the functions:
   - `submitReport` with hash `0x1111111111111111111111111111111111111111111111111111111111111111` and `"high_risk"`
   - `getReport(1)` → you should see your hash and timestamp
   - `disputeReport(1, "FALSE_POSITIVE")` → status becomes 1
   - `getReport(99)` → should fail

✅ **Done when:** all of the above behave correctly in Remix VM.

**Remember:** only the hash and risk level go on-chain. Never URLs, messages or names, because blockchains are public forever.

## Step 2 — Deploy to Sepolia (30 min)

1. In the Remix Deploy tab, choose **"Injected Provider – MetaMask"** and confirm MetaMask is on Sepolia.
2. Click **Deploy** and confirm in MetaMask.
3. Copy the **contract address** and open it on https://sepolia.etherscan.io to see it live.
4. Optional but impressive: on Etherscan → Contract → "Verify and Publish" so anyone can read the source.
5. Save to the repo:
   - `contracts/ThreatRegistry.sol`: your source
   - `contracts/ThreatRegistry.abi.json`: Remix → Compiler tab → "ABI" copy button
   - `contracts/deployment.json`:
     ```json
     {"network": "sepolia", "chain_id": 11155111, "address": "0x...", "deploy_tx": "0x...", "deployed_at": "2026-11-08"}
     ```
6. **Hand-off to P1:** tell P1 the address. Send the wallet's **private key in a private DM, never in git**
   (MetaMask → account details → show private key). P1 puts it in `.env`.

✅ **Done when:** the contract shows on Sepolia Etherscan, the 3 files are pushed, and P1 has the address and key.

## Step 3 — Registry UI (React)

The basic versions already work: `RegistryPanel.tsx` and `VerifyPage.tsx`. Until P1 finishes `chain.py`, the
button shows "On-chain registry not implemented yet". That's expected. Improve them:

1. **Etherscan links:** turn the tx hash into a link to `https://sepolia.etherscan.io/tx/<tx_hash>`, and the
   contract address into `https://sepolia.etherscan.io/address/<address>`.
2. **Copy buttons** next to the hashes (`navigator.clipboard.writeText`).
3. **Verify page:** show the block time (`block_timestamp` is in seconds, so multiply by 1000 for `new Date()`),
   a big green ✓ / red ✗, and a short explanation: "The fingerprint we recalculated matches the one stored on the blockchain".
4. **Explain to normal users** in 1–2 sentences what "on-chain" means. Keep it friendly.

Run it: `cd frontend && npm run dev`. To see real results, the backend must be running too (see README).

✅ **Done when:** after P1's `chain.py` lands, you can register a report, click through to Etherscan and see the
transaction, then verify it and get a green tick.

## Step 4 — Testing report (`docs/testing-report.md`)

Required: **at least 3 suspicious and 3 genuine cases**. Aim for 10.
Run each one through the app and fill in the table: input, expected result, actual risk level, key findings
and a screenshot. Suggested cases (AGENTS.md §12):

- Genuine: `github.com`, `google.com`, your university website, a genuine bank OTP SMS
- Suspicious: `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com`, `paypa1-secure-login.com`,
  a fresh URL from the OpenPhish feed (copy text only, **never open it**), P3's scam messages
- **Tamper test:** register a report on-chain, then change one character of it in the database (ask P1 how), and
  verify again. It must show ✗ mismatch. This is a great demo moment.

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

> Read AGENTS.md and docs/tasks/P4-web3.md. I am P4. Write contracts/ThreatRegistry.sol implementing exactly
> the interface in Step 1, for Solidity ^0.8.24, so I can paste it into Remix. Explain how to test each
> function in Remix VM.

Do one step per prompt, and test in Remix VM before deploying.
