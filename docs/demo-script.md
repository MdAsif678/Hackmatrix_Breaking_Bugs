# Demo script

About 6 minutes. Follows the judges' flow: **Submit → Investigate → Analyse → Risk → Report on-chain → Verify.**
Live site: https://trustlens-check.vercel.app

## Before you start (5 minutes earlier)

- Open https://trustlens-api-p05f.onrender.com/api/health. It should say `{"status":"ok"}` within a few seconds
  (if it takes ~1 minute, the free server was asleep; it is awake now).
- Open the live site in a fresh private window, so the intro animation plays.
- Keep these ready to paste:
  - Link: `paypa1-secure-login.com`
  - Message: `Dear customer, your SBI account KYC expires today. Update now at http://sbi-kyc-verify.example/login or your account will be blocked. Share the OTP sent to you to complete verification.`
- For the tamper step, have the backend running on a laptop with the Sepolia settings in `.env` (see README),
  and one report already sealed from that laptop.

## The walkthrough

| # | What to do | What to say |
|---|---|---|
| 1 | Let the intro play, move the mouse over the hero | "TrustLens checks suspicious links, websites and messages, and shows the evidence behind every verdict. The lens is the idea: look closer before you trust." |
| 2 | Scroll through *How it works* | "Five independent checks run in parallel: lookalike names, domain age, known phishing lists, the certificate, and the site's security settings." |
| 3 | Click **Check a link**, paste `paypa1-secure-login.com`, press **Check this link** | "This is the live pipeline. First we make sure the address is public, so nobody can point our server at internal machines. Then the five checks run at once, each with an 8 second limit." |
| 4 | Watch the results fill in, the verdict appear, the report open | "The verdict comes from fixed rules, not from the AI. Here it is Suspicious: the name copies PayPal with a 1 in place of the l." |
| 5 | On the report, point at the cards, the coverage ring and the per-check lines | "Every number here is computed from the findings. Coverage tells you how much evidence we could gather; below 50% we say Inconclusive instead of guessing." |
| 6 | Go to **Check**, switch to **Message or email**, paste the SBI message, run it | "Messages are analysed for scam patterns, and every link inside is checked too. Personal details are masked before the AI sees anything." |
| 7 | On the report, show *What this means* and the evidence list | "Gemini only explains the findings. Every sentence must point to a finding, and an answer that calls a site safe is thrown away." |
| 8 | In the side panel, press **Seal this report on-chain** | "We store only a SHA-256 fingerprint of the report on Ethereum Sepolia, never the link or the message, because a blockchain is public and permanent." |
| 9 | Click the Etherscan link | "Anyone can see the record. Nobody, including us, can change it." |
| 10 | Press **Verify this report** | "Verify recomputes the fingerprint from the stored report and compares it with the chain: it matches, it was sealed by the official TrustLens wallet, and within 24 hours of the report." |
| 11 | Laptop backend: `cd backend && python scripts/tamper_report.py <report-id>`, then verify that report again | "Now I quietly change the stored verdict to Low Risk, as an insider hiding a scam would. Verify immediately shows the report was changed after it was sealed." |
| 12 | Close on the History page | "Reports that share a server, certificate, phone number or UPI ID are linked as a possible campaign." |

## If something goes wrong

- **A check takes about a minute:** the free server was asleep. Wait; the next one is fast.
- **"Could not run" on a check:** that source did not answer in time. The report still shows what the other checks
  found, and coverage drops honestly.
- **The explanation says it was written from the rules:** the Gemini quota is used up (it resets at 1:30 pm India
  time). The verdict is unaffected, because it never came from the AI.
- **Seal fails:** the Sepolia wallet may be out of test ETH, or the network is congested. Show an already sealed
  report and its Etherscan record instead.
