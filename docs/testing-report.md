# Testing report

TrustLens is tested at three levels: automated unit tests, end-to-end runs of the real pipeline against live
websites and messages, and the blockchain seal/verify flow on Ethereum Sepolia. The project brief asks for at least
3 suspicious and 3 benign cases with observed results; this report has 27.

## Summary (re-run on 10 Nov 2026, current build)

| Level | Result |
|---|---|
| Backend unit tests (`cd backend && python -m pytest -q`) | **185 passed** |
| Smart contract tests (`cd contracts && npx hardhat test`) | **6 passed** |
| End-to-end cases below (live services, local backend) | **13 of 13 as expected** |
| Storage on Postgres (save, update, list, correlation, full API) | **Passed** against a real Postgres server |
| Blockchain: seal, verify, tamper detection on Sepolia | **Passed** (records #4 to #6) |

## End-to-end cases (10 Nov 2026)

Each input was submitted to the real API with live threat feeds, DNS, certificate checks and Gemini.
"Checks ran" counts the checks that completed (a message also runs the link checks on the link inside it).

| # | Case | Input | Expected | Observed | Checks ran | Time | Main reason | Pass |
|---|---|---|---|---|---|---|---|---|
| 1 | Lookalike (digit for letter) | `paypa1-secure-login.com` | Suspicious or worse | **Suspicious** | 3/5 | 5.6 s | High-severity finding: url.typosquat | ✅ |
| 2 | Lookalike (Cyrillic letter, punycode) | `xn--pple-43d.com` | Suspicious or worse | **Suspicious** | 3/5 | 6.0 s | High-severity finding: url.mixed_script | ✅ |
| 3 | Expired certificate | `expired-rsa-dv.ssl.com` | Suspicious or worse | **Suspicious** | 5/5 | 6.3 s | High-severity finding: tls.expired | ✅ |
| 4 | Revoked certificate | `revoked-rsa-dv.ssl.com` | High Risk | **High Risk** | 5/5 | 5.9 s | Critical finding(s): tls.revoked | ✅ |
| 5 | Live phishing URL from the OpenPhish feed | live entry `www.facebook-q.blogspot.com/…` (not linked) | Confirmed Malicious | **Confirmed Malicious** | 5/5 | 8.4 s | Matched trusted threat intelligence: threat_intel.openphish | ✅ |
| 6 | Benign: Google | `google.com` | Low Risk | **Low Risk** | 5/5 | 9.6 s | No significant malicious indicators within the available checks | ✅ |
| 7 | Benign: GitHub | `github.com` | Low Risk | **Low Risk** | 5/5 | 11.3 s | No significant malicious indicators within the available checks | ✅ |
| 8 | Benign: SBI official site | `onlinesbi.sbi` | Low Risk | **Low Risk** | 5/5 | 11.0 s | No significant malicious indicators within the available checks | ✅ |
| 9 | Fake KYC SMS | `Dear customer, your SBI account KYC expires today. Update no…` | High Risk | **High Risk** | 4/6 | 7.7 s | Multiple high-severity findings: message.impersonation, url.brand_in_subdomain | ✅ |
| 10 | Fake job offer asking for a fee | `Congratulations! You are selected for a work-from-home data …` | Suspicious or worse | **High Risk** | 1/1 | 8.2 s | Multiple high-severity findings: message.job_fee, message.payment_request | ✅ |
| 11 | Fake bank OTP request | `HDFC Bank: Your account will be suspended in 2 hours. To sto…` | Suspicious or worse | **Suspicious** | 1/1 | 7.0 s | High-severity finding: message.otp_request | ✅ |
| 12 | Benign OTP | `123456 is your OTP for login to your Swiggy account. Do not …` | Low Risk | **Low Risk** | 1/1 | 5.6 s | No significant malicious indicators within the available checks | ✅ |
| 13 | Benign delivery update | `Your Amazon order #402-1234567-1234567 has been delivered. T…` | Low Risk | **Low Risk** | 1/1 | 6.0 s | No significant malicious indicators within the available checks | ✅ |

Notes:
- The two lookalike domains do not exist, so the website checks (certificate, security headers) cannot run on
  them; the verdict comes from the address itself, as intended.
- The live phishing URL was taken from the OpenPhish public feed at test time. TrustLens never executes page
  scripts and only fetches pages through its SSRF-safe client.

## Blockchain seal and verification (Ethereum Sepolia)

Contract [`0x089F…cb2e`](https://sepolia.etherscan.io/address/0x089F4b08bcDBDEA5e3328D38676A63017266cb2e),
official wallet `0xf4f0…1256`.

| # | Case | Expected | Observed | Pass |
|---|---|---|---|---|
| 1 | Verify a report that was never sealed | "not sealed yet" | `not_registered` | ✅ |
| 2 | Seal a report (live site, Render) | Transaction succeeds, record created | Record #4, [tx `0xe1d7…46d7`](https://sepolia.etherscan.io/tx/0xe1d79106692fcfe6d954f7f9167e758c504838b63190baab68ea663bd1d346d7), about 25 s | ✅ |
| 3 | Verify the untouched sealed report | `verified` | Fingerprints match, submitter is the official wallet, status `active` | ✅ |
| 4 | Press *Seal* again on the same report | No second transaction | Returns record #4 again | ✅ |
| 5 | Edit a sealed report in the database (`scripts/tamper_report.py`, record #6) | `mismatch` | "The report was changed after it was sealed" | ✅ |
| 6 | Seal from a wallet that is not TrustLens | `untrusted_submitter` | Covered by unit tests (`tests/test_chain.py`) and `scripts/fake_seal_attack.py` | ✅ |
| 7 | Seal a report more than 24 h after it was created | `registered_late` | Covered by unit tests | ✅ |


## Security and phishing test cases (Md Azhar Khan)

| # | Input | Type | Expected | Observed risk level | Key findings | Notes |
|---|---|---|---|---|---|---|
| 1 | `https://wyshtap.cc/` | url | confirmed_malicious | confirmed_malicious | `threat_intel.openphish` (Critical, Authoritative) | Live match in OpenPhish zero-day phishing feed. |
| 2 | `https://paypa1-secure-login.com` | url | suspicious | suspicious | `url.typosquat` (High), `dns.no_resolution` (Medium) | Levenshtein distance 1 away from `paypal.com`. |
| 3 | `https://xn--pple-43d.com` | url | suspicious | suspicious | `url.mixed_script` (High), `url.punycode` (Medium), `dns.no_resolution` (Medium) | IDN homograph attack mixing Cyrillic `а` with Latin characters. |
| 4 | `http://user@192.168.1.1/login` | url | suspicious | suspicious | `url.ip_host` (High), `url.at_symbol` (High), `url.no_https` (Low), `url.credential_words` (Low) | Raw IP host and userinfo `@` obfuscation technique. |
| 5 | `https://sbi.kyc-update.in/verify` | url | suspicious | suspicious | `url.brand_in_subdomain` (High), `url.credential_words` (Low), `dns.no_resolution` (Medium) | Unauthorized domain spoofing State Bank of India brand. |
| 6 | `https://github.com` | url | low_risk | low_risk | None (Clean DNS, age > 15 yrs, valid TLS, complete security headers) | High-reputation developer platform; 100% coverage. |
| 7 | `https://www.google.com` | url | low_risk | low_risk | None (Official domain in `brands.json`, clean DNS, valid TLS) | Recognized official brand domain in whitelist. |
| 8 | `https://onlinesbi.sbi` | url | low_risk | low_risk | None (Recognized official SBI domain, valid DNS) | Legitimate banking portal recognized by brand heuristics. |
| 9 | `http://neverssl.com` | url | low_risk | low_risk | `headers.no_https_redirect` (Medium), `headers.missing_csp` (Low), `headers.missing_frame_protection` (Low) | Intentionally unencrypted site for captive portal testing. |

---

## Message and scam test cases (Md Shahzeb Ali)

| # | Input | Type | Expected | Observed risk level | Key findings | Notes |
|---|---|---|---|---|---|---|
| 10 | `"Dear customer, your SBI account KYC is suspended. Immediately click http://sbi-kyc-update.example/login to verify your Aadhaar and PAN card, or your account will be blocked today."` | message | high_risk | high_risk | `message.impersonation`, `message.kyc_update`, `message.urgency`, `url.brand_in_subdomain` | Multi-vector attack combining SMS impersonation with phishing link. |
| 11 | `"Dear customer, an unauthorized transaction of ₹15,000 was initiated on your card. To cancel, please share the OTP sent to your mobile with our support executive."` | message | suspicious | suspicious | `message.otp_request` (High) | Direct OTP theft attempt attempting social engineering authorization. |
| 12 | `"Congratulations! You are selected for work from home data entry job with salary of ₹45,000 per month. Pay a refundable registration charge of ₹999 at payment.support@ybl to receive your appointment letter."` | message | suspicious | suspicious | `message.job_fee` (High) | Advance-fee employment scam demanding registration fee via UPI. |
| 13 | `"492018 is the OTP for your online transaction of Rs 1,499.00 at Flipkart using HDFC Bank card ending 8812. Do not share your OTP with anyone. -HDFC Bank"` | message | low_risk | low_risk | None (0 findings) | Authentic bank advisory containing "Do not share" correctly unflagged. |
| 14 | `"Your Amazon order with tracking #402-99128 is out for delivery today and will arrive by 7 PM. Please keep exact change ready if paying cash on delivery."` | message | low_risk | low_risk | None (0 findings) | Genuine delivery status alert containing no deceptive indicators. |
