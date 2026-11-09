# Testing Report (Owner: P4 — everyone contributes)

Requirement: at least 3 suspicious and 3 benign test cases, with observed results.

## Security & Phishing Test Cases (P2 Contributions)

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

## Message & Scam Analysis Test Cases (P3 Contributions)

| # | Input | Type | Expected | Observed risk level | Key findings | Notes |
|---|---|---|---|---|---|---|
| 10 | `"Dear customer, your SBI account KYC is suspended. Immediately click http://sbi-kyc-update.example/login to verify your Aadhaar and PAN card, or your account will be blocked today."` | message | high_risk | high_risk | `message.impersonation`, `message.kyc_update`, `message.urgency`, `url.brand_in_subdomain` | Multi-vector attack combining SMS impersonation with phishing link. |
| 11 | `"Dear customer, an unauthorized transaction of ₹15,000 was initiated on your card. To cancel, please share the OTP sent to your mobile with our support executive."` | message | suspicious | suspicious | `message.otp_request` (High) | Direct OTP theft attempt attempting social engineering authorization. |
| 12 | `"Congratulations! You are selected for work from home data entry job with salary of ₹45,000 per month. Pay a refundable registration charge of ₹999 at payment.support@ybl to receive your appointment letter."` | message | suspicious | suspicious | `message.job_fee` (High) | Advance-fee employment scam demanding registration fee via UPI. |
| 13 | `"492018 is the OTP for your online transaction of Rs 1,499.00 at Flipkart using HDFC Bank card ending 8812. Do not share your OTP with anyone. -HDFC Bank"` | message | low_risk | low_risk | None (0 findings) | Authentic bank advisory containing "Do not share" correctly unflagged. |
| 14 | `"Your Amazon order with tracking #402-99128 is out for delivery today and will arrive by 7 PM. Please keep exact change ready if paying cash on delivery."` | message | low_risk | low_risk | None (0 findings) | Genuine delivery status alert containing no deceptive indicators. |
