# PHISH-001 — Phishing Email Investigation Report

## 1. Executive Summary

A phishing email impersonating Microsoft was identified and investigated.

The email used the display name "Microsoft Account Team" and claimed to originate from:

noreply@microsoftonline-verify.com

The investigation identified multiple suspicious indicators, including SPF, DKIM, and DMARC authentication failures, suspicious sender infrastructure, a Microsoft-themed sender domain, and a shortened Bitly URL.

The exact shortened URL was investigated using URLScan and VirusTotal. The URL currently returns HTTP 404, while VirusTotal shows one security vendor classifying the exact URL as phishing.

Based on the combined evidence, PHISH-001 is classified as:

PHISHING — HIGH CONFIDENCE

No evidence currently establishes that the recipient clicked the URL, submitted credentials, executed malware, or experienced account compromise.

---

## 2. Incident Details

| Field | Value |
|---|---|
| Case ID | PHISH-001 |
| Incident Type | Phishing |
| Date in Email | 2026-02-06 |
| Sender | noreply@microsoftonline-verify.com |
| Display Name | Microsoft Account Team |
| Subject | [Action Required] Unusual sign-in activity on your account |
| Recipient | jacobcookofficial@gmail.com |
| Classification | Phishing — High Confidence |
| Compromise | Not Established |

---

## 3. Email Analysis

### Sender

Display name: `Microsoft Account Team`

Sender: `noreply@microsoftonline-verify.com`

Return-Path: `noreply@microsoftonline-verify.com`

The sender domain uses Microsoft-related terminology while not being Microsoft's legitimate domain.

### Subject

[Action Required] Unusual sign-in activity on your account

The subject creates urgency around account security and attempts to encourage the recipient to take action.

---

## 4. Email Authentication

### SPF

Result: `FAIL`

The sending IP: `178.238.225.91` was not authorized by the SPF policy associated with the sender domain.

### DKIM

Result: `FAIL`

Authentication results showed:
`
header.i=@microsoftonline-verify.com
header.s=default
header.b=none
`
No successful DKIM authentication was established.

### DMARC

Result: `FAIL`

Authentication results showed: `header.from=microsoftonline-verify.com`

DMARC evaluation failed.

### Authentication Assessment

SPF, DKIM, and DMARC all failed for the message.

This provides strong evidence that the message did not successfully authenticate as an authorized message from the sender domain.

---

## 5. Sender Infrastructure

Sending IP: `178.238.225.91`

Received hostname: `vps-291847.contabo.net`

Reverse DNS: `vmi3247644.contaboserver.net`

Hosting provider: `Contabo GmbH`

ASN: `AS51167`

WHOIS information places the IP within Contabo infrastructure.

The hosting provider itself is not considered malicious based solely on this evidence.

---

## 6. Sender Domain Investigation

Domain: `microsoftonline-verify.com`

Current DNS status: `NXDOMAIN`

Current records:

- A: None
- MX: None
- TXT: None
- NS: None

Current Verisign RDAP query: `HTTP 404`

The domain was present in the February 6, 2026 email but is currently not resolving.

The current state cannot establish the historical registration or DNS state of the domain on the date of delivery.

---

## 7. URL Investigation

Extracted URL: `https://bit.ly/3vF9xKz`

URL type: `Shortened URL`

### URLScan

- Current result: HTTP 404
- Redirects observed: None
- Main domain: bit.ly
- Main IP: 67.199.248.11
- ASN: AS396982 — Google Cloud Platform
- Verdict: No classification

### VirusTotal

- Detection: 1/91 security vendors
- Flagging vendor: Phishing Database
- Classification: Phishing
- Current status: 404
- First displayed submission: 2026-04-13
- Last displayed submission: 2026-04-17

The VirusTotal result provides supporting evidence that the exact shortened URL has been associated with phishing.

The original destination could not be recovered from the current URLScan scan.

---

## 8. Indicators of Compromise

### Email

- noreply@microsoftonline-verify.com
- microsoftonline-verify.com

### Network

- 178.238.225.91
- vmi3247644.contaboserver.net
- vps-291847.contabo.net

### URL

- https://bit.ly/3vF9xKz
- bit.ly
- 67.199.248.11

---

## 9. MITRE ATT&CK Mapping

### T1566.002 — Phishing: Spearphishing Link

Evidence:

The email contains a shortened URL intended to direct the recipient to an external web resource.

Confidence: High

### T1036.005 — Masquerading: Match Legitimate Name or Location

Evidence:

The sender uses the display name "Microsoft Account Team" and a Microsoft-themed sender domain.

Confidence: Medium

No additional techniques were mapped because the available evidence does not establish credential theft, malware execution, account compromise, persistence, or data exfiltration.

---

## 10. Investigation Timeline

| Date/Time | Event |
|---|---|
| 2026-02-06 17:14:18 UTC | Email timestamp |
| 2026-02-06 | Microsoft impersonation observed |
| 2026-02-06 | Email sent from 178.238.225.91 |
| 2026-02-06 | SPF failed |
| 2026-02-06 | DKIM failed |
| 2026-02-06 | DMARC failed |
| 2026-02-06 | Bitly URL observed in email |
| 2026-09-22 | DNS investigation performed |
| 2026-09-22 | RDAP investigation performed |
| 2026-09-22 | Sender infrastructure investigated |
| 2026-09-22 | URLScan investigation performed |
| 2026-09-22 | VirusTotal investigation performed |
| 2026-09-23 | Evidence correlation and report preparation |

---

## 11. Evidence Correlation

The investigation identified the following combination of evidence:

1. Microsoft impersonation.
2. Microsoft-themed sender domain.
3. SPF failure.
4. DKIM failure.
5. DMARC failure.
6. Suspicious sender infrastructure.
7. Account-security urgency in the subject.
8. Shortened URL.
9. VirusTotal phishing classification for the exact URL.
10. Current inactivity of the sender domain and shortened URL.

Taken together, these findings are consistent with a phishing email designed to impersonate Microsoft and direct the recipient toward an external URL.

---

## 12. Incident Response

### Containment

- Quarantine the email.
- Search for identical or related messages.
- Search for the identified IOCs across security controls.
- Block confirmed malicious indicators where appropriate.
- Preserve the original email and forensic evidence.

### User Investigation

Determine whether the recipient:

- Opened the email.
- Clicked the URL.
- Entered credentials.
- Downloaded a file.
- Observed suspicious account activity.

### If Credentials Were Submitted

- Reset the affected password.
- Revoke active sessions.
- Review authentication activity.
- Review MFA/security-setting changes.
- Escalate for account-compromise investigation.

### Endpoint Investigation

If the URL was clicked:

- Review browser activity.
- Review DNS/proxy logs.
- Review EDR telemetry.
- Check for downloaded files.
- Search for additional indicators.

---

## 13. Limitations

The investigation has several limitations:

- The original Bitly destination could not be recovered from the current URLScan scan.
- The sender domain is currently NXDOMAIN, so its historical DNS state could not be established from current DNS queries.
- Current RDAP did not return a registration object.
- VirusTotal's displayed phishing classification is from April 2026, after the February 2026 email.
- No evidence currently establishes user interaction with the phishing URL.
- No evidence currently establishes credential compromise or endpoint compromise.

---

## 14. Final Assessment

Classification: `PHISHING — HIGH CONFIDENCE`

The available evidence strongly supports classification of PHISH-001 as a phishing email.

The investigation establishes suspicious sender identity, failed email authentication, suspicious infrastructure, Microsoft impersonation, and a shortened URL with supporting phishing reputation data.

However, the investigation does not establish that the recipient interacted with the URL or that an account or endpoint was compromised.

Further investigation of organizational email, web, authentication, and endpoint telemetry would be required to determine whether the phishing campaign resulted in user interaction or compromise.
