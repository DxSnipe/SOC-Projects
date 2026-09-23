# PHISH-001 — Phishing Email Investigation

A SOC L1-style phishing email investigation focused on email header analysis, authentication validation, sender infrastructure investigation, URL analysis, IOC extraction, MITRE ATT&CK mapping, and incident response.

---

## 🎯 Objective

Investigate a suspicious email impersonating Microsoft and determine whether the available evidence supports classification as a phishing attempt.

The investigation was performed using the original `.eml` evidence and passive analysis techniques.

---

## 🧪 Investigation Scenario

The email presents itself as a Microsoft account-security notification.

**Subject:**

`[Action Required] Unusual sign-in activity on your account`

**Sender:**

`noreply@microsoftonline-verify.com`

**Display Name:**

`Microsoft Account Team`

The message contains a shortened Bitly URL.

---

## 🛠️ Tools & Technologies

- Linux
- Bash
- grep
- dig
- curl
- WHOIS
- RDAP
- URLScan
- VirusTotal
- MITRE ATT&CK
- Email headers
- DNS investigation
- Threat intelligence

---

## 🔎 Investigation Workflow

```text
Email Evidence
      ↓
Header Analysis
      ↓
SPF / DKIM / DMARC
      ↓
DNS / RDAP
      ↓
Sender Infrastructure
      ↓
URL Extraction
      ↓
URLScan
      ↓
VirusTotal
      ↓
IOC Extraction
      ↓
Evidence Correlation
      ↓
MITRE ATT&CK Mapping
      ↓
Incident Response
      ↓
Final Assessment
```

## Email Authentication Findings

| Control | Result |
| ------- | ------ |
| SPF     | FAIL   |
| DKIM    | FAIL   |
| DMARC   | FAIL   |
All three authentication mechanisms failed for the investigated message.

Sender Infrastructure

Sender IP:

178.238.225.91

Reverse DNS:

vmi3247644.contaboserver.net

Received hostname:

vps-291847.contabo.net

Network provider:

Contabo GmbH

ASN:

AS51167

The IP was associated with commercial hosting infrastructure. The hosting provider itself was not classified as malicious based solely on this evidence.

URL Investigation

Extracted URL:

https://bit.ly/3vF9xKz

URLScan
Current result: HTTP 404
Redirects captured: None
Main domain: bit.ly
Main IP: 67.199.248.11
ASN: AS396982
Verdict: No classification
VirusTotal
Detection: 1/91 security vendors
Flagging vendor: Phishing Database
Classification: Phishing
Current status: 404

The original destination of the shortened URL could not be recovered from the current URLScan scan.

Evidence Correlation

The investigation identified multiple related indicators:

Microsoft impersonation
Microsoft-themed sender domain
SPF failure
DKIM failure
DMARC failure
Suspicious sender infrastructure
Account-security urgency
Shortened URL
Supporting phishing reputation data from VirusTotal

The combined evidence supports classification of the email as a phishing attempt.

## MITRE ATT&CK Mapping

| Technique | Name                                            | Evidence                             |
| --------- | ----------------------------------------------- | ------------------------------------ |
| T1566.002 | Phishing: Spearphishing Link                    | Shortened URL contained in the email |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Microsoft impersonation              |

Techniques not supported by evidence were intentionally excluded.

Incident Response

Recommended SOC actions:

Quarantine the phishing email.
Search for related messages across mailboxes.
Hunt for the identified IOCs.
Determine whether the recipient clicked the URL.
Determine whether credentials were submitted.
Review authentication activity if interaction occurred.
Review endpoint, DNS, proxy, and EDR telemetry if the URL was accessed.
Reset credentials and revoke sessions if compromise is confirmed.

Final Assessment

Classification: PHISHING — HIGH CONFIDENCE

The available evidence strongly supports classification of PHISH-001 as a phishing email.

However:

User interaction is unknown.
Credential compromise is not established.
Endpoint compromise is not established.
The original Bitly destination could not be recovered.
Current DNS state does not establish historical DNS state.
VirusTotal's displayed phishing classification occurred after the original email date.

Further organizational telemetry would be required to determine whether the campaign resulted in successful user interaction or compromise.

## Project Structure

```text
phishing-email-investigation/
│
├── README.md
├── evidence/
│   ├── PHISH-001.eml
│   └── PHISH-001.sha256.txt
│
├── iocs/
│   └── PHISH-001-iocs.md
│
├── notes/
│   ├── case-details.md
│   ├── header-analysis.md
│   ├── authentication-analysis.md
│   ├── dns-analysis.md
│   ├── sender-infrastructure.md
│   ├── url-analysis.md
│   ├── correlation-analysis.md
│   ├── timeline.md
│   ├── mitre-mapping.md
│   └── incident-response.md
│
└── reports/
    └── PHISH-001-incident-report.md
```
