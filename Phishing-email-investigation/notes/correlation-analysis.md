# PHISH-001 — Evidence Correlation Analysis

## 1. Email Identity

The email uses the display name: `"Microsoft Account Team"`

The actual sender address is: `noreply@microsoftonline-verify.com`

The sender domain does not correspond to Microsoft's legitimate domain infrastructure.

Subject: `[Action Required] Unusual sign-in activity on your account`

The subject uses account-security urgency to encourage the recipient to take action.

---

## 2. Email Authentication

SPF:
FAIL

DKIM:
FAIL

DMARC:
FAIL

Authentication results indicate that the message did not successfully authenticate as an authorized message from microsoftonline-verify.com.

---

## 3. Sender Infrastructure

Sending IP: `178.238.225.91`

Reverse DNS: `vmi3247644.contaboserver.net`

Received hostname: `vps-291847.contabo.net`

Network: `Contabo GmbH`

ASN: `AS51167`

The sending infrastructure was hosted within a commercial hosting provider network.

The hosting provider itself is not considered malicious based solely on this evidence.

---

## 4. Sender Domain

Domain: `microsoftonline-verify.com`

Current DNS status: `NXDOMAIN`

Current A/MX/TXT/NS records: `Not available`

Current Verisign RDAP query: `HTTP 404`

The domain was used in the original email dated February 6, 2026, but is currently not resolving.

The current inactive state does not establish the historical registration or DNS state at the time the email was delivered.

---

## 5. URL Investigation

URL: `https://bit.ly/3vF9xKz`

URL type: `Shortened URL`

URLScan:

- Current result: HTTP 404
- Redirects captured: None
- Verdict: No classification

VirusTotal:

- 1/91 security vendors flagged the URL
- Flagging vendor: Phishing Database
- Classification: Phishing
- Current status: 404

The shortened URL is currently inactive.

The available VirusTotal evidence provides supporting evidence that the URL has been associated with phishing, but does not independently establish that it was malicious on February 6, 2026.

---

## 6. Evidence Correlation

The following indicators are observed together:

1. Microsoft impersonation through the display name.
2. Sender domain designed to resemble Microsoft-related infrastructure.
3. SPF authentication failure.
4. DKIM authentication failure.
5. DMARC authentication failure.
6. Sending infrastructure hosted on a commercial VPS provider.
7. Urgency-based account security subject.
8. A shortened URL embedded in the email.
9. VirusTotal contains a phishing classification for the exact shortened URL.
10. The sender domain and shortened URL are currently inactive.

These findings reinforce each other and are consistent with a phishing email designed to impersonate Microsoft and direct the recipient toward an external URL.

---

## 7. Limitations

The original destination of the Bitly URL could not be recovered from the current URLScan scan.

The current DNS and RDAP state represents the domain's state during the investigation in September 2026 and cannot by itself establish its state on February 6, 2026.

No evidence currently confirms that the recipient clicked the URL or submitted credentials.

No endpoint compromise has been established from the available email evidence.

---

## 8. Provisional Classification

Classification: `PHISHING — HIGH CONFIDENCE`

Rationale:

The combination of impersonation, authentication failures, suspicious sender infrastructure, social-engineering language, shortened URL usage, and supporting phishing reputation data provides strong evidence that PHISH-001 is a phishing email.

This classification is based on the available email and passive threat-intelligence evidence. It does not establish whether the recipient interacted with the URL or whether account compromise occurred.
