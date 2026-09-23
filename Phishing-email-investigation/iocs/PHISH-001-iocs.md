# PHISH-001 — Indicators of Compromise

## 1. Email Indicators

| Type | Indicator | Description |
|---|---|---|
| Email Address | noreply@microsoftonline-verify.com | Sender address |
| Email Address | noreply@microsoftonline-verify.com | Return-Path |
| Domain | microsoftonline-verify.com | Sender domain |
| Hostname | mail.microsoftonline-verify.com | Hostname observed in Received header |
| Hostname | vps-291847.contabo.net | Infrastructure hostname in Received header |
| Message-ID Domain | microsoftonline-verify.com | Domain used in Message-ID |

## 2. Network Indicators

| Type | Indicator | Description |
|---|---|---|
| IPv4 | 178.238.225.91 | Sending mail server IP |
| ASN | AS51167 | Contabo network |
| Reverse DNS | vmi3247644.contaboserver.net | PTR record for sender IP |
| Hosting Provider | Contabo GmbH | Network owner |

## 3. URL Indicators

| Type | Indicator | Description |
|---|---|---|
| URL | https://bit.ly/3vF9xKz | Shortened URL found in email |
| Domain | bit.ly | URL shortener domain |
| IPv4 | 67.199.248.11 | Current serving IP observed by URLScan/VirusTotal |

## 4. Authentication Indicators

| Authentication | Result |
|---|---|
| SPF | FAIL |
| DKIM | FAIL |
| DMARC | FAIL |

## 5. URL Reputation Evidence

VirusTotal:
- 1/91 security vendors flagged the URL
- Flagging vendor: Phishing Database
- Classification: Phishing
- Current HTTP status: 404
- Historical VT submissions shown: April 2026

URLScan:
- Current result: 404
- Redirects observed: None
- Verdict: No classification

## 6. Domain Investigation

microsoftonline-verify.com:

- Current DNS status: NXDOMAIN
- A record: None
- MX record: None
- TXT record: None
- NS record: None
- Current Verisign RDAP query: HTTP 404

## 7. IOC Assessment

The indicators above were extracted from the original email and subsequent passive investigation.

The sender domain, sender IP, infrastructure hostnames, authentication failures, and shortened URL should be considered investigation indicators associated with PHISH-001.

The current inactive state of the domain and URL does not establish their historical state at the time the email was delivered.
