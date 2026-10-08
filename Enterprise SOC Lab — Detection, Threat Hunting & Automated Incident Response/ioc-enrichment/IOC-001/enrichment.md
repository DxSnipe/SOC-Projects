# IOC-001 — 152.58.87.10

## Observable

- **Type:** IPv4 Address
- **Value:** `152.58.87.10`
- **Observed On:** SOC-Windows
- **Activity:** Windows authentication failures

## Source Context

The IP was observed as the source address for repeated Windows Security Event ID 4625 failures.

Associated activity:

- Target account: Administrator
- Logon Type: 3
- Authentication: NTLM
- Status: 0xC000006D
- SubStatus: 0xC000006A

## Enrichment

The IP should be evaluated using:

- WHOIS/RDAP
- ASN
- Geolocation
- Threat-intelligence reputation
- Historical reputation
- Abuse reports

## Contextual Assessment

The address was used as the source of controlled project authentication-validation activity.

Therefore, its presence in this lab does not establish that the IP is malicious.

## Analyst Decision

**Classification: Context-dependent / Controlled Lab Observable**

The IP should not be blocked solely because it appeared in the Project 4 authentication telemetry.

## SOC Lesson

An IP address becomes meaningful when combined with:

- Authentication behavior
- Frequency
- Target accounts
- Reputation
- Timing
- Other activity from the same source
