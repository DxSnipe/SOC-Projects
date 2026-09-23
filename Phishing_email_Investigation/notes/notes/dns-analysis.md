# PHISH-001 — DNS Analysis

## Domain

microsoftonline-verify.com

## Investigation Date

2026-09-22

## Current DNS Results

| Record | Result |
|---|---|
| A | NXDOMAIN |
| MX | NXDOMAIN |
| TXT | NXDOMAIN |
| NS | NXDOMAIN |

## Observation

At the time of investigation, microsoftonline-verify.com
returned NXDOMAIN for A, MX, TXT and NS queries.

The original email evidence from February 2026 shows that
the domain was used as the sender/envelope domain and was
associated with the historical sender infrastructure
178.238.225.91.

## Assessment

The current NXDOMAIN state should not be interpreted as
evidence that the domain never existed. The domain may have
been taken offline, expired, or had its DNS records removed
after the phishing campaign.

Historical evidence should therefore be retained and
correlated with passive DNS, registration data, threat
intelligence, and the original email headers.

## RDAP

**Query date:** 2026-09-22

**RDAP service:** Verisign (.com)

**Result:** HTTP 404 Not Found

**Observation:**
The current Verisign RDAP query did not return a registration object for microsoftonline-verify.com.

This is consistent with the current DNS investigation, where the domain returned NXDOMAIN.

**Forensic limitation:**
The current RDAP result does not establish that the domain was never registered. 
The original email provides historical evidence that the domain was used as the sender 
domain on 2026-02-06.

Historical registration or passive-DNS data would be required to establish the domain's previous registration and DNS state.
