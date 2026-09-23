# PHISH-001 — Investigation Timeline

| Time / Date | Event | Evidence |
|---|---|---|
| 2026-02-06 17:14:18 UTC | Phishing email timestamp | Date header |
| 2026-02-06 | Email uses Microsoft impersonation | From / Subject |
| 2026-02-06 | Email sent from 178.238.225.91 | Received header |
| 2026-02-06 | SPF authentication failed | Authentication-Results |
| 2026-02-06 | DKIM authentication failed | Authentication-Results |
| 2026-02-06 | DMARC authentication failed | Authentication-Results |
| 2026-02-06 | Bitly URL present in email | Email body |
| 2026-09-22 | Current DNS investigation performed | dig |
| 2026-09-22 | Current RDAP investigation performed | Verisign RDAP |
| 2026-09-22 | Sender IP infrastructure investigated | WHOIS / reverse DNS |
| 2026-09-22 | URLScan investigation performed | URLScan |
| 2026-09-22 | VirusTotal investigation performed | VirusTotal |
| 2026-09-22 | Evidence correlation completed | Analyst investigation |
