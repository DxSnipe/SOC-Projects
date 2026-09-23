# PHISH-001 — Incident Response Actions

## 1. Detection and Triage

The email should be classified as a phishing incident based on the available evidence.

Initial severity:
High

Reason:
- Microsoft impersonation
- SPF/DKIM/DMARC failures
- Suspicious sender domain
- Suspicious sender infrastructure
- Embedded shortened URL
- VirusTotal phishing classification

---

## 2. Containment

Recommended containment actions:

1. Remove/quarantine the phishing email from the affected mailbox.
2. Search mailboxes for the same sender, subject, URL, and related indicators.
3. Block or quarantine the malicious/suspicious sender domain where appropriate.
4. Block the identified phishing URL/domain through available email/web security controls.
5. Preserve the original email and headers as evidence.

---

## 3. User Investigation

Determine whether the recipient:

- Opened the email.
- Clicked the URL.
- Entered credentials.
- Downloaded a file.
- Received additional suspicious emails.
- Reported unusual account activity.

The current evidence does not establish that the recipient clicked the URL or submitted credentials.

---

## 4. If Credentials Were Submitted

If the user confirms that credentials were entered:

1. Reset the affected password.
2. Revoke active sessions where supported.
3. Review recent authentication activity.
4. Check for suspicious MFA changes or new authentication methods.
5. Investigate unusual account activity.
6. Escalate to the appropriate incident-response team.

---

## 5. Endpoint Investigation

If the URL was clicked:

1. Identify the affected endpoint.
2. Review browser/network activity around the click time.
3. Check DNS and proxy logs.
4. Review EDR alerts and process activity.
5. Search for downloaded files.
6. Check for suspicious persistence or additional indicators.

No endpoint compromise is established from the current email evidence.

---

## 6. Threat Hunting

Search security telemetry for:

- `microsoftonline-verify.com`
- `178.238.225.91`
- `bit.ly/3vF9xKz`
- `vmi3247644.contaboserver.net`
- `vps-291847.contabo.net`
- `noreply@microsoftonline-verify.com`

Search across:

- Email security logs
- Proxy/web logs
- DNS logs
- EDR telemetry
- SIEM
- Authentication logs

---

## 7. Escalation Criteria

Escalate the incident if:

- The user clicked the phishing URL.
- Credentials were submitted.
- MFA was modified.
- Suspicious authentication activity is detected.
- Malware was downloaded or executed.
- Multiple users received the campaign.
- Additional related indicators are discovered.

---

## 8. Recovery

If compromise is confirmed:

- Reset affected credentials.
- Revoke active sessions.
- Restore affected systems if necessary.
- Remove malicious artifacts.
- Continue monitoring for related activity.
- Confirm that security controls are blocking the campaign indicators.

---

## 9. Lessons Learned

Recommended defensive improvements:

- Strengthen phishing awareness training.
- Improve email authentication enforcement.
- Monitor lookalike/impersonation domains.
- Improve URL and email reputation filtering.
- Ensure users have an easy phishing-reporting mechanism.
- Maintain SIEM/EDR visibility for post-click investigation.

---

## Current Case Status

Classification:
PHISHING — HIGH CONFIDENCE

Compromise:
NOT ESTABLISHED

User interaction:
UNKNOWN

Credential theft:
NOT ESTABLISHED

Malware execution:
NOT ESTABLISHED

Recommended next action:
Search organizational email, web, authentication, and endpoint telemetry for the identified IOCs and determine whether any users interacted with the phishing campaign.
