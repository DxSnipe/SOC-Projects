# PHISH-001 — Authentication Analysis

## SPF

**Result:** FAIL

**Envelope sender:**
noreply@microsoftonline-verify.com

**Sending IP:**
178.238.225.91

**Observation:**
The sending IP was not authorized by the SPF policy for microsoftonline-verify.com.

---

## DKIM

**Result:** FAIL

**Signing identity:**
microsoftonline-verify.com

**Selector:**
default

**Observation:**
The email did not successfully authenticate using DKIM for the claimed sender domain.

---

## DMARC

**Result:** FAIL

**Header From domain:**
microsoftonline-verify.com

**Policy:**
p=NONE

**Observation:**
The message failed DMARC evaluation for the visible From domain. The domain's DMARC policy was configured
with p=NONE, meaning monitoring rather than an enforcement action was requested.

---

## Authentication Assessment

SPF: FAIL
DKIM: FAIL
DMARC: FAIL

The authentication results provide strong evidence that the message did not successfully authenticate as an 
authorized message from microsoftonline-verify.com.

Authentication results will be correlated with sender identity, domain ownership, URL behavior, infrastructure,
and email content before assigning the final verdict.
