# IOC-002 — 127.0.0.1

## Observable

- **Type:** IPv4 Address
- **Value:** `127.0.0.1`
- **Host:** Ubuntu Wazuh Manager
- **Activity:** SSH authentication testing

## Source Context

The address was observed as the source of controlled SSH authentication attempts against the non-existent account:

`fake-soc-user`

## Enrichment

`127.0.0.1` is a loopback address representing the local host.

External threat-intelligence reputation is therefore not meaningful for this observable in this context.

## Contextual Assessment

The address represents locally generated laboratory activity.

It is not an external attacker infrastructure indicator.

## Analyst Decision

**Classification: Benign / Internal Loopback**

No blocking or containment action is appropriate.

## SOC Lesson

Not every IP observed in an authentication event is an external IOC. Address type and network context must be considered before enrichment.
