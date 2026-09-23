# PHISH-001 — Sender Infrastructure

## Sender IP

178.238.225.91

## Reverse DNS / Hostname

vps-291847.contabo.net

## Network

178.238.224.0 - 178.238.227.255

## Network Name

CONTABO

## Organization

Contabo GmbH

## Country

DE

## Origin ASN

AS51167

## Evidence Source

RIPE WHOIS query performed on 2026-09-22.

## Assessment

The sender IP was allocated within infrastructure associated with Contabo GmbH and 
originated from AS51167.

The hosting provider itself is not considered malicious.
The infrastructure information is supporting context and must be correlated with the email's sender identity,
authentication results, domain, URL behavior, and other threat-intelligence evidence.

## Correlation

The IP is the same sender IP observed in the original PHISH-001 email's Received header:

178.238.225.91

## Reverse DNS

Sender IP:
178.238.225.91

Reverse DNS:
vmi3247644.contaboserver.net

The sender IP resolves via reverse DNS to a Contabo-hosted server.

The hostname observed in the email's Received header was: vps-291847.contabo.net

The reverse-DNS hostname differs from the hostname presented in the Received header. This is an infrastructure observation and does not by itself indicate malicious activity.

Combined with WHOIS data, the sender infrastructure can be summarized as:

178.238.225.91
→ vmi3247644.contaboserver.net
→ Contabo GmbH
→ AS51167
→ Germany
