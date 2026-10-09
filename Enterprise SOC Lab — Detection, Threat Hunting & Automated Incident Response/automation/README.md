# Python SOC Automation

A modular Python-based SOC automation workflow designed to process Wazuh alerts, extract indicators, correlate related events, generate incident records, and recommend response actions.

## Overview

This module demonstrates how repetitive SOC alert-handling tasks can be organized into a structured, auditable workflow while keeping an analyst involved in incident assessment and response decisions.

**Key features**
- Parse and normalize Wazuh alert data.
- Extract relevant IOCs from alert fields and event evidence.
- Correlate related alerts using available process and event context.
- Calculate configurable risk scores and generate incident records.
- Enrich IP addresses, domains, URLs, and file hashes where supported.
- Generate response recommendations in simulation mode.
- Record workflow actions in JSONL audit logs.
- Test core components using Python unit tests.

## Technology Stack

`Python 3` · `JSON` · `JSONL` · `Wazuh` · `Unit Testing`

The implementation is designed around Python's standard library where possible.

## Project Structure

| File / Directory | Purpose |
|---|---|
| `soc_alert_parser.py` | Parses alerts and extracts relevant evidence and indicators |
| `alert_correlator.py` | Identifies potentially related alerts |
| `incident_engine.py` | Generates incident records and calculates risk scores |
| `enrichment/` | IOC classification and optional threat-intelligence lookups |
| `orchestration/` | Coordinates the alert-processing workflow |
| `soar/` | Generates incident response recommendations |
| `audit/` | Records automation actions |
| `config/risk_config.json` | Configurable risk scores and severity thresholds |
| `tests/` | Core automated tests |
| `samples/` | Sample alert data for validation |

## Workflow

```text
Wazuh Alert
    ↓
Alert Parsing
    ↓
IOC Extraction
    ↓
Alert Correlation
    ↓
IOC Enrichment
    ↓
Incident Generation
    ↓
Response Recommendation
    ↓
Audit Logging
```

## Run the Automation

Run the following command from the `automation/` directory, provided the Wazuh alert file is accessible:

```bash
python3 -m orchestration.soc_orchestrator \
  --alert-file /var/ossec/logs/alerts/alerts.json \
  --config config/risk_config.json \
  --output-dir output/validation \
  --rule 92213 \
  --mode SIMULATE
```

This processes alerts matching rule `92213`, uses the configured risk-scoring rules, and writes the resulting artifacts to `output/validation/`.

**Important:** The command assumes the expected files and paths exist. Review the generated incident and audit records after execution.

## Testing

Run the core unit tests from the `automation/` directory:

```bash
python3 -m unittest discover -s tests -v
```

The core test suite passed **27 tests during development**. Rerun the suite after changes to confirm the current result.

## Validation Results

A Wazuh alert associated with rule `92213` was processed through the workflow in simulation mode.

- An incident record was generated.
- The automation assigned a risk score of `2` and severity `LOW`.
- The response recommendation was `MONITOR_AND_VALIDATE`.
- The incident remained unreviewed, and compromise was not established.
- No destructive response action was executed.
- Workflow actions were recorded in the audit log.

These results demonstrate alert-processing and decision-support behavior, not autonomous endpoint remediation.

## Scope and Limitations

- Risk scores support prioritization; they are not probabilities of compromise.
- IOC enrichment does not imply that an indicator is malicious.
- External threat-intelligence results require an actual provider response and appropriate configuration.
- Alert correlation depends on the evidence available in the input events.
- Response recommendations require analyst review and appropriate authorization.

---

**Focus:** SOC Automation · Alert Triage · IOC Enrichment · Incident Generation · Audit Logging · Simulated Response
