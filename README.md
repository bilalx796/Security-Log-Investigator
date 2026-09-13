# Security Log Investigator

A lightweight, Python-based tool for detecting suspicious authentication activity and correlating related events into evidence-based security alerts.

## Why

A single failed login isn't interesting. But a sequence like this is:

```
Multiple failed logins → Successful login → New IP → MFA disabled → Admin granted
```

Instead of raising a warning per event, this tool correlates related activity per user and produces one explainable finding: what happened, why it's suspicious, how severe it is, and what to check next.

## Features

- **Normalization** — parses structured JSON logs into a consistent event format (timestamp, user, event type, IP, device)
- **Detection rules** — brute-force attempts, failed-then-successful login, logins from a new IP/device, MFA disabled after login, privilege escalation after login
- **Correlation** — combines related events per user into a single alert instead of many isolated warnings
- **Severity scoring** — LOW / MEDIUM / HIGH / CRITICAL based on how many indicators are present
- **Investigation recommendations** — concrete next steps tied to each triggered rule

## Example Output

```
Potential Account Compromise

Severity: HIGH
User: alice

Evidence:
- 3 failed login attempts within 40 seconds
- Successful login immediately after failed attempts
- Successful login originated from a previously unseen IP address
- MFA was disabled shortly after authentication
- Administrative privileges were granted

Assessment:
The sequence of authentication and account changes is consistent
with a potential account compromise.

Recommended Investigation:
1. Review recent authentication history for repeated failed login attempts.
2. Verify whether the successful login was authorized.
3. Investigate the source IP address and device used for the login.
4. Review the MFA configuration change to confirm it was authorized.
5. Investigate the administrative privilege change for authorization.
```

## Architecture

```
Logs → Parser → Normalization → Detection Rules → Correlation → Severity → Alert
```

## Project Structure

```
Security-Log-Investigator/
├── src/
│   ├── parser.py     # Load and normalize logs
│   ├── detector.py   # Detection, correlation, severity, recommendations
│   └── main.py       # Runs the analysis and prints alerts
├── data/
│   └── sample_logs.json
├── tests/
│   └── test_detector.py
└── README.md
```

## Running

```bash
python src/main.py                             # run the analyzer on sample logs
python src/main.py --log-file path/to/logs.json  # run against your own logs
python -m unittest discover tests              # run the test suite
```

No external dependencies — standard library only.

## Design Decisions & Limitations

This is intentionally a small, rule-based prototype rather than a production SIEM:

- **Thresholds are fixed constants, not tuned.** Brute-force detection (3 failures / 60s) and the MFA/privilege time windows (600s) are reasonable starting points, not values derived from real traffic.
- **Severity is evidence-count-based**, not weighted by indicator risk (e.g. an MFA change currently counts the same as a new IP). A weighted score would be a natural next step.
- **In-memory, single-file processing.** There's no persistence, streaming ingestion, or handling for logs too large to fit in memory — fine for a demo, not for production log volume.
- **No IP reputation, geolocation, or ML.** "New IP" just means "not seen before for this user," with no enrichment or impossible-travel logic.

These are scoping choices for a one-day build, not oversights — see Future Improvements for the natural next steps.

## Future Improvements

- Additional log formats and richer correlation
- Impossible-travel and lateral-movement detection
- IP reputation / geolocation enrichment
- Alert deduplication and an interactive dashboard
- SIEM integration, ML-assisted anomaly detection
