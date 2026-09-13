# Security Log Investigator

A Python-based security log analysis tool for detecting suspicious activity, correlating authentication events, and identifying potential account compromises.

## Overview

Security systems generate large amounts of authentication and system activity logs. During a security investigation, analysts often need to examine these events and determine whether a sequence of activity represents normal behavior or a potential security incident.

**Security Log Investigator** is a lightweight SOC-style security analysis tool designed to automate part of this investigation process.

The tool processes structured security logs, identifies suspicious patterns, correlates related events, and generates evidence-based security alerts. Rather than treating individual events in isolation, it examines sequences of activity to determine whether multiple events together indicate a larger security concern.

For example, a single failed login may be harmless. However, the following sequence could indicate a potential account compromise:

```text
Multiple failed login attempts
        ↓
Successful authentication
        ↓
Login from an unfamiliar IP address
        ↓
MFA configuration changed
        ↓
Administrative privileges granted
```

Security Log Investigator is designed to recognize this type of activity and provide an analyst with a concise explanation of why the sequence is suspicious.

---

## Goals

The primary goals of this project are to:

* Analyze authentication and security-related logs
* Detect suspicious login and account activity
* Correlate multiple events into meaningful security findings
* Identify potential account compromise
* Provide evidence explaining why an event or sequence was flagged
* Assign a severity level to security findings
* Recommend appropriate investigation steps
* Provide a foundation for expanding the tool into a more complete security investigation platform

The project focuses on **explainable security detection** rather than simply producing a generic warning.

---

## Key Features

### Log Parsing and Normalization

The tool accepts structured security logs and converts them into a consistent internal format.

Supported log information can include:

* Timestamp
* Username
* Event type
* Source IP address
* Device information
* Authentication result
* Privilege changes
* MFA activity
* Other security-related metadata

Normalizing the events allows the detection engine to analyze logs consistently even when individual events contain different fields.

---

### Suspicious Activity Detection

Security Log Investigator contains detection logic for common authentication and account-security indicators.

Examples include:

#### Brute-Force Attempts

Detects repeated failed authentication attempts against the same account.

Example:

```text
10:41:02  alice  LOGIN_FAILED  10.2.4.15
10:41:08  alice  LOGIN_FAILED  10.2.4.15
10:41:14  alice  LOGIN_FAILED  10.2.4.15
10:41:20  alice  LOGIN_FAILED  10.2.4.15
```

A large number of failures within a short period may indicate password guessing or a brute-force attack.

---

#### Failed Logins Followed by Successful Authentication

A successful login immediately following multiple failed attempts can be more significant than either event alone.

Example:

```text
10:41  alice  LOGIN_FAILED
10:42  alice  LOGIN_FAILED
10:43  alice  LOGIN_FAILED
10:44  alice  LOGIN_SUCCESS
```

The tool correlates these events and can flag the sequence as suspicious.

---

#### Unusual Login Activity

The tool can identify authentication activity that differs from previously observed behavior, such as:

* A previously unseen IP address
* A new source location
* A new device
* Authentication activity occurring in an unusual sequence

These indicators can become more meaningful when combined with other suspicious events.

---

#### MFA Changes

Changes to multi-factor authentication configuration can be an important indicator during an account compromise investigation.

For example:

```text
LOGIN_SUCCESS
      ↓
MFA_DISABLED
```

An attacker who gains access to an account may attempt to disable or modify security controls.

---

#### Privilege Escalation

The tool identifies potentially suspicious changes to account privileges.

Example:

```text
USER_LOGIN
     ↓
ADMIN_PRIVILEGE_GRANTED
```

Privilege changes are particularly important when they occur shortly after suspicious authentication activity.

---

## Event Correlation

One of the main goals of Security Log Investigator is to move beyond analyzing individual log entries.

A single event may not be enough to indicate an attack.

For example:

```text
LOGIN_FAILED
```

does not necessarily represent a security incident.

However:

```text
LOGIN_FAILED
LOGIN_FAILED
LOGIN_FAILED
LOGIN_SUCCESS
NEW_IP
MFA_DISABLED
ADMIN_GRANTED
```

represents a much more suspicious sequence.

The detection engine correlates related events using information such as:

* User
* Source IP
* Timestamp
* Event type
* Authentication sequence
* Account activity
* Privilege changes

This allows the tool to identify patterns that would be difficult to recognize by examining each log entry independently.

---

## Evidence-Based Alerts

When suspicious activity is detected, the tool generates a structured security alert.

Each alert is designed to explain **why** the activity was flagged rather than simply stating that something is suspicious.

Example:

```text
Potential Account Compromise

Severity: HIGH

User: alice

Evidence:
- 4 failed login attempts within 30 seconds
- Successful login immediately after failed attempts
- Successful login originated from a previously unseen IP address
- MFA was disabled shortly after authentication
- Administrative privileges were granted

Assessment:
The sequence of authentication and account changes is consistent
with a potential account compromise followed by privilege escalation.

Recommended Investigation:
1. Verify whether the successful login was authorized.
2. Investigate the source IP address.
3. Review recent activity associated with the account.
4. Determine whether the MFA change was authorized.
5. Investigate the administrative privilege change.
```

This format is intended to make the output useful to a security analyst investigating an incident.

---

## Severity Classification

Security findings are assigned a severity level based on the indicators present in the event sequence.

Example severity levels:

| Severity | Description                                                                  |
| -------- | ---------------------------------------------------------------------------- |
| LOW      | Minor or potentially unusual activity requiring limited investigation        |
| MEDIUM   | Suspicious behavior with multiple indicators                                 |
| HIGH     | Strong evidence of potentially malicious activity                            |
| CRITICAL | Multiple high-risk indicators suggesting an active or significant compromise |

Severity is based on the combination of evidence rather than a single log event.

For example, a single failed login would generally be less concerning than a sequence involving repeated failures, a successful login from a new IP, MFA modification, and privilege escalation.

---

## Investigation Recommendations

Security Log Investigator also provides recommended next steps based on the detected activity.

Examples include:

* Verify whether the authentication was authorized
* Investigate the source IP address
* Review recent authentication history
* Examine activity associated with the affected account
* Check for unauthorized privilege changes
* Review MFA configuration changes
* Investigate additional activity from the same IP address
* Determine whether other accounts or systems were affected

The goal is to help move an analyst from **detection → understanding → investigation**.

---

## Architecture

The project follows a modular processing pipeline:

```text
Security Logs
     │
     ▼
┌───────────────┐
│ Log Parser    │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Normalization │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Detection     │
│ Engine        │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Correlation & │
│ Evidence      │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Severity      │
│ Assessment    │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Investigation │
│ Recommendations│
└───────┬───────┘
        │
        ▼
 Security Alerts
```

The separation between parsing, detection, and output makes the project easier to test and extend.

---

## Example Workflow

Given a set of security logs:

```json
[
  {
    "timestamp": "2026-09-12T09:41:00",
    "user": "alice",
    "event": "LOGIN_FAILED",
    "ip": "10.2.4.15"
  },
  {
    "timestamp": "2026-09-12T09:42:00",
    "user": "alice",
    "event": "LOGIN_FAILED",
    "ip": "10.2.4.15"
  },
  {
    "timestamp": "2026-09-12T09:43:00",
    "user": "alice",
    "event": "LOGIN_FAILED",
    "ip": "10.2.4.15"
  },
  {
    "timestamp": "2026-09-12T09:44:00",
    "user": "alice",
    "event": "LOGIN_SUCCESS",
    "ip": "10.2.4.15"
  },
  {
    "timestamp": "2026-09-12T09:45:00",
    "user": "alice",
    "event": "LOGIN_SUCCESS",
    "ip": "185.44.10.21"
  },
  {
    "timestamp": "2026-09-12T09:47:00",
    "user": "alice",
    "event": "MFA_DISABLED",
    "ip": "185.44.10.21"
  },
  {
    "timestamp": "2026-09-12T09:49:00",
    "user": "alice",
    "event": "ADMIN_GRANTED",
    "ip": "185.44.10.21"
  }
]
```

The tool can correlate these events and identify the sequence as a potential account compromise.

Instead of generating seven unrelated warnings, the system can produce one higher-level investigation finding containing the relevant evidence.

---

## Project Structure

```text
Security-Log-Investigator/
│
├── src/
│   ├── parser.py
│   ├── detector.py
│   └── main.py
│
├── data/
│   └── sample_logs.json
│
├── tests/
│   └── test_detector.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

### `src/`

Contains the main application logic.

* `parser.py` — Loads and normalizes security logs
* `detector.py` — Contains suspicious activity detection and correlation logic
* `main.py` — Runs the analysis workflow and presents the results

### `data/`

Contains sample security logs used for development and demonstration.

### `tests/`

Contains automated tests for detection logic and other core functionality.

---

## Testing

The project includes unit tests to verify that detection rules behave as expected.

Testing scenarios include:

* Normal authentication activity
* Repeated failed logins
* Failed logins followed by successful authentication
* Unusual IP addresses
* MFA changes
* Privilege escalation
* Combined suspicious activity
* Events that should **not** trigger an alert

The goal is to ensure that detection rules identify suspicious behavior while reducing unnecessary false positives.

---

## Technologies

* **Python**
* **JSON / structured security logs**
* **Python standard library**
* **Unit testing**
* **Git / GitHub**

---

## Running the Project

Clone the repository:

```bash
git clone <repository-url>
cd Security-Log-Investigator
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the analyzer:

```bash
python src/main.py
```

Run the tests:

```bash
python -m unittest discover tests
```

---

## Example Use Cases

Security Log Investigator can be used as a simplified security operations workflow for:

* Investigating suspicious authentication activity
* Detecting potential brute-force attacks
* Identifying possible account compromise
* Investigating unusual login behavior
* Reviewing privilege changes
* Demonstrating security detection concepts
* Learning how SOC analysts correlate security events

The project is intentionally designed as a lightweight investigation tool rather than a replacement for a production SIEM or security monitoring platform.

---

## Future Improvements

Potential future improvements include:

* Support for additional log formats
* More sophisticated event correlation
* Detection of lateral movement
* Detection of suspicious command execution
* Detection of impossible-travel authentication patterns
* IP reputation enrichment
* Geolocation enrichment
* More advanced risk scoring
* Alert deduplication
* Interactive investigation dashboard
* Integration with SIEM platforms
* Machine-learning-assisted anomaly detection
* Natural-language explanations of security incidents

These improvements could allow the project to evolve from a rule-based log analyzer into a more complete security investigation platform.

---

## Why This Project?

Security analysts often have to work through large amounts of security telemetry to determine which events actually matter.

This project explores a fundamental cybersecurity problem:

> **How can raw security events be transformed into meaningful, explainable security findings?**

Rather than simply detecting individual suspicious events, Security Log Investigator focuses on connecting related activity and presenting the evidence behind a potential incident.

This project serves as a foundation for exploring larger security investigation and incident-response systems.
