"""Suspicious activity detection and correlation logic."""

from dataclasses import dataclass
from typing import List, Optional

from parser import Event

BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW_SECONDS = 60
MFA_CHANGE_WINDOW_SECONDS = 600
PRIVILEGE_CHANGE_WINDOW_SECONDS = 600


def detect_brute_force(events: List[Event]) -> Optional[str]:
    failures = [e for e in events if e.event == "LOGIN_FAILED"]

    for i in range(len(failures) - BRUTE_FORCE_THRESHOLD + 1):
        window = failures[i : i + BRUTE_FORCE_THRESHOLD]
        elapsed = (window[-1].timestamp - window[0].timestamp).total_seconds()
        if elapsed <= BRUTE_FORCE_WINDOW_SECONDS:
            return (
                f"{len(window)} failed login attempts within "
                f"{int(elapsed)} seconds"
            )
    return None


def detect_failed_then_success(events: List[Event]) -> Optional[str]:
    for prev, curr in zip(events, events[1:]):
        if prev.event == "LOGIN_FAILED" and curr.event == "LOGIN_SUCCESS":
            return "Successful login immediately after failed attempts"
    return None


def detect_new_ip_or_device(events: List[Event]) -> Optional[str]:
    seen_ips = set()
    seen_devices = set()

    for event in events:
        if event.event != "LOGIN_SUCCESS":
            continue

        is_new_ip = event.ip and event.ip not in seen_ips
        is_new_device = event.device and event.device not in seen_devices

        if seen_ips and is_new_ip:
            return "Successful login originated from a previously unseen IP address"
        if seen_devices and is_new_device:
            return "Successful login originated from a previously unseen device"

        if event.ip:
            seen_ips.add(event.ip)
        if event.device:
            seen_devices.add(event.device)

    return None


def detect_mfa_disabled_after_login(events: List[Event]) -> Optional[str]:
    last_login_time = None

    for event in events:
        if event.event == "LOGIN_SUCCESS":
            last_login_time = event.timestamp
        elif event.event == "MFA_DISABLED" and last_login_time is not None:
            elapsed = (event.timestamp - last_login_time).total_seconds()
            if elapsed <= MFA_CHANGE_WINDOW_SECONDS:
                return "MFA was disabled shortly after authentication"

    return None


def detect_privilege_escalation(events: List[Event]) -> Optional[str]:
    last_login_time = None

    for event in events:
        if event.event == "LOGIN_SUCCESS":
            last_login_time = event.timestamp
        elif event.event == "ADMIN_GRANTED" and last_login_time is not None:
            elapsed = (event.timestamp - last_login_time).total_seconds()
            if elapsed <= PRIVILEGE_CHANGE_WINDOW_SECONDS:
                return "Administrative privileges were granted"

    return None


DETECTION_RULES = [
    (
        detect_brute_force,
        "Review recent authentication history for repeated failed login attempts.",
    ),
    (
        detect_failed_then_success,
        "Verify whether the successful login was authorized.",
    ),
    (
        detect_new_ip_or_device,
        "Investigate the source IP address and device used for the login.",
    ),
    (
        detect_mfa_disabled_after_login,
        "Review the MFA configuration change to confirm it was authorized.",
    ),
    (
        detect_privilege_escalation,
        "Investigate the administrative privilege change for authorization.",
    ),
]


def correlate_user_events(events: List[Event]):
    evidence = []
    recommendations = []
    for rule, recommendation in DETECTION_RULES:
        result = rule(events)
        if result:
            evidence.append(result)
            recommendations.append(recommendation)
    return evidence, recommendations


SEVERITY_ASSESSMENTS = {
    "LOW": "Minor or unusual activity was observed that may warrant a quick review.",
    "MEDIUM": "Multiple indicators suggest unusual account activity that should be investigated.",
    "HIGH": (
        "The sequence of authentication and account changes is consistent "
        "with a potential account compromise."
    ),
    "CRITICAL": (
        "Strong evidence of an active account compromise, including "
        "security control changes and/or privilege escalation."
    ),
}


def calculate_severity(evidence_count: int) -> Optional[str]:
    if evidence_count <= 0:
        return None
    if evidence_count == 1:
        return "LOW"
    if evidence_count <= 3:
        return "MEDIUM"
    if evidence_count <= 5:
        return "HIGH"
    return "CRITICAL"


@dataclass
class Alert:
    user: str
    severity: str
    evidence: List[str]
    assessment: str
    recommendations: List[str]


def analyze_user(events: List[Event]) -> Optional[Alert]:
    if not events:
        return None

    evidence, recommendations = correlate_user_events(events)
    severity = calculate_severity(len(evidence))
    if severity is None:
        return None

    return Alert(
        user=events[0].user,
        severity=severity,
        evidence=evidence,
        assessment=SEVERITY_ASSESSMENTS[severity],
        recommendations=recommendations,
    )
