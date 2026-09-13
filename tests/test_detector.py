import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import (
    analyze_user,
    calculate_severity,
    detect_brute_force,
    detect_failed_then_success,
    detect_mfa_disabled_after_login,
    detect_new_ip_or_device,
    detect_privilege_escalation,
)
from parser import Event

BASE_TIME = datetime(2026, 1, 1, 9, 0, 0)


def make_event(seconds_offset, user, event, ip="10.0.0.1", device="device-1"):
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds_offset),
        user=user,
        event=event,
        ip=ip,
        device=device,
    )


class TestDetectionRules(unittest.TestCase):
    def test_brute_force_detected(self):
        events = [
            make_event(0, "alice", "LOGIN_FAILED"),
            make_event(10, "alice", "LOGIN_FAILED"),
            make_event(20, "alice", "LOGIN_FAILED"),
        ]
        self.assertIsNotNone(detect_brute_force(events))

    def test_brute_force_not_detected_when_spread_out(self):
        events = [
            make_event(0, "alice", "LOGIN_FAILED"),
            make_event(200, "alice", "LOGIN_FAILED"),
            make_event(400, "alice", "LOGIN_FAILED"),
        ]
        self.assertIsNone(detect_brute_force(events))

    def test_failed_then_success_detected(self):
        events = [
            make_event(0, "alice", "LOGIN_FAILED"),
            make_event(10, "alice", "LOGIN_SUCCESS"),
        ]
        self.assertIsNotNone(detect_failed_then_success(events))

    def test_failed_then_success_not_detected_for_success_only(self):
        events = [make_event(0, "alice", "LOGIN_SUCCESS")]
        self.assertIsNone(detect_failed_then_success(events))

    def test_new_ip_detected(self):
        events = [
            make_event(0, "alice", "LOGIN_SUCCESS", ip="10.0.0.1"),
            make_event(10, "alice", "LOGIN_SUCCESS", ip="185.44.10.21"),
        ]
        self.assertIsNotNone(detect_new_ip_or_device(events))

    def test_new_ip_not_detected_for_consistent_ip(self):
        events = [
            make_event(0, "alice", "LOGIN_SUCCESS", ip="10.0.0.1"),
            make_event(10, "alice", "LOGIN_SUCCESS", ip="10.0.0.1"),
        ]
        self.assertIsNone(detect_new_ip_or_device(events))

    def test_mfa_disabled_after_login_detected(self):
        events = [
            make_event(0, "alice", "LOGIN_SUCCESS"),
            make_event(60, "alice", "MFA_DISABLED"),
        ]
        self.assertIsNotNone(detect_mfa_disabled_after_login(events))

    def test_mfa_disabled_without_prior_login_not_detected(self):
        events = [make_event(0, "alice", "MFA_DISABLED")]
        self.assertIsNone(detect_mfa_disabled_after_login(events))

    def test_privilege_escalation_detected(self):
        events = [
            make_event(0, "alice", "LOGIN_SUCCESS"),
            make_event(60, "alice", "ADMIN_GRANTED"),
        ]
        self.assertIsNotNone(detect_privilege_escalation(events))

    def test_privilege_escalation_without_prior_login_not_detected(self):
        events = [make_event(0, "alice", "ADMIN_GRANTED")]
        self.assertIsNone(detect_privilege_escalation(events))


class TestSeverity(unittest.TestCase):
    def test_no_evidence_returns_none(self):
        self.assertIsNone(calculate_severity(0))

    def test_severity_thresholds(self):
        self.assertEqual(calculate_severity(1), "LOW")
        self.assertEqual(calculate_severity(3), "MEDIUM")
        self.assertEqual(calculate_severity(5), "HIGH")
        self.assertEqual(calculate_severity(6), "CRITICAL")


class TestAnalyzeUser(unittest.TestCase):
    def test_normal_activity_produces_no_alert(self):
        events = [
            make_event(0, "bob", "LOGIN_SUCCESS"),
            make_event(600, "bob", "LOGIN_SUCCESS"),
            make_event(700, "bob", "LOGOUT"),
        ]
        self.assertIsNone(analyze_user(events))

    def test_full_compromise_sequence_is_high_severity(self):
        events = [
            make_event(0, "alice", "LOGIN_FAILED", ip="10.0.0.1", device="device-1"),
            make_event(10, "alice", "LOGIN_FAILED", ip="10.0.0.1", device="device-1"),
            make_event(20, "alice", "LOGIN_FAILED", ip="10.0.0.1", device="device-1"),
            make_event(30, "alice", "LOGIN_SUCCESS", ip="10.0.0.1", device="device-1"),
            make_event(40, "alice", "LOGIN_SUCCESS", ip="185.44.10.21", device="unknown"),
            make_event(100, "alice", "MFA_DISABLED", ip="185.44.10.21", device="unknown"),
            make_event(160, "alice", "ADMIN_GRANTED", ip="185.44.10.21", device="unknown"),
        ]
        alert = analyze_user(events)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(len(alert.evidence), 5)
        self.assertEqual(len(alert.recommendations), 5)

    def test_single_weak_indicator_is_low_severity(self):
        events = [
            make_event(0, "carol", "LOGIN_SUCCESS", ip="10.0.0.1", device="device-1"),
            make_event(86400, "carol", "LOGIN_SUCCESS", ip="203.0.113.77", device="laptop"),
        ]
        alert = analyze_user(events)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "LOW")
        self.assertEqual(len(alert.evidence), 1)


if __name__ == "__main__":
    unittest.main()
