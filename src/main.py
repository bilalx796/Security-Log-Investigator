"""Runs the analysis workflow and presents the results."""

import argparse
import os

from detector import Alert, analyze_user
from parser import group_by_user, load_logs

DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "sample_logs.json"
)

ALERT_TITLES = {
    "CRITICAL": "Potential Account Compromise",
    "HIGH": "Potential Account Compromise",
    "MEDIUM": "Suspicious Account Activity",
    "LOW": "Unusual Account Activity",
}


def format_alert(alert: Alert) -> str:
    evidence_lines = "\n".join(f"- {item}" for item in alert.evidence)
    recommendation_lines = "\n".join(
        f"{i}. {rec}" for i, rec in enumerate(alert.recommendations, 1)
    )

    return (
        f"{ALERT_TITLES[alert.severity]}\n\n"
        f"Severity: {alert.severity}\n\n"
        f"User: {alert.user}\n\n"
        f"Evidence:\n{evidence_lines}\n\n"
        f"Assessment:\n{alert.assessment}\n\n"
        f"Recommended Investigation:\n{recommendation_lines}"
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze security logs for suspicious authentication activity."
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_PATH,
        help="Path to a JSON log file (default: data/sample_logs.json)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    events = load_logs(args.log_file)
    grouped = group_by_user(events)

    for user, user_events in grouped.items():
        alert = analyze_user(user_events)
        print("=" * 60)
        if alert:
            print(format_alert(alert))
        else:
            print(f"User: {user}\n\nNo suspicious activity detected.")
        print("=" * 60)
        print()


if __name__ == "__main__":
    main()
