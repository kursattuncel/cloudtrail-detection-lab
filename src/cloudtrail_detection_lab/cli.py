from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_events(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("Records", data if isinstance(data, list) else [])


def detect(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for event in events:
        name = str(event.get("eventName", ""))
        user_type = str(event.get("userIdentity", {}).get("type", ""))
        mfa = str(event.get("additionalEventData", {}).get("MFAUsed", "Unknown"))
        source = str(event.get("sourceIPAddress", "unknown"))

        if user_type == "Root":
            alerts.append(alert("critical", "Root account activity", event, "Confirm business need and verify MFA-protected root access."))
        if name == "ConsoleLogin" and mfa.lower() == "no":
            alerts.append(alert("high", "Console login without MFA", event, "Review identity controls and require MFA for console access."))
        if name in {"StopLogging", "DeleteTrail", "PutEventSelectors"}:
            alerts.append(alert("critical", "CloudTrail logging tampering", event, "Preserve logs and investigate whether audit coverage was reduced."))
        if name in {"PutBucketAcl", "PutBucketPolicy"} and "s3" in str(event.get("eventSource", "")):
            request = json.dumps(event.get("requestParameters", {})).lower()
            if "public" in request or "allow" in request and "*" in request:
                alerts.append(alert("high", "Potential public S3 access change", event, "Validate bucket exposure and restore least-privilege policy."))
        if source.endswith(".tor-exit.example"):
            alerts.append(alert("medium", "Suspicious anonymized source", event, "Correlate with identity behavior and conditional access policy."))
    return alerts


def alert(severity: str, title: str, event: dict[str, Any], action: str) -> dict[str, str]:
    return {
        "severity": severity,
        "title": title,
        "eventName": str(event.get("eventName", "")),
        "principal": str(event.get("userIdentity", {}).get("arn", event.get("userIdentity", {}).get("type", "unknown"))),
        "sourceIPAddress": str(event.get("sourceIPAddress", "unknown")),
        "recommendedAction": action,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run synthetic CloudTrail detections.")
    parser.add_argument("events", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(detect(load_events(args.events)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
