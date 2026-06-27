import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloudtrail_detection_lab.cli import detect


class CloudtrailDetectionTests(unittest.TestCase):
    def test_detects_console_login_without_mfa(self):
        alerts = detect([{"eventName": "ConsoleLogin", "additionalEventData": {"MFAUsed": "No"}, "userIdentity": {"type": "IAMUser"}}])
        self.assertEqual(alerts[0]["title"], "Console login without MFA")

    def test_detects_logging_tampering(self):
        alerts = detect([{"eventName": "StopLogging", "userIdentity": {"type": "IAMUser"}}])
        self.assertEqual(alerts[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
