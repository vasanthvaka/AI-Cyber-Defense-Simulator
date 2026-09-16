import unittest

from detector import process_detector as detector


class TestProcessDetector(unittest.TestCase):

    def setUp(self):

        detector.flagged_processes.clear()

    def create_event(
        self,
        process_name="chrome.exe",
        process_id=5000,
        parent_process="explorer.exe",
        executable_path=(
            r"C:\Program Files\Google\Chrome"
            r"\Application\chrome.exe"
        ),
        command_line="chrome.exe"
    ):

        return {
            "event_type": "PROCESS_ACTIVITY",
            "timestamp": "12:00:00",
            "process_name": process_name,
            "process_id": process_id,
            "parent_process": parent_process,
            "user": "vasanth",
            "executable_path": executable_path,
            "command_line": command_line,
            "action": "STARTED"
        }

    def test_normal_process_does_not_trigger_alert(self):

        event = self.create_event()

        alert = detector.detect_suspicious_process(event)

        self.assertIsNone(alert)

    def test_one_indicator_does_not_trigger_alert(self):

        event = self.create_event(
            process_name="powershell.exe",
            parent_process="explorer.exe",
            executable_path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\powershell.exe"
            ),
            command_line=(
                "powershell.exe "
                "-EncodedCommand [SIMULATED_DATA]"
            )
        )

        alert = detector.detect_suspicious_process(event)

        self.assertIsNone(alert)

    def test_two_indicators_trigger_medium_alert(self):

        event = self.create_event(
            process_name="powershell.exe",
            parent_process="WINWORD.EXE",
            executable_path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\powershell.exe"
            ),
            command_line=(
                "powershell.exe "
                "-EncodedCommand [SIMULATED_DATA]"
            )
        )

        alert = detector.detect_suspicious_process(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["attack_type"],
            "SUSPICIOUS_PROCESS"
        )
        self.assertEqual(
            alert["risk_score"],
            2
        )
        self.assertEqual(
            alert["severity"],
            "MEDIUM"
        )
        self.assertEqual(
            len(alert["indicators"]),
            2
        )

    def test_three_indicators_trigger_high_alert(self):

        event = self.create_event(
            process_name="powershell.exe",
            parent_process="WINWORD.EXE",
            executable_path=(
                r"C:\Users\vasanth\AppData"
                r"\Local\Temp\powershell.exe"
            ),
            command_line=(
                "powershell.exe "
                "-EncodedCommand [SIMULATED_DATA]"
            )
        )

        alert = detector.detect_suspicious_process(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["risk_score"],
            3
        )
        self.assertEqual(
            alert["severity"],
            "HIGH"
        )
        self.assertEqual(
            len(alert["indicators"]),
            3
        )

    def test_same_process_is_not_alerted_twice(self):

        event = self.create_event(
            process_name="powershell.exe",
            process_id=7000,
            parent_process="WINWORD.EXE",
            executable_path=(
                r"C:\Users\vasanth\AppData"
                r"\Local\Temp\powershell.exe"
            ),
            command_line=(
                "powershell.exe "
                "-EncodedCommand [SIMULATED_DATA]"
            )
        )

        first_alert = detector.detect_suspicious_process(
            event
        )

        repeated_alert = detector.detect_suspicious_process(
            event
        )

        self.assertIsNotNone(first_alert)
        self.assertIsNone(repeated_alert)


if __name__ == "__main__":
    unittest.main()