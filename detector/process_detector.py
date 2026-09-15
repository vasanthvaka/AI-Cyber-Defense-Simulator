suspicious_parent_child_pairs = {
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe")
}

suspicious_command_patterns = [
    "-encodedcommand",
    "invoke-webrequest",
    "downloadstring"
]

suspicious_path_patterns = [
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public"
]

flagged_processes = set()

RISK_THRESHOLD = 2


def detect_suspicious_process(event):

    process_name = event["process_name"].lower()
    parent_process = event["parent_process"].lower()
    command_line = event["command_line"].lower()
    executable_path = event["executable_path"].lower()
    process_id = event["process_id"]

    risk_score = 0
    indicators = []

    # Check the parent-child relationship
    process_pair = (parent_process, process_name)

    if process_pair in suspicious_parent_child_pairs:
        risk_score += 1
        indicators.append(
            "Suspicious parent-child process relationship"
        )

    # Check for suspicious command-line patterns
    if any(
        pattern in command_line
        for pattern in suspicious_command_patterns
    ):
        risk_score += 1
        indicators.append(
            "Suspicious command-line pattern"
        )

    # Check whether the executable is in a suspicious location
    if any(
        pattern in executable_path
        for pattern in suspicious_path_patterns
    ):
        risk_score += 1
        indicators.append(
            "Executable running from a suspicious location"
        )

    if (
        risk_score >= RISK_THRESHOLD
        and process_id not in flagged_processes
    ):
        flagged_processes.add(process_id)

        if risk_score == 3:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        return {
            "attack_type": "SUSPICIOUS_PROCESS",
            "process_name": event["process_name"],
            "process_id": process_id,
            "parent_process": event["parent_process"],
            "user": event["user"],
            "executable_path": event["executable_path"],
            "command_line": event["command_line"],
            "risk_score": risk_score,
            "indicators": indicators,
            "severity": severity
        }

    return None