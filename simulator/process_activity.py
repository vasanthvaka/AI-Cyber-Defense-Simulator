import random
import time
from datetime import datetime

from monitor.event_monitor import process_event


normal_processes = [
    {
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "executable_path": (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ),
        "command_line": "chrome.exe"
    },
    {
        "process_name": "Code.exe",
        "parent_process": "explorer.exe",
        "executable_path": (
            r"C:\Users\vasanth\AppData\Local\Programs"
            r"\Microsoft VS Code\Code.exe"
        ),
        "command_line": "Code.exe"
    },
    {
        "process_name": "python.exe",
        "parent_process": "Code.exe",
        "executable_path": (
            r"C:\Users\vasanth\AppData\Local\Programs"
            r"\Python\Python311\python.exe"
        ),
        "command_line": "python app.py"
    },
    {
        "process_name": "notepad.exe",
        "parent_process": "explorer.exe",
        "executable_path": (
            r"C:\Windows\System32\notepad.exe"
        ),
        "command_line": "notepad.exe"
    }
]


def create_process_event(
    process_name,
    parent_process,
    executable_path,
    command_line
):

    return {
        "event_type": "PROCESS_ACTIVITY",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "process_name": process_name,
        "process_id": random.randint(1000, 9999),
        "parent_process": parent_process,
        "user": "vasanth",
        "executable_path": executable_path,
        "command_line": command_line,
        "action": "STARTED"
    }


def generate_normal_process():

    process = random.choice(normal_processes)

    return create_process_event(
        process_name=process["process_name"],
        parent_process=process["parent_process"],
        executable_path=process["executable_path"],
        command_line=process["command_line"]
    )


def generate_suspicious_process():

    return create_process_event(
        process_name="powershell.exe",
        parent_process="WINWORD.EXE",
        executable_path=(
            r"C:\Users\vasanth\AppData\Local\Temp\powershell.exe"
        ),
        command_line=(
            "powershell.exe -EncodedCommand [SIMULATED_DATA]"
        )
    )


for i in range(12):

    if i == 6:
        event = generate_suspicious_process()
    else:
        event = generate_normal_process()

    process_event(event)
    time.sleep(0.3)