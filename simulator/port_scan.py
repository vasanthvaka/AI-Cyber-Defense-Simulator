import random
import time
from datetime import datetime

from monitor.event_monitor import process_event


target_ip = "192.168.1.100"

normal_client_ips = [
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22"
]

scanner_ip = "10.0.2.50"

normal_ports = [
    80,
    443
]

scan_ports = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    5432,
    3389
]

open_ports = {
    22,
    80,
    443,
    3306
}


def create_connection_event(source_ip, destination_port):

    if destination_port in open_ports:
        connection_status = "OPEN"
    else:
        connection_status = "CLOSED"

    return {
        "event_type": "NETWORK_CONNECTION",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "destination_port": destination_port,
        "protocol": "TCP",
        "connection_status": connection_status
    }


def generate_normal_connection():

    source_ip = random.choice(normal_client_ips)
    destination_port = random.choice(normal_ports)

    return create_connection_event(
        source_ip=source_ip,
        destination_port=destination_port
    )


def generate_port_scan(destination_port):

    return create_connection_event(
        source_ip=scanner_ip,
        destination_port=destination_port
    )


def run_port_scan_simulation():

    for i in range(30):

        if 8 <= i <= 22:
            port = scan_ports[i - 8]
            event = generate_port_scan(port)
        else:
            event = generate_normal_connection()

        process_event(event)
        time.sleep(0.2)


if __name__ == "__main__":
    run_port_scan_simulation()