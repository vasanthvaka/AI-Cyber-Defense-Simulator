import random
import time
from datetime import datetime

from monitor.event_monitor import process_event


normal_client_ips = [
    "192.168.1.20",
    "192.168.1.21",
    "192.168.1.22"
]

attacker_ips = [
    "10.0.1.1",
    "10.0.1.2",
    "10.0.1.3",
    "10.0.1.4",
    "10.0.1.5",
    "10.0.1.6",
    "10.0.1.7",
    "10.0.1.8"
]

endpoints = [
    "/",
    "/login",
    "/products",
    "/profile"
]


def create_http_event(ip, endpoint):

    return {
        "event_type": "HTTP_REQUEST",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "source_ip": ip,
        "target_service": "web-server",
        "endpoint": endpoint,
        "method": "GET"
    }


def generate_normal_request():

    ip = random.choice(normal_client_ips)
    endpoint = random.choice(endpoints)

    return create_http_event(
        ip=ip,
        endpoint=endpoint
    )


def generate_ddos_request():

    ip = random.choice(attacker_ips)

    return create_http_event(
        ip=ip,
        endpoint="/login"
    )


for i in range(40):

    if 10 <= i <= 29:
        event = generate_ddos_request()
    else:
        event = generate_normal_request()

    process_event(event)
    time.sleep(0.1)