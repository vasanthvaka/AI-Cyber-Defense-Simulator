import random
import time
from datetime import datetime
from monitor.event_monitor import process_event

users = ["admin", "vasanth", "navyatha", "sudev", "tanishq"]

normal_ips = [
    "192.168.1.10",
    "192.168.1.11",
    "192.168.1.12"
]
attacker_ip = "10.0.0.50"
distributed_attacker_ips = [ "10.0.0.51", "10.0.0.52", "10.0.0.53", "10.0.0.54", "10.0.0.55" ]


def create_login_event(username, ip, status):

    event = {
        "event_type": "LOGIN_ATTEMPT",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "username": username,
        "source_ip": ip,
        "status": status
    }

    return event


def generate_normal_login():

    username = random.choice(users)
    ip = random.choice(normal_ips)

    status = random.choices(
        ["SUCCESS", "FAILED"],
        weights=[90, 10]
    )[0]

    return create_login_event(username, ip, status)


def generate_brute_force():

    return create_login_event(
        username="admin",
        ip=attacker_ip,
        status="FAILED"
    )
def generate_distributed_brute_force(): 
    ip = random.choice(distributed_attacker_ips) 
    return create_login_event( 
        username="admin", 
        ip=ip, 
        status="FAILED" 
    )

for i in range(20):

    if 7 <= i <= 14:
        event = generate_distributed_brute_force()
    else:
        event = generate_normal_login()

    process_event(event)
    time.sleep(0.3)