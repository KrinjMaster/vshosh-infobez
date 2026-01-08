import os
import random
import time
from datetime import datetime

from config import CLIENT_IP, LOG_FILE

ATTACKS = (
    [f"Failed password attempt for user{n} from IP {CLIENT_IP}" for n in range(1, 11)]
    + [
        f"Unauthorized sudo command executed by admin from IP {CLIENT_IP}"
        for _ in range(10)
    ]
    + [f"Segmentation fault in process sshd from IP {CLIENT_IP}" for _ in range(10)]
    + [f"Malware detected in /tmp/tmpfile from IP {CLIENT_IP}" for _ in range(10)]
    + [f"Bruteforce login attempt detected from IP {CLIENT_IP}" for _ in range(10)]
    + [f"SQL injection attempt in webapp from IP {CLIENT_IP}" for _ in range(10)]
    + [f"Root access granted to user{n} from IP {CLIENT_IP}" for n in range(1, 11)]
    + [f"Credential dumping attempt from IP {CLIENT_IP}" for _ in range(10)]
    + [f"Unauthorized file access by admin from IP {CLIENT_IP}" for _ in range(10)]
    + [f"Exploit detected in process bash from IP {CLIENT_IP}" for _ in range(10)]
)

NORMAL = [
    "User login successful",
    "File opened: /home/user/document.txt",
    "Process started: firefox",
    "User logout",
    "Package updated: apt-get upgrade",
    "Cron job executed",
    "SSH session started",
    "System check completed",
    "Disk usage: 40%",
    "Network interface eth0 up",
]


def generate_line():
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    hostname = os.getenv("CLIENT_ID", "client_1")
    user = random.choice(["guest", "admin"])
    msg = random.choice(ATTACKS) if random.random() < 0.02 else random.choice(NORMAL)
    return f"{ts} {hostname} {user}: {msg}\n"


def run_generator():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    while True:
        line = generate_line()
        with open(LOG_FILE, "a") as f:
            f.write(line)
        time.sleep(1)
