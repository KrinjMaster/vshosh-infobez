import os
import random
import threading
import time
from datetime import datetime

import requests
from auth import AuthClient
from config import (
    CLIENT_ID,
    CLIENT_IP,
    LOG_DIR,
    LOG_ENDPOINT,
    MAC_ADDRESS,
    SEND_INTERVAL,
    SERVER_URL,
    USERNAMES,
)

NORMAL_LOGS = [
    "INFO User login success user={user}",
    "INFO Process started name=sshd pid={pid}",
    "INFO File accessed path=/home/{user}/report.docx",
    "WARNING Disk usage high on /dev/sda1",
    "ERROR Permission denied user={user} command=sudo",
]

THREAT_LOGS = [
    "WARNING Failed password attempt user={user} from IP {ip}",
    "ERROR Unauthorized root access attempt by user={user}",
    "ALERT Malware detected in /tmp/malicious.sh",
    "ALERT Brute-force login detected for user={user}",
    "CRITICAL Segmentation fault in process sshd pid={pid}",
    "ALERT Suspicious port scanning activity from IP {ip}",
    "ERROR SQL injection attempt in webapp by user={user}",
    "WARNING Trojan dropped in /opt/backdoor",
    "ALERT Privilege escalation detected for user={user}",
    "CRITICAL Unauthorized sudo command by user={user}",
]


def generate_log_line():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = random.choice(USERNAMES)
    pid = random.randint(1000, 5000)
    ip = CLIENT_IP

    template = (
        random.choice(THREAT_LOGS)
        if random.random() < 0.07
        else random.choice(NORMAL_LOGS)
    )
    line = template.format(user=user, pid=pid, ip=ip)
    return f"{ts} {line}\n"


def log_writer():
    os.makedirs(LOG_DIR, exist_ok=True)
    filename = os.path.join(LOG_DIR, f"log_{CLIENT_ID}.log")
    while True:
        with open(filename, "a") as f:
            f.write(generate_log_line())
        time.sleep(1)


class LogWatcher:
    def __init__(self):
        self.positions = {}

    def read_new(self):
        entries = []
        for file in os.listdir(LOG_DIR):
            path = os.path.join(LOG_DIR, file)
            if path not in self.positions:
                self.positions[path] = 0
            with open(path, "r") as f:
                f.seek(self.positions[path])
                lines = f.readlines()
                self.positions[path] = f.tell()
                for line in lines:
                    entries.append({"file": file, "line": line.strip()})
        return entries


def send_loop():
    auth_client = AuthClient()

    while not auth_client.authenticate():
        print("[CLIENT] Waiting for auth...")
        time.sleep(2)
    session = auth_client.get_session()
    watcher = LogWatcher()

    while True:
        entries = watcher.read_new()
        for e in entries:
            payload = {
                "client_id": CLIENT_ID,
                "mac": MAC_ADDRESS,
                "ip": CLIENT_IP,
                "level": "INFO",
                "message": e["line"],
            }
            try:
                resp = session.post(SERVER_URL + LOG_ENDPOINT, json=payload, timeout=5)
                if resp.status_code == 401:
                    print("[CLIENT] Token expired, re-authenticating...")
                    auth_client.authenticate()
                    session = auth_client.get_session()
            except Exception as ex:
                print("[!] Send log error:", ex)
        time.sleep(SEND_INTERVAL)


def main():
    threading.Thread(target=log_writer, daemon=True).start()
    threading.Thread(target=send_loop, daemon=True).start()

    print(f"[*] Client {CLIENT_ID} started, MAC={MAC_ADDRESS}, IP={CLIENT_IP}")

    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()
