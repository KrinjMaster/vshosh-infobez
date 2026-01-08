import socket
import time

import requests
from config import LOG_FILE, SEND_INTERVAL, SERVER_URL

offset = 0
HOSTNAME = socket.gethostname()


def send_line(line):
    payload = {
        "hostname": HOSTNAME,
        "message": line.strip(),
    }
    requests.post(SERVER_URL, json=payload, timeout=2)


def loop():
    global offset

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(offset)
                lines = f.readlines()
                offset = f.tell()

            for line in lines:
                send_line(line)
        except FileNotFoundError:
            pass

        time.sleep(SEND_INTERVAL)
