import ipaddress
import json
import os
import random
import time
from datetime import datetime
from pathlib import Path

from config import CLIENT_ID, CLIENT_IP, LOG_DIR, USERNAMES

used = {}


def random_ipv4():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def format_syslog(entry: dict) -> str:
    ts_raw = entry.get("timestamp")
    try:
        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
        ts_str = ts.strftime("%b %d %H:%M:%S")
    except Exception:
        ts_str = datetime.now().strftime("%b %d %H:%M:%S")

    host = f"{CLIENT_ID}@{CLIENT_IP}"

    service = (
        entry.get("source", {}).get("service")
        or entry.get("service")
        or entry.get("component")
        or "system"
    )

    pid = entry.get("pid")

    if not pid:
        correlation = entry.get("metadata", {}).get("correlationId", "0000")
        pid = str(abs(hash(correlation)) % 10000)

    message = (
        entry.get("message", "")
        .strip()
        .replace("{USERID}", random.choice(USERNAMES))
        .replace("{USERNAME}", random.choice(USERNAMES))
        .replace("{CLIENTIP}", CLIENT_IP)
        .replace("{SESSIONID}", CLIENT_IP)
        .replace("{SRCIP}", CLIENT_IP)
        .replace("{DSTIP}", str(random_ipv4()))
        .replace("{SRCPORT}", str(random.randint(1024, 65535)))
        .replace("{DSTPORT}", str(random.randint(1024, 65535)))
    )

    return f"{ts_str} {host} {service}[{pid}]: {message}"


def jsonl_to_linux_logs_loop():
    while True:
        for jsonl_file in Path(LOG_DIR).glob("*.jsonl"):
            if used.get(jsonl_file) is None:
                time.sleep(1)
                process_file(jsonl_file)

                try:
                    os.remove(jsonl_file)
                except:
                    pass


def process_file(jsonl_path: Path):
    out_path = str(jsonl_path).replace(".jsonl", ".log")

    with open(jsonl_path, "r") as src, open(out_path, "w") as dst:
        for line in src:
            line = line.strip()

            if not line:
                continue
            try:
                entry = json.loads(line)
                dst.write(format_syslog(entry) + "\n")
            except json.JSONDecodeError:
                continue

        used[jsonl_path] = True

    print(f"[OK] {os.path.basename(jsonl_path)} → {os.path.basename(out_path)}")
