import threading
import time

from auth import AuthClient
from config import (CLIENT_ID, CLIENT_IP, LOG_DIR, LOG_ENDPOINT, MAC_ADDRESS,
                    SEND_INTERVAL, SERVER_URL)
from generator_runner import start_generator
from log_formatter import jsonl_to_linux_logs_loop
from log_watcher import LogWatcher

BATCH_SIZE = 50


def send_loop():
    auth = AuthClient()

    while not auth.authenticate():
        print("[CLIENT] Waiting for authentication...")
        time.sleep(2)

    session = auth.get_session()
    watcher = LogWatcher(LOG_DIR)

    buffer = []

    while True:
        entries = watcher.read_new()

        for entry in entries:
            buffer.append(
                {
                    "client_id": CLIENT_ID,
                    "mac": MAC_ADDRESS,
                    "ip": CLIENT_IP,
                    "message": entry["line"],
                }
            )

        if len(buffer) >= BATCH_SIZE:
            try:
                r = session.post(
                    SERVER_URL + LOG_ENDPOINT,
                    json={"events": buffer},
                    timeout=5,
                )

                if r.status_code == 401:
                    print("[CLIENT] JWT expired, re-auth...")
                    auth.authenticate()
                    session = auth.get_session()
                else:
                    buffer.clear()

            except Exception as e:
                print("[CLIENT] Send error:", e)

        time.sleep(SEND_INTERVAL)


def main():
    print(f"[CLIENT] Starting client {CLIENT_ID}")

    threading.Thread(target=start_generator, daemon=True).start()
    threading.Thread(
        target=jsonl_to_linux_logs_loop, daemon=True, name="jsonl-to-linux"
    ).start()
    threading.Thread(target=send_loop, daemon=True).start()

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
