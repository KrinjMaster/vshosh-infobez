import os
import sqlite3
import sys
import threading
import time

DB_DIR = "/app/data"
DB_PATH = os.path.join(DB_DIR, "bd.sqlite3")
os.makedirs(DB_DIR, exist_ok=True)

HELP_TEXT = """
Available commands:
 help                - show this help
 stats               - show summary statistics
 threats [N]         - show last N threats
 logs [user <name>]  - show last logs or filter by user
 attack-types        - show detected attack types
 clients             - list all clients (mac + id)
 watch               - start real-time monitoring of new threats
 stop                - stop watching threats
 exit                - exit CLI
"""

ATTACK_TYPES = [
    "failed password",
    "sudo attempt",
    "root access",
    "malware",
    "trojan",
    "bruteforce",
    "sql injection",
    "segmentation fault",
    "privilege escalation",
    "unauthorized access",
]


class AdminCLI:
    def __init__(self):
        self.last_check = "1970-01-01 00:00:00"
        self.running = True
        self.watching = False
        self.watch_thread = None

    def watch_threats(self):
        while self.watching:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT id, timestamp, client_id, mac, ip, level, message
                        FROM threats
                        WHERE timestamp > ?
                        ORDER BY timestamp ASC
                    """,
                        (self.last_check,),
                    )
                    rows = c.fetchall()
                    if rows:
                        for r in rows:
                            print(f"[ALERT] {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[6]}")
                        self.last_check = rows[-1][1]
            except Exception as e:
                print("[!] Error reading threats:", e)
            time.sleep(2)

    def run(self):
        print("[ADMIN CLI] Connected to bd.sqlite3")
        print("Type 'help' to see commands.")

        while self.running:
            try:
                cmd = input("admin> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nExiting CLI...")
                self.running = False
                self.watching = False
                break

            if cmd == "help":
                print(HELP_TEXT)

            elif cmd == "watch":
                if not self.watching:
                    self.watching = True
                    self.watch_thread = threading.Thread(
                        target=self.watch_threats, daemon=True
                    )
                    self.watch_thread.start()
                    print("[ADMIN CLI] Watching new threats...")

            elif cmd == "stop":
                if self.watching:
                    self.watching = False
                    if self.watch_thread:
                        self.watch_thread.join(timeout=1)
                    print("[ADMIN CLI] Stopped watching.")

            elif cmd == "stats":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM logs")
                    total_logs = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM threats")
                    total_threats = c.fetchone()[0]
                    c.execute("SELECT COUNT(DISTINCT client_id) FROM logs")
                    clients = c.fetchone()[0]
                print(
                    f"Total logs: {total_logs}, Threats: {total_threats}, Clients: {clients}"
                )

            elif cmd.startswith("threats"):
                n = 10
                parts = cmd.split()
                if len(parts) > 1:
                    try:
                        n = int(parts[1])
                    except:
                        pass
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(
                        "SELECT timestamp, client_id, mac, ip, level, message FROM threats ORDER BY timestamp DESC LIMIT ?",
                        (n,),
                    )
                    rows = c.fetchall()
                    for r in rows:
                        print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]}")

            elif cmd.startswith("logs"):
                parts = cmd.split()
                query = "SELECT timestamp, client_id, mac, ip, level, message FROM logs"
                params = ()
                if len(parts) == 3 and parts[1] == "user":
                    query += " WHERE client_id=?"
                    params = (parts[2],)
                query += " ORDER BY timestamp DESC LIMIT 20"
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(query, params)
                    rows = c.fetchall()
                    for r in rows:
                        print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]}")

            elif cmd == "attack-types":
                for t in ATTACK_TYPES:
                    print("-", t)

            elif cmd == "clients":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT DISTINCT client_id, mac FROM logs")
                    for r in c.fetchall():
                        print(r[0], r[1])

            elif cmd == "exit":
                self.running = False
                self.watching = False
                print("Exiting CLI...")

            else:
                print("Unknown command. Type 'help'")


if __name__ == "__main__":
    cli = AdminCLI()
    cli.run()
