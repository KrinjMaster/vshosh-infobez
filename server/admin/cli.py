import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta

DB_PATH = os.getenv("DB_PATH", "app/db.sqlite3")

HELP_TEXT = """
Available commands:
 help                         - show this help
 stats                        - show summary statistics
 stats levels                 - logs count by INFO/WARNING/THREAT
 threats [N]                  - show last N threats
 logs                          - show last logs
 logs user <name>             - filter logs by client_id
 logs level <INFO|WARNING|THREAT>
 clients                      - list all clients
 top-threats                  - top clients by threat count
 correlate                    - run attack correlation engine
 watch                        - real-time threat monitoring
 stop                         - stop watching
 exit                         - exit CLI
"""


class AdminCLI:
    def __init__(self):
        self.running = True
        self.watching = False
        self.last_check = "1970-01-01 00:00:00"
        self.watch_thread = None

    def watch_threats(self):
        print("[WATCH] Real-time THREAT monitoring started")
        while self.watching:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT timestamp, client_id, ip, message
                        FROM threats
                        WHERE timestamp > ?
                        ORDER BY timestamp ASC
                        """,
                        (self.last_check,),
                    )
                    rows = c.fetchall()

                    if rows:
                        for r in rows:
                            print(
                                f"[THREAT] {r[0]} | client={r[1]} | ip={r[2]} | {r[3]}"
                            )
                        self.last_check = rows[-1][0]
            except Exception as e:
                print("[ERROR] watch:", e)

            time.sleep(2)

    def correlate_attacks(self):
        # more than 4 unsuccesful login then succesful -> bruteforce correlation
        window_start = (datetime.utcnow() - timedelta(minutes=2)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        inserted = 0

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()

            c.execute(
                """
                SELECT client_id, ip, COUNT(*)
                FROM logs
                WHERE message LIKE '%Failed login attempt%'
                  AND timestamp > ?
                GROUP BY client_id, ip
                HAVING COUNT(*) >= 5
                """,
                (window_start,),
            )

            suspects = c.fetchall()

            for client_id, ip, attempts in suspects:
                c.execute(
                    """
                    SELECT timestamp
                    FROM logs
                    WHERE client_id = ?
                      AND message LIKE '%login successful%'
                      AND timestamp > ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                    """,
                    (client_id, window_start),
                )
                success = c.fetchone()

                if success:
                    msg = (
                        f"Bruteforce suspected: {attempts} failed logins "
                        f"followed by successful login"
                    )
                    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                    c.execute(
                        """
                        INSERT INTO threats (timestamp, client_id, mac, ip, level, message)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (ts, client_id, "-", ip, "THREAT", msg),
                    )
                    inserted += 1

            conn.commit()

        print(f"[CORRELATION] New correlated threats: {inserted}")

    def run(self):
        print(f"[ADMIN CLI] Connected to {DB_PATH}")
        print("Type 'help' to see commands")

        while self.running:
            try:
                cmd = input("admin> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nExiting CLI...")
                self.running = False
                self.watching = False
                break

            if not cmd:
                continue

            if cmd == "help":
                print(HELP_TEXT)

            elif cmd == "watch":
                if not self.watching:
                    self.watching = True
                    self.watch_thread = threading.Thread(
                        target=self.watch_threats, daemon=True
                    )
                    self.watch_thread.start()

            elif cmd == "stop":
                self.watching = False
                print("[WATCH] Stopped")

            elif cmd == "stats":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM logs")
                    logs = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM threats")
                    threats = c.fetchone()[0]
                    c.execute("SELECT COUNT(DISTINCT client_id) FROM logs")
                    clients = c.fetchone()[0]

                print(f"Logs: {logs} | Threats: {threats} | Clients: {clients}")

            elif cmd == "stats levels":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT level, COUNT(*) FROM logs GROUP BY level")
                    for lvl, cnt in c.fetchall():
                        print(f"{lvl}: {cnt}")

            elif cmd.startswith("threats"):
                n = 10
                parts = cmd.split()
                if len(parts) == 2:
                    try:
                        n = int(parts[1])
                    except:
                        pass

                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT timestamp, client_id, ip, message
                        FROM threats
                        ORDER BY timestamp DESC
                        LIMIT ?
                        """,
                        (n,),
                    )
                    for r in c.fetchall():
                        print(f"{r[0]} | client={r[1]} | ip={r[2]} | {r[3]}")

            elif cmd.startswith("logs"):
                parts = cmd.split()
                query = "SELECT timestamp, client_id, level, message FROM logs"
                params = []

                if len(parts) == 3 and parts[1] == "user":
                    query += " WHERE client_id=?"
                    params.append(parts[2])

                elif len(parts) == 3 and parts[1] == "level":
                    query += " WHERE level=?"
                    params.append(parts[2].upper())

                query += " ORDER BY timestamp DESC LIMIT 20"

                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(query, params)
                    for r in c.fetchall():
                        print(f"{r[0]} | {r[1]} | {r[2]} | {r[3]}")

            elif cmd == "clients":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT DISTINCT client_id, mac FROM logs")
                    for r in c.fetchall():
                        print(f"{r[0]} | {r[1]}")

            elif cmd == "top-threats":
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute(
                        """
                        SELECT client_id, COUNT(*)
                        FROM threats
                        GROUP BY client_id
                        ORDER BY COUNT(*) DESC
                        LIMIT 10
                        """
                    )
                    for r in c.fetchall():
                        print(f"{r[0]} -> {r[1]} threats")

            elif cmd == "correlate":
                self.correlate_attacks()

            elif cmd == "exit":
                self.running = False
                self.watching = False
                print("Bye")

            else:
                print("Unknown command. Type 'help'")


if __name__ == "__main__":
    AdminCLI().run()
