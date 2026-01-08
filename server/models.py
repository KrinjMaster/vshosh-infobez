import sqlite3

from config import DB_PATH


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            mac TEXT,
            ip TEXT,
            log TEXT,
            is_threat INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        )
        c.execute(
            """
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT,
            mac TEXT,
            ip TEXT,
            log TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
        )
        conn.commit()


def save_log(client_id, mac, ip, log, is_threat):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO logs (client_id, mac, ip, log, is_threat) VALUES (?, ?, ?, ?, ?)",
            (client_id, mac, ip, log, int(is_threat)),
        )
        if is_threat:
            c.execute(
                "INSERT INTO threats (client_id, mac, ip, log) VALUES (?, ?, ?, ?)",
                (client_id, mac, ip, log),
            )
        conn.commit()
