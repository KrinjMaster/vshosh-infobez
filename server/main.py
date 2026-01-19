import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta

import jwt
from auth_middleware import verify_request
from config import (
    AUTHORIZED_IPS,
    AUTHORIZED_MACS,
    DB_PATH,
    JWT_ALGORITHM,
    JWT_EXP_SECONDS,
    JWT_SECRET,
)
from flask import Flask, jsonify, request
from log_analyzer import LogAnalyzer

ANALYSIS_INTERVAL = 2
BUFFER_LIMIT = 1000

log_buffer = []
buffer_lock = threading.Lock()

analyzer = LogAnalyzer()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_id TEXT,
            mac TEXT,
            ip TEXT,
            level TEXT,
            message TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_id TEXT,
            mac TEXT,
            ip TEXT,
            level TEXT,
            message TEXT
        )
        """
    )

    conn.commit()
    conn.close()


init_db()


app = Flask(__name__)


def create_jwt(client_ip):
    payload = {
        "ip": client_ip,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_SECONDS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def check_jwt():
    token = request.cookies.get("access_token")
    if not token:
        return False
    try:
        jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return True
    except Exception:
        return False


def analysis_loop():
    while True:
        time.sleep(ANALYSIS_INTERVAL)

        with buffer_lock:
            if not log_buffer:
                continue
            batch = log_buffer.copy()
            log_buffer.clear()

        results = analyzer.analyze_logs([entry["message"] for entry in batch])

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        for entry in batch:
            level = analyzer.analyze_line(entry["message"])
            cur.execute(
                """
                INSERT INTO logs (timestamp, client_id, mac, ip, level, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry["timestamp"],
                    entry["client_id"],
                    entry["mac"],
                    entry["ip"],
                    level,
                    entry["message"],
                ),
            )

        for threat_msg in results["THREAT"]:
            for entry in batch:
                if entry["message"] == threat_msg:
                    cur.execute(
                        """
                        INSERT INTO threats (timestamp, client_id, mac, ip, level, message)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entry["timestamp"],
                            entry["client_id"],
                            entry["mac"],
                            entry["ip"],
                            "THREAT",
                            entry["message"],
                        ),
                    )
                    print(
                        f"[THREAT] {entry['timestamp']} {entry['client_id']} {entry['ip']} {entry['message']}"
                    )

        conn.commit()
        conn.close()


@app.route("/api/auth", methods=["POST"])
def auth():
    client_ip = request.remote_addr

    token = create_jwt(client_ip)

    response = jsonify({"status": "authenticated"})
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="Strict",
        max_age=JWT_EXP_SECONDS,
    )
    return response


@app.route("/api/log", methods=["POST"])
@verify_request
def receive_logs():
    data = request.json or {}
    events = data.get("events", [])

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    with buffer_lock:
        for e in events:
            log_buffer.append(
                {
                    "timestamp": now,
                    "client_id": e.get("client_id", "unknown"),
                    "mac": e.get("mac", "uknown_mac"),
                    "ip": e.get("ip", "uknown_ip"),
                    "message": e.get("message", ""),
                }
            )

        if len(log_buffer) > BUFFER_LIMIT:
            log_buffer[:] = log_buffer[-BUFFER_LIMIT:]

    return jsonify({"status": "accepted", "count": len(events)})


if __name__ == "__main__":
    print("[*] SIEM Server starting on 0.0.0.0:8000")
    threading.Thread(target=analysis_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8000)
