import os
import sqlite3
from datetime import datetime, timedelta

import jwt
from flask import Flask, jsonify, request

DB_DIR = "/app/data"
DB_PATH = os.path.join(DB_DIR, "bd.sqlite3")
os.makedirs(DB_DIR, exist_ok=True)

JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "AA:BB:CC:00:01,AA:BB:CC:00:02").split(
    ","
)

THREAT_KEYWORDS = [
    "failed password",
    "unauthorized",
    "segmentation fault",
    "root access",
    "malware",
    "trojan",
    "bruteforce",
    "sql injection",
    "permission denied",
    "error",
]

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()
cursor.execute(
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
cursor.execute(
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

app = Flask(__name__)


def create_jwt(client_ip):
    payload = {"ip": client_ip, "exp": datetime.utcnow() + timedelta(hours=1)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def detect_threat(message):
    msg = message.lower()
    return any(word in msg for word in THREAT_KEYWORDS)


@app.route("/api/auth", methods=["POST"])
def auth():
    client_mac = request.headers.get("X-MAC-ADDRESS")
    client_ip = request.remote_addr

    if client_mac not in AUTHORIZED_MACS:
        return jsonify({"error": "Unauthorized MAC"}), 403

    token = create_jwt(client_ip)
    response = jsonify({"status": "authenticated"})
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="Strict",
        max_age=3600,
    )
    return response


@app.route("/api/log", methods=["POST"])
def log():
    token = request.cookies.get("access_token")
    if not token:
        return jsonify({"error": "JWT required"}), 401
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return jsonify({"error": "Invalid JWT"}), 401

    client_mac = request.headers.get("X-MAC-ADDRESS")
    client_ip = request.remote_addr

    if client_mac not in AUTHORIZED_MACS:
        return jsonify({"error": "Unauthorized MAC"}), 403

    data = request.json
    client_id = data.get("client_id", "unknown")
    level = data.get("level", "INFO")
    message = data.get("message", "")

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO logs (timestamp, client_id, mac, ip, level, message)
        VALUES (?, ?, ?, ?, ?, ?)
    """,
        (timestamp, client_id, client_mac, client_ip, level, message),
    )
    conn.commit()

    if detect_threat(message):
        cursor.execute(
            """
            INSERT INTO threats (timestamp, client_id, mac, ip, level, message)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (timestamp, client_id, client_mac, client_ip, level, message),
        )
        conn.commit()
        print(f"[THREAT] {timestamp} {client_id} {client_ip} {message}")

    conn.close()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("[*] Server starting on 0.0.0.0:8000...")
    app.run(host="0.0.0.0", port=8000)
