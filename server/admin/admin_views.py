import sqlite3

from config import DB_PATH
from flask import Blueprint, jsonify, request

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/api/admin/threats", methods=["GET"])
def get_new_threats():
    since = request.args.get("since", "1970-01-01 00:00:00")
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(
            """
            SELECT id, client_id, mac, ip, log, timestamp
            FROM threats
            WHERE timestamp > ?
            ORDER BY timestamp ASC
        """,
            (since,),
        )
        rows = c.fetchall()

    return jsonify(
        [
            {
                "id": r[0],
                "client_id": r[1],
                "mac": r[2],
                "ip": r[3],
                "log": r[4],
                "timestamp": r[5],
            }
            for r in rows
        ]
    )
