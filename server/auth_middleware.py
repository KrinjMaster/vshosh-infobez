import jwt
from config import ALLOWED_IPS, ALLOWED_MACS, JWT_ALGORITHM, SECRET_KEY
from flask import jsonify, request


def verify_request(f):
    from functools import wraps

    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "JWT required"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        except:
            return jsonify({"error": "Invalid token"}), 401

        mac = request.headers.get("X-MAC-ADDRESS")
        if not mac or mac not in ALLOWED_MACS:
            return jsonify({"error": "Unauthorized MAC"}), 403

        client_ip = request.remote_addr
        if client_ip not in ALLOWED_IPS:
            return jsonify({"error": "Unauthorized IP"}), 403

        request.client_mac = mac
        request.client_id = payload.get("client_id")
        request.client_ip = client_ip

        return f(*args, **kwargs)

    return wrapper
