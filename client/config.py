import os

CLIENT_ID = os.getenv("CLIENT_ID", "client1")

MAC_ADDRESS = os.getenv("MAC_ADDRESS", "AA:BB:CC:00:01")
CLIENT_IP = os.getenv("CLIENT_IP", "172.28.0.2")
VERIFY_TLS = os.getenv("VERIFY_TLS", False)

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, f"log_{CLIENT_ID}.log")

SERVER_URL = os.getenv("SERVER_URL", "http://172.28.0.10:8000")
AUTH_ENDPOINT = "/api/auth"
LOG_ENDPOINT = "/api/log"

USERNAMES = ["guest", "admin"]

SEND_INTERVAL = 2
