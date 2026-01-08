import os

DB_PATH = os.getenv("DB_PATH", "/db.sqlite3")
JWT_SECRET = os.getenv("JWT_SECRET", "supersecret")
JWT_ALGORITHM = "HS256"
JWT_EXP_SECONDS = 3600
AUTHORIZED_MACS = os.getenv("AUTHORIZED_MACS", "").split(",")
