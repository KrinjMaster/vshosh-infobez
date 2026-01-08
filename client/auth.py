import requests
from config import AUTH_ENDPOINT, MAC_ADDRESS, SERVER_URL, VERIFY_TLS


class AuthClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"X-MAC-ADDRESS": MAC_ADDRESS})

    def authenticate(self):
        try:
            resp = self.session.post(
                SERVER_URL + AUTH_ENDPOINT, verify=VERIFY_TLS, timeout=5
            )
            if resp.status_code == 200:
                print("[AUTH] Auth success")
                return True
            else:
                print(f"[AUTH] Failed: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            print("[AUTH] Error:", e)
            return False

    def get_session(self):
        return self.session
