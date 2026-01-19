import re
import time
from collections import defaultdict, deque


class LogAnalyzer:
    def __init__(self):
        self.failed_logins = defaultdict(deque)
        self.rate_limits = defaultdict(deque)
        self.device_events = defaultdict(deque)

        self.WINDOW = 60  # seconds

        self.patterns = {
            "FAILED_LOGIN": re.compile(r"Failed login attempt", re.I),
            "SUCCESS_LOGIN": re.compile(r"login successful", re.I),
            "ACCOUNT_LOCK": re.compile(r"Account .* locked", re.I),
            "SUSPICIOUS_LOGIN": re.compile(r"Suspicious login", re.I),
            "RATE_LIMIT": re.compile(r"Rate limit exceeded", re.I),
            "ATTEMPTS_HIGH": re.compile(r"Attempts:\s*[4-9]/", re.I),
            "PASSWORD_CHANGE": re.compile(r"Password changed", re.I),
            "ADMIN_PATH": re.compile(r"/admin", re.I),
            "ERROR_5XX": re.compile(r"\s5\d\d\s"),
            "BACKUP_CORRUPT": re.compile(r"Integrity:\s*CORRUPTED", re.I),
            "BACKUP_GROWTH": re.compile(r"Backup size increased", re.I),
            "DEVICE_SUSPICIOUS": re.compile(r"Suspicious device behavior", re.I),
            "DEVICE_OFFLINE": re.compile(r"Device .* offline", re.I),
            "FIRMWARE_OUTDATED": re.compile(r"firmware outdated", re.I),
        }

    def _cleanup(self, dq):
        now = time.time()
        while dq and now - dq[0] > self.WINDOW:
            dq.popleft()

    def _extract_ip(self, line):
        m = re.search(r"IP:\s*([\d\.]+)", line)
        return m.group(1) if m else None

    def _extract_device(self, line):
        m = re.search(r"Device\s+([a-f0-9\-]{8,})", line, re.I)
        return m.group(1) if m else None

    def analyze_line(self, line: str) -> str:
        now = time.time()
        risk = 0

        #  Brute force
        if self.patterns["FAILED_LOGIN"].search(line):
            ip = self._extract_ip(line)
            if ip:
                self.failed_logins[ip].append(now)
                self._cleanup(self.failed_logins[ip])
                risk += 1

                if len(self.failed_logins[ip]) >= 3:
                    return "THREAT"

        if self.patterns["ATTEMPTS_HIGH"].search(line):
            return "THREAT"

        if self.patterns["ACCOUNT_LOCK"].search(line):
            return "THREAT"

        # Suspicious login
        if self.patterns["SUSPICIOUS_LOGIN"].search(line):
            risk += 3

        # API abuse / DoS-lite
        if self.patterns["RATE_LIMIT"].search(line):
            ip = self._extract_ip(line)
            if ip:
                self.rate_limits[ip].append(now)
                self._cleanup(self.rate_limits[ip])
                if len(self.rate_limits[ip]) >= 2:
                    return "THREAT"
            risk += 2

        if self.patterns["ERROR_5XX"].search(line):
            risk += 1

        #  Account takeover scenario
        if self.patterns["SUCCESS_LOGIN"].search(line) and risk >= 3:
            return "THREAT"

        if self.patterns["PASSWORD_CHANGE"].search(line) and risk >= 3:
            return "THREAT"

        #  Backup / ransomware indicators
        if self.patterns["BACKUP_CORRUPT"].search(line):
            return "THREAT"

        if self.patterns["BACKUP_GROWTH"].search(line):
            risk += 2

        #  IoT compromise
        if self.patterns["DEVICE_SUSPICIOUS"].search(line):
            device = self._extract_device(line)
            if device:
                self.device_events[device].append(now)
                self._cleanup(self.device_events[device])
                if len(self.device_events[device]) >= 2:
                    return "THREAT"
            risk += 3

        if self.patterns["DEVICE_OFFLINE"].search(line):
            risk += 2

        if self.patterns["FIRMWARE_OUTDATED"].search(line):
            risk += 1

        if risk >= 5:
            return "THREAT"
        elif risk >= 2:
            return "WARNING"

        return "INFO"

    def analyze_logs(self, lines):
        results = {
            "THREAT": [],
            "WARNING": [],
            "INFO": [],
        }

        for line in lines:
            level = self.analyze_line(line)
            results[level].append(line)

        return results
