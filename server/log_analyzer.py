import re


class LogAnalyzer:
    def __init__(self):
        self.threat_patterns = [
            r"Account .* locked",
            r"Suspicious login",
            r"Suspicious request pattern",
            r"Unauthorized access",
            r"Invalid credentials",
            r"Rate limit exceeded",
            r"Attempts:\s*[4-9]/",
            r"Attempts:\s*5/5",
        ]

        self.warning_patterns = [
            r"Failed login attempt",
            r"Database connection failed",
            r"\s4\d\d\s",
            r"\s5\d\d\s",
            r"battery low",
            r"firmware outdated",
            r"Bad request",
            r"Internal server error",
            r"Resource not found",
        ]

    def analyze_line(self, line: str) -> str:
        for pattern in self.threat_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return "THREAT"

        for pattern in self.warning_patterns:
            if re.search(pattern, line, re.IGNORECASE):
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
