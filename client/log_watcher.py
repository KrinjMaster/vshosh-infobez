import os


class LogWatcher:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.positions = {}

    def read_new(self):
        entries = []

        for filename in os.listdir(self.log_dir):
            if not filename.endswith(".log"):
                continue

            path = os.path.join(self.log_dir, filename)

            if not os.path.isfile(path):
                continue

            if path not in self.positions:
                self.positions[path] = 0

            with open(path, "r", errors="ignore") as f:
                f.seek(self.positions[path])
                lines = f.readlines()
                self.positions[path] = f.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                entries.append({"file": filename, "line": line})

        return entries
