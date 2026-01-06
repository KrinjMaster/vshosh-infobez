import os
import re
import select
import sys
import time
from datetime import datetime

LOG_DIR = "./logs"
SCAN_INTERVAL = 2  # секунды

# --- правила детекта ---
THREAT_RULES = {
    "BRUTE_FORCE": re.compile(r"Failed password"),
    "PRIV_ESC": re.compile(r"(sudo|su).*COMMAND"),
    "EXEC_BLOCKED": re.compile(r"EXEC_BLOCKED"),
    "NETWORK_SCAN": re.compile(r"(nmap|port scan)", re.IGNORECASE),
}

# --- состояние ---
known_offsets = {}  # файл -> позиция
all_events = []  # все события
alerts = []  # все угрозы
new_alerts_buffer = []  # новые угрозы (для уведомления)
notification_pending = False


# ---------- UTILS ----------


def parse_log_line(line):
    """
    Парсинг linux-подобного лога
    """
    try:
        # Добавляем год прямо при парсинге
        # Убираем DeprecationWarning
        now_year = 2026  # можно динамически: datetime.now().year
        ts = datetime.strptime(f"{now_year} {line[:15]}", "%Y %b %d %H:%M:%S")
    except Exception:
        return None

    host_match = re.search(r"\s([a-zA-Z0-9\-]+)\s", line)
    host = host_match.group(1) if host_match else "unknown"

    user_match = re.search(r"user\s*=?\s*([a-zA-Z0-9\[\]_]+)", line)
    user = user_match.group(1) if user_match else "system"

    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    ip = ip_match.group(1) if ip_match else "-"

    action = "INFO"
    for name, pattern in THREAT_RULES.items():
        if pattern.search(line):
            action = name
            break

    return {
        "timestamp": ts,
        "host": host,
        "user": user,
        "ip": ip,
        "action": action,
        "raw": line.strip(),
    }


# ---------- SCANNER ----------


def scan_logs():
    global notification_pending

    for filename in os.listdir(LOG_DIR):
        path = os.path.join(LOG_DIR, filename)
        if not os.path.isfile(path):
            continue

        if path not in known_offsets:
            known_offsets[path] = 0

        with open(path, "r", errors="ignore") as f:
            f.seek(known_offsets[path])
            lines = f.readlines()
            known_offsets[path] = f.tell()

        for line in lines:
            event = parse_log_line(line)
            if not event:
                continue

            all_events.append(event)

            if event["action"] != "INFO":
                alerts.append(event)
                new_alerts_buffer.append(event)
                notification_pending = True


# ---------- UI ----------


def show_menu():
    print("\n--- Mini-SIEM (Blue Team) ---")
    print("1. Последние события")
    print("2. Активные алерты")
    print("3. Алерты по пользователю")
    print("4. Статистика")
    print("5. Выход")
    print("> ", end="", flush=True)


def show_new_alerts_prompt():
    global notification_pending
    count = len(new_alerts_buffer)
    print(f"\n🚨 Обнаружено {count} новых угроз. Посмотреть? (y/n)")
    print("> ", end="", flush=True)


def handle_new_alerts(answer):
    global new_alerts_buffer, notification_pending

    if answer.lower() == "y":
        for a in new_alerts_buffer:
            print(
                f"[{a['action']}] {a['timestamp']} {a['host']} user={a['user']} ip={a['ip']}"
            )
    new_alerts_buffer.clear()
    notification_pending = False


def show_last_events():
    for e in all_events[-10:]:
        print(
            f"{e['timestamp']} | {e['host']} | user={e['user']} | ip={e['ip']} | {e['action']}"
        )


def show_alerts():
    for a in alerts[-10:]:
        print(
            f"[{a['action']}] {a['timestamp']} {a['host']} user={a['user']} ip={a['ip']}"
        )


def show_alerts_by_user():
    user = input("Введите пользователя: ")
    for a in alerts:
        if a["user"] == user:
            print(f"[{a['action']}] {a['timestamp']} {a['host']} ip={a['ip']}")


def show_stats():
    stats = {}
    for a in alerts:
        stats[a["action"]] = stats.get(a["action"], 0) + 1
    for k, v in stats.items():
        print(f"{k}: {v}")


# ---------- MAIN LOOP ----------


def main():
    print("Mini-SIEM запущен. Мониторинг логов...\n")
    show_menu()

    last_scan = 0

    while True:
        now = time.time()

        # --- периодическое сканирование ---
        if now - last_scan >= SCAN_INTERVAL:
            scan_logs()
            last_scan = now

            if notification_pending:
                show_new_alerts_prompt()

        # --- неблокирующий ввод ---
        r, _, _ = select.select([sys.stdin], [], [], 0.5)
        if not r:
            continue

        cmd = sys.stdin.readline().strip()

        # --- обработка уведомлений ---
        if notification_pending and cmd.lower() in ("y", "n"):
            handle_new_alerts(cmd)
            show_menu()
            continue

        # --- меню ---
        if cmd == "1":
            show_last_events()
        elif cmd == "2":
            show_alerts()
        elif cmd == "3":
            show_alerts_by_user()
        elif cmd == "4":
            show_stats()
        elif cmd == "5":
            print("Выход.")
            break

        show_menu()


if __name__ == "__main__":
    if not os.path.isdir(LOG_DIR):
        os.makedirs(LOG_DIR)
    main()
