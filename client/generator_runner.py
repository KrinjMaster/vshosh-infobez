import os
import subprocess

from config import CLIENT_ID, CONFIG_PATH, LOG_GENERATOR_DIR


def start_generator():
    env = os.environ.copy()

    env["HOSTNAME"] = CLIENT_ID
    env["LOG_GENERATOR_CLIENT_ID"] = CLIENT_ID
    env.setdefault("ENABLE_MONITORING", "false")

    cmd = [
        "npm",
        "run",
        "generate",
        "--",
        "--config",
        CONFIG_PATH,
    ]

    print("[GENERATOR] Launching:")
    print(" ".join(cmd))
    print(f"[GENERATOR] cwd = {LOG_GENERATOR_DIR}")

    subprocess.run(
        cmd,
        cwd=LOG_GENERATOR_DIR,  # 🔑 ВАЖНО
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
