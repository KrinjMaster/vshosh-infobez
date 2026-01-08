NORMAL_LOGS = [
    "sshd[{pid}]: Accepted password for {user} from {ip} port {port}",
    "systemd[{pid}]: Started Session {session} of user {user}.",
    "sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; COMMAND={cmd}",
    "cron[{pid}]: ({user}) CMD ({cmd})",
    "kernel: eth0: link up",
]

ATTACK_LOGS = [
    "sshd[{pid}]: Failed password for {user} from {ip} port {port}",
    "sudo[{pid}]: {user} : authentication failure",
    "kernel: audit: suspicious execve by {user}",
    "bash[{pid}]: {user} executed suspicious command: {cmd}",
    "kernel: possible credential dumping detected",
]
