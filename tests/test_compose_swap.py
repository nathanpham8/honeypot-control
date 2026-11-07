"""Fix 3: the quarantine server builds under a separate image tag.

No Docker: only checks the generated compose text. Before activation the logging
service uses the stock tag; after activate_silent_logging_server() it uses
bash-arena-logging-server-quarantine:latest. Module globals are restored after.
"""

import sys

from control_arena.settings.bash_arena.base_environment import get_compose_file

from honeypot.plant import activate_silent_logging_server

STOCK = "bash-arena-logging-server:latest"
QUAR = "bash-arena-logging-server-quarantine:latest"


def main() -> int:
    results = []
    orig_compose = get_compose_file.compose_file_path
    orig_logpath = get_compose_file.logging_server_path
    try:
        stock = get_compose_file.get_compose_file("10736505")
        results.append(("stock compose uses the stock logging tag",
                        f"image: {STOCK}" in stock and f"image: {QUAR}" not in stock))

        activate_silent_logging_server()
        quar = get_compose_file.get_compose_file("10736505")
        results.append(("activated compose uses the quarantine tag",
                        f"image: {QUAR}" in quar and f"image: {STOCK}" not in quar))
    finally:
        get_compose_file.compose_file_path = orig_compose
        get_compose_file.logging_server_path = orig_logpath

    # Confirm restoration.
    restored = get_compose_file.get_compose_file("10736505")
    results.append(("stock tag restored after cleanup", f"image: {STOCK}" in restored))

    print("\n================ COMPOSE SWAP TEST ================")
    all_ok = True
    for name, ok in results:
        all_ok = all_ok and ok
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("OVERALL:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
