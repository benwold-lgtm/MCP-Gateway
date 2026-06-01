import json
import time
import os
from datetime import datetime

BASE_DIR = os.path.dirname(__file__)
STATE_FILE = os.path.join(BASE_DIR, "project_state.json")


def monitor_state():
    print(f"[*] Starting Watcher: Monitoring {STATE_FILE}")
    last_mtime = os.path.getmtime(STATE_FILE)

    try:
        while True:
            current_mtime = os.path.getmtime(STATE_FILE)

            if current_mtime != last_mtime:
                last_mtime = current_mtime
                print(f"[{datetime.now().isoformat()}] State change detected.")

                with open(STATE_FILE, "r") as f:
                    state = json.load(f)

                for task in state.get("tasks", []):
                    if task.get("status") == "pending":
                        print(f"[!] ALERT: Pending task found: {task['id']} - {task['description']}")
                        # In a real implementation, this is where you would trigger
                        # an LLM call or a subagent process.
                        # For now, we just log the detection.

                print("[*] Monitoring complete for this cycle. Waiting for next change...")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] Watcher stopped by user.")
    except Exception as e:
        print(f"[!] Watcher Error: {e}")


if __name__ == "__main__":
    monitor_state()
