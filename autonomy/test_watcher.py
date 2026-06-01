import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(__file__)
STATE_FILE = os.path.join(BASE_DIR, "project_state.json")


def inject_pending_task(task_id, description):
    print(f"[*] Injecting task: {task_id}")

    with open(STATE_FILE, "r") as f:
        state = json.load(f)

    new_task = {"id": task_id, "description": description, "status": "pending", "dependencies": []}

    state["tasks"].append(new_task)
    state["metadata"]["last_updated"] = datetime.utcnow().isoformat() + "Z"

    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

    print("[*] Injection successful.")


if __name__ == "__main__":
    inject_pending_task("test-task-999", "This is a test task for the watcher.")
