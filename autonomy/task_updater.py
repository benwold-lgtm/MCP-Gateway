import json
import sys
import argparse

MANIFEST_FILE = "project_manifest.json"


def update_task_status(task_id, new_status):
    with open(MANIFEST_FILE, "r") as f:
        data = json.load(f)

    found = False
    for task in data["tasks"]:
        if task["id"] == task_id:
            task["status"] = new_status
            found = True
            break

    if found:
        with open(MANIFEST_FILE, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Successfully updated {task_id} to {new_status}")
    else:
        print(f"Error: Task {task_id} not found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update project task status.")
    parser.add_argument("--id", required=True, help="The ID of the task to update")
    parser.add_argument("--status", required=True, choices=["todo", "in_progress", "done"], help="New status")

    args = parser.parse_args()
    update_task_status(args.id, args.status)
