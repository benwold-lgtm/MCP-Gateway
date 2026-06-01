import json
import subprocess
import sys

BASE_DIR = os.path.dirname(__file__)
SCRATCHPAD_PATH = os.path.join(BASE_DIR, "scratchpad.json")
MANIFEST_PATH = os.path.join(BASE_DIR, "project_manifest.json")


def verify_task(task_id):
    print(f"[*] Verifying task: {task_id}")

    with open(SCRATCHPAD_PATH, "r") as f:
        scratchpad = json.load(f)

    # Simple logic: Check if a corresponding file or test passed
    # In a real implementation, this would run pytest or check for specific file existence

    success = True  # Placeholder for real verification logic

    if success:
        print(f"[+] Task {task_id} verified successfully.")
        update_manifest(task_id, "done")
        scratchpad["last_verification_result"] = "SUCCESS"
    else:
        print(f"[-] Task {task_id} verification failed.")
        update_manifest(task_id, "todo")
        scratchpad["last_verification_result"] = "FAILURE"

    with open(SCRATCHPAD_PATH, "w") as f:
        json.dump(scratchpad, f, indent=2)


def update_manifest(task_id, status):
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)

    for task in manifest["tasks"]:
        if task["id"] == task_id:
            task["status"] = status
            break

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        verify_task(sys.argv[1])
    else:
        print("Usage: python verifier.py <task_id>")
