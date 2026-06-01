import json
import os
import subprocess
import time

BASE_DIR = os.path.dirname(__file__)
MANIFEST_PATH = os.path.join(BASE_DIR, 'project_manifest.json')
SCRATCHPAD_PATH = os.path.join(BASE_DIR, 'scratchpad.json')
WATCHDOG_SCRATCHPAD = SCRATCHPAD_PATH

def load_manifest():
    with open(MANIFEST_PATH, 'r') as f:
        return json.load(f)

def load_scratchpad():
    with open(WATCHDOG_SCRATCHPAD, 'r') as f:
        return json.load(f)

def save_scratchpad(data):
    with open(WATCHDOG_SCRATCHPAD, 'w') as f:
        json.dump(data, f, indent=2)

def run_agent_on_task(task):
    print(f"[*] Triggering autonomous agent for task: {task['id']}")
    # In a real implementation, this would call hermes_agent or delegate_task
    # For this PoC, we simulate the orchestration through a system call
    # or a placeholder command.
    return True

def main_loop():
    print("[*] Autonomy Watchdog started. Monitoring manifest...")
    while True:
        try:
            manifest = load_manifest()
            scratchpad = load_scratchpad()
            
            changed = False
            for task in manifest['tasks']:
                # Logic: If task is 'todo' and no current task is 'in_progress', start it
                if task['status'] == 'todo':
                    # Check if we are already working on something
                    if scratchpad['current_task_id'] is None:
                        print(f"[!] Found pending task: {task['id']}. Starting execution.")
                        scratchpad['current_task_id'] = task['id']
                        scratchpad['sub_goal_breakdown'] = [f"Execute {task['description']}"]
                        save_scratchpad(scratchpad)
                        
                        # Triggering the agent
                        success = run_agent_on_task(task)
                        
                        if success:
                            # Simulate transition to in_progress
                            # In real life, the agent does this. We just trigger the start.
                            pass 
                        
                        changed = True

            if changed:
                save_scratchpad(scratchpad)
            
            time.sleep(10) # Poll every 10 seconds
        except Exception as e:
            print(f"[!] Error in Watchdog loop: {e}")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
