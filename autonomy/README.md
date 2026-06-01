# Autonomy Engine Documentation

The Autonomy Engine is a specialized control loop designed for the MCP Gateway project to enable self-directed development.

## Components

### 1. Scratchpad (`autonomy/scratchpad.json`)
The Short-Term Memory of the agent. It tracks the current active task, sub-goal breakdown, and the results of the most recent verification step.

### 2. Watchdog (`autonomy/watchdog.py`)
The Scheduler. It monitors the `project_manifest` and detects new tasks. When a task is identified, it triggers the agent execution.

### 3. Verifier (`autonomy/verifier.py`)
The Auditor. It is a standalone script that executes tests (unit tests, integration tests, or linting) to verify that the works performed by the Agent meet the required quality standards. It then updates the task status.

## Workflow
1. **Detection**: The Watchdog scans the manifest for tasks in the `todo` state.
2. **Trigger**: Once a task is found, a command is issued to the Agent.
3. **Verification**: The Agent performs the task, then calls the Verifier.
4. **Completion**: The Verifier updates the task status to `done`.
