.PHONY: install test test-integration test-fast lint format typecheck security build run worker clean

install:
	pip install -e ".[dev]"

# Fast unit suite (fakeredis); no external services required.
test:
	pytest tests/ -v -m "not integration"

# Real-Redis integration tests. Needs Redis at MCP_TEST_REDIS_URL
# (default redis://localhost:6379/15); tests skip if it's unreachable.
test-integration:
	pytest tests/ -v -m integration

test-fast:
	pytest tests/ -x -q -m "not integration"

lint:
	flake8 device_mcp_gateway/ tests/ --max-line-length=120

typecheck:
	mypy device_mcp_gateway/ --ignore-missing-imports

# Static security scan — same invocation as the CI security job. Flags Medium+
# severity issues (B104 bind-all, etc.); annotate true false-positives with # nosec.
security:
	bandit -r device_mcp_gateway -ll

format:
	black device_mcp_gateway/ tests/
	isort device_mcp_gateway/ tests/

# Local mirror of the CI gates — run before every push.
check: lint typecheck security test

build:
	docker build -t device-mcp-gateway:local .

run:
	device-mcp --config config.yaml

worker:
	device-mcp-worker --config config.yaml

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .mypy_cache .pytest_cache htmlcov coverage.xml

k8s-apply:
	kubectl apply -k deploy/kubernetes/

k8s-delete:
	kubectl delete -k deploy/kubernetes/
