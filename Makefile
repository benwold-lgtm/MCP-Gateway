.PHONY: install test test-integration test-fast lint format typecheck build run worker clean

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
	flake8 device_mcp_gateway/ tests/

typecheck:
	mypy device_mcp_gateway/

format:
	black device_mcp_gateway/ tests/
	isort device_mcp_gateway/ tests/

check: lint typecheck test

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
