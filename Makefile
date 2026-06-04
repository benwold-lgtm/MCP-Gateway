.PHONY: install test lint format typecheck build run worker clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-fast:
	pytest tests/ -x -q

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
