FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt pyproject.toml ./
COPY device_mcp_gateway/ ./device_mcp_gateway/
RUN pip install --no-cache-dir --prefix=/deps .

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /deps /usr/local
COPY device_mcp_gateway/ ./device_mcp_gateway/
COPY config.yaml ./
RUN adduser --disabled-password --gecos "" --uid 1000 appuser \
    && mkdir -p /app/data /app/logs \
    && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
ENV MCP_CONFIG=/app/config.yaml
CMD ["uvicorn", "device_mcp_gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
