FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt pyproject.toml ./
COPY device_mcp_gateway/ ./device_mcp_gateway/
# Install pinned runtime deps from the lockfile, then the package itself
# without re-resolving — reproducible, fully-pinned image builds.
RUN pip install --no-cache-dir --prefix=/deps -r requirements.txt \
    && pip install --no-cache-dir --prefix=/deps --no-deps .

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" \
    || exit 1
CMD ["device-mcp"]
