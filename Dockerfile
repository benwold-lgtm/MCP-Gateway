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
# /secrets is unused unless a deployment mounts a volume there (e.g. the lite compose's
# MCP_API_KEY_FILE). Pre-creating + chowning it here matters even though it's empty: when
# Docker mounts a brand-new named volume over a path, it seeds the volume by copying
# whatever the image has at that path (including ownership) — an image path that doesn't
# exist at all gets an empty root-owned directory instead, which appuser can't write to.
RUN adduser --disabled-password --gecos "" --uid 1000 appuser \
    && mkdir -p /app/data /app/logs /secrets \
    && chown -R appuser:appuser /app /secrets
USER appuser
EXPOSE 8000
ENV MCP_CONFIG=/app/config.yaml
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" \
    || exit 1
CMD ["device-mcp"]
