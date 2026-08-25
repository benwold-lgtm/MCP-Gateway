FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt pyproject.toml README.md ./
COPY device_mcp_catalog/ ./device_mcp_catalog/
# Install pinned runtime deps from the lockfile, then the package itself
# without re-resolving — reproducible, fully-pinned image builds.
RUN pip install --no-cache-dir --prefix=/deps -r requirements.txt \
    && pip install --no-cache-dir --prefix=/deps --no-deps .

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /deps /usr/local
COPY device_mcp_catalog/ ./device_mcp_catalog/
RUN adduser --disabled-password --gecos "" --uid 1000 appuser
USER appuser
EXPOSE 8100
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:8100/healthz', timeout=3)" \
    || exit 1
CMD ["device-mcp-catalog"]
