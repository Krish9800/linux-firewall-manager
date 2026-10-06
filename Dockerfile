# Stage 1: Build virtual environment and package
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir .

# Stage 2: Minimal rootless runtime
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Linux Firewall Manager" \
      org.opencontainers.image.description="Declarative, lock-safe firewall management daemon for nftables and iptables" \
      org.opencontainers.image.authors="Security Operations Team" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Create non-privileged system user and group
RUN groupadd -g 10001 netsec && \
    useradd -u 10001 -g netsec -s /bin/sh -M netsec && \
    apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
COPY src/ ./src/

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    FW_BACKEND=simulation \
    FW_PORT=8000 \
    FW_HOST=0.0.0.0

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["uvicorn", "fwmanager.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
