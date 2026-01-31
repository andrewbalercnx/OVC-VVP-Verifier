FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 libsodium-dev \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

# Install keripy (vendored)
COPY keripy /srv/keripy
RUN pip install --no-cache-dir /srv/keripy

# Install common package
COPY common /srv/common
RUN pip install --no-cache-dir /srv/common

# Install issuer service
COPY services/issuer/pyproject.toml /srv/pyproject.toml
COPY services/issuer/app /srv/app
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

# Copy config (will be overridden by volume mount in docker-compose)
COPY services/issuer/config /srv/config

# Data volume for persistence
VOLUME /data/vvp-issuer

# Environment
ENV PYTHONUNBUFFERED=1
ENV VVP_WITNESS_CONFIG=/srv/config/witnesses.json

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8001/healthz || exit 1

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8001"]
