FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsodium23 libsodium-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /srv

# Install common package first (shared monorepo code)
COPY common /srv/common
RUN pip install --no-cache-dir /srv/common

# Install verifier service
COPY services/verifier/pyproject.toml /srv/pyproject.toml
COPY services/verifier/app /srv/app
RUN pip install --no-cache-dir -U pip && pip install --no-cache-dir .

# Static assets
COPY services/verifier/web /srv/web

ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host=0.0.0.0", "--port=8000"]
