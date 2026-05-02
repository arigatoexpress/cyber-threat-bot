# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080

WORKDIR /app

# Install system deps first for layer caching. Slim image already has libffi
# and openssl that requests / urllib3 need. No need to add build-essential
# unless we add C-extension deps.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy only the package metadata first so dep installation is cached unless
# pyproject.toml changes.
COPY pyproject.toml README.md /app/
COPY src /app/src

RUN pip install --upgrade pip wheel \
 && pip install -e .

# Copy the rest (entrypoint, profiles, scripts) AFTER the install so source
# tweaks don't bust the install layer.
COPY app.py /app/
COPY profiles /app/profiles

# Cloud Run sends SIGTERM and expects a quick shutdown. The stdlib
# ThreadingHTTPServer responds to KeyboardInterrupt; uvicorn-style hard exits
# are not necessary for this surface.
EXPOSE 8080

# Drop privileges. Cloud Run already isolates containers, but keeping this
# in line with security review expectations.
RUN useradd --system --create-home --uid 10001 ctb
USER ctb

CMD ["python", "/app/app.py"]
