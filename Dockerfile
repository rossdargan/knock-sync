FROM python:3.13-alpine

LABEL org.opencontainers.image.title="knock-sync" \
      org.opencontainers.image.description="Sync a Cloudflare Worker knock allowlist + static IPs into UniFi traffic matching lists"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEALTH_FILE=/tmp/knock-sync.health \
    STATIC_FILE=/config/static.txt

RUN adduser -D -H -u 10001 knock && mkdir -p /config
WORKDIR /app
COPY knock_sync.py /app/knock_sync.py

USER knock

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD ["python3", "/app/knock_sync.py", "--healthcheck"]

ENTRYPOINT ["python3", "/app/knock_sync.py"]
