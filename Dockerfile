FROM python:3.11-alpine@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4

ARG APP_UID=10001
ARG APP_GID=10001

RUN addgroup -g "${APP_GID}" -S profilesync \
    && adduser -u "${APP_UID}" -S -D -H -G profilesync profilesync

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER profilesync:profilesync
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=3))['status'] == 'ok'"]

ENTRYPOINT ["python", "-m", "profile_sync_server.http"]
CMD ["--listen", "0.0.0.0", "--allow-non-loopback", "--port", "8765", "--database", "/data/state.sqlite", "--key-registry", "/run/profile-sync/key-registry.json"]

