FROM python:3.12.11-slim

# Must match the host uid that owns secrets/id_shutdown: ssh refuses a key
# that is not owned by the current user or is readable by others.
ARG UID=1000

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "PyJWT[crypto]==2.10.1" \
 && useradd --system --uid "$UID" --no-create-home wol \
 && mkdir -p /app/data && chown wol /app/data

WORKDIR /app
COPY app.py index.html logs.html ./

USER wol
ENV WOL_CONFIG=/app/config.toml WOL_DATA_DIR=/app/data WOL_SECRETS_DIR=/app/secrets PYTHONUNBUFFERED=1
HEALTHCHECK --interval=60s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=2)"
CMD ["python", "app.py"]
