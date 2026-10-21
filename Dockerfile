FROM python:3.12.11-slim

RUN pip install --no-cache-dir "PyJWT[crypto]==2.10.1" \
 && useradd --system --uid 10001 --no-create-home wol

WORKDIR /app
COPY app.py index.html ./

USER wol
ENV WOL_CONFIG=/app/config.toml PYTHONUNBUFFERED=1
HEALTHCHECK --interval=60s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz', timeout=2)"
CMD ["python", "app.py"]
