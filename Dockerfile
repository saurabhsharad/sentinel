# Sentinel — runtime security layer for AI agents
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# MOSS_PROJECT_ID / MOSS_PROJECT_KEY are provided as runtime env vars by the host.
# The app warms the two Moss indexes on startup (first boot ~10-60s).
ENV PORT=8011
CMD ["sh", "-c", "uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8011}"]
