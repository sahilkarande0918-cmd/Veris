# Veris verdict engine — cloud image (Railway/any container host).
#
# Built from the repo ROOT because the engine resolves packages/shared and
# fixtures/ relative to the repo root (parents[3] in app/__init__.py and
# checks.py). Keeping that layout in the image means no path surgery.
FROM python:3.11-slim

WORKDIR /app

# System libs opencv-python-headless links against. cv2 is imported lazily
# (only the QR image-file path uses it; the app sends decoded text), so the
# server starts even without these -- but include them so /check/qr file
# decoding works too.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 libgl1 \
    && rm -rf /var/lib/apt/lists/*

COPY services/verdict-engine/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY packages/ ./packages/
COPY fixtures/ ./fixtures/
COPY services/verdict-engine/ ./services/verdict-engine/

WORKDIR /app/services/verdict-engine

# Railway injects $PORT. Bind all interfaces so the platform can route to it.
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8010}
