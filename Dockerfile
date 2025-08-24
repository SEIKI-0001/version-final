# Dockerfile
FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
# sample_hello.py はルートに置く想定
COPY sample_hello.py .

# Cloud Run が注入する $PORT を使って起動
CMD ["python", "sample_hello.py"]
