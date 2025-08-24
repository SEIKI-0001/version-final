FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sample_hello.py .

CMD ["sh","-c","uvicorn sample_hello:app --host 0.0.0.0 --port ${PORT:-8080} --log-level info"]
