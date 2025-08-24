# 1) ベース
FROM python:3.11-slim

# 2) 環境
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# 3) 作業ディレクトリ
WORKDIR /app

# 4) 依存
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# 5) アプリ本体コピー（←ここを app.py に）
COPY app.py /app/app.py

# 6) 起動
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
