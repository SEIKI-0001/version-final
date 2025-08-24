# 1) ベース
FROM python:3.11-slim

# 2) 環境
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# 3) 作業ディレクトリ
WORKDIR /app

# 4) 依存を先にコピー→インストール
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# 5) アプリ本体コピー
COPY sample_hello.py /app/sample_hello.py

# 6) 起動（必ず 0.0.0.0:8080 で待ち受け）
CMD ["uvicorn", "sample_hello:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
