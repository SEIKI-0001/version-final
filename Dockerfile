FROM python:3.9-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app
COPY sample_hello.py .
CMD ["python", "sample_hello.py"]
