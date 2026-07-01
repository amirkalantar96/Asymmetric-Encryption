FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir cryptography

COPY app/ ./app/
COPY keys/ ./keys/

CMD ["python", "app/license_generator.py"]
