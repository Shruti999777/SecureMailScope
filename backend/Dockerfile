# SecureMailScope Backend Dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system utilities (tcpdump / libpcap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Initialize CA hierarchy & models if not present
RUN python scripts/generate_ca_hierarchy.py && python scripts/generate_synthetic_pcaps.py && python scripts/train_ml_models.py

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
