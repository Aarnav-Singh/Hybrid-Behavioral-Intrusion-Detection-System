FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies directly (no external requirements.txt needed)
RUN pip install --no-cache-dir \
    elasticsearch==8.11.0 \
    pandas==2.1.3 \
    numpy==1.26.2 \
    scikit-learn==1.3.2 \
    scipy==1.11.4 \
    prometheus-client==0.19.0 \
    mlflow==2.9.2 \
    requests==2.31.0 \
    rich==13.7.0 \
    joblib==1.3.2

# Copy detection engine source
COPY . .

# Create data/model directories
RUN mkdir -p /app/data /app/models /app/logs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/metrics || exit 1

EXPOSE 8000

CMD ["python", "main.py"]
