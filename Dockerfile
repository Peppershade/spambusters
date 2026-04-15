# Spambuster Dockerfile
FROM python:3.14-slim-bookworm

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Upgrade pip and install Python dependencies
# Install CPU-only PyTorch (much smaller) + other deps
RUN pip install --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for data persistence
RUN mkdir -p /app/data

# Set default environment variables
ENV DATABASE_PATH=/app/data/spambuster.db
ENV MODEL_PATH=/app/data/spam_model.pt
ENV VECTORIZER_PATH=/app/data/vectorizer.pkl
ENV OPERATION_MODE=learning
ENV SPAM_THRESHOLD=0.7
ENV SCAN_INTERVAL=300
ENV MAX_EMAILS_PER_SCAN=50

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run with gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "app:app"]
