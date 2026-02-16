# Sentinel Data Generator - Container Image
# Build: docker build -t sentinel-datagen .
# Run:   docker run --rm -e SENTINEL_DCE_ENDPOINT=... -e SENTINEL_DCR_ID=... sentinel-datagen

FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Install dependencies first (for better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY sentinel_data_generator/ ./sentinel_data_generator/
COPY config/config.example.yaml ./config/config.yaml

# Switch to non-root user
USER appuser

# Default command: run with log_analytics output
ENTRYPOINT ["python", "-m", "sentinel_data_generator"]
CMD ["--output", "log_analytics", "--log-level", "INFO"]
