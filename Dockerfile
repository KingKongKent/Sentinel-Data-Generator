# Sentinel Data Generator - Container Image
# Generates realistic demo/test data for Microsoft Sentinel.
#
# Supported log types:
#   - SecurityEvent (Windows security events)
#   - CommonSecurityLog (CEF format: firewall, IDS, threat intel)
#
# Build:
#   docker build -t sentinel-datagen .
#
# Run (send to Sentinel):
#   docker run --rm \
#     -e AZURE_CLIENT_ID=<sp-client-id> \
#     -e AZURE_CLIENT_SECRET=<sp-secret> \
#     -e AZURE_TENANT_ID=<tenant-id> \
#     -e SENTINEL_DCE_ENDPOINT=<dce-endpoint> \
#     -e SENTINEL_DCR_ID=<dcr-id> \
#     sentinel-datagen --output log_analytics --count 100
#
# Run (stdout preview):
#   docker run --rm sentinel-datagen --output stdout --count 10

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
