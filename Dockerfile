FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Create unprivileged user for security
RUN groupadd -r recon && useradd -r -g recon -d /app -s /bin/bash recon

# Copy dependency specifications first for caching
COPY pyproject.toml requirements.txt ./

# Install python dependencies
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir setuptools wheel

# Copy source tree
COPY . .

# Install package in editable or standard mode
RUN pip install --no-cache-dir .

# Set permissions for non-root execution
RUN mkdir -p /app/output && chown -R recon:recon /app

USER recon

# Set entrypoint
ENTRYPOINT ["venom"]
CMD ["--help"]
