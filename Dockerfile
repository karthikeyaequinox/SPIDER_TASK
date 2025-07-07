# Advanced Reconnaissance Suite Dockerfile
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    nmap \
    nikto \
    whois \
    dnsutils \
    wget \
    curl \
    git \
    chromium-browser \
    chromium-chromedriver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p reports reports/vuln

# Set permissions
RUN chmod +x *.py

# Expose Flask port
EXPOSE 5000

# Create a non-root user for security
RUN useradd -m -u 1000 reconuser && chown -R reconuser:reconuser /app
USER reconuser

# Default command
CMD ["python3", "app.py"]
