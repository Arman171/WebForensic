FROM python:3.10-slim

LABEL maintainer="WebForensicAnalyzer Team"
LABEL version="1.0.0"
LABEL description="Advanced Web Reconnaissance Tool"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make the script executable
RUN chmod +x WebForensicAnalyzer.py

# Create non-root user for security
RUN useradd -m wfauser
RUN chown -R wfauser:wfauser /app
USER wfauser

# Set entrypoint
ENTRYPOINT ["python", "WebForensicAnalyzer.py"]

# Default command (can be overridden)
CMD ["--help"]