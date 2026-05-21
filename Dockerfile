FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY import_cowrie.py .
COPY import_suricata.py .
COPY import_cve.py .
COPY import_all_data.py .

# Create logs directory
RUN mkdir -p /app/logs

CMD ["python", "import_all_data.py"]
