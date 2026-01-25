FROM python:3.11-alpine

# Set working directory
WORKDIR /opt/opencti-connector-assemblyline

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN apk add --no-cache \
    git \
    libffi-dev \
    libmagic \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del git

# Copy source code
COPY src/ ./

# Set entrypoint
ENTRYPOINT ["python", "main.py"]
