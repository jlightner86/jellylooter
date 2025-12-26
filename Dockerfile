FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (including FFmpeg with full codec support for transcoding)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libx265-dev \
    libx264-dev \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY looter_app.py .

# Copy templates (required)
COPY templates/ templates/

# Create directories
RUN mkdir -p /config /storage static

EXPOSE 5000

# Set timezone (can be overridden with -e TZ=America/New_York)
ENV TZ=UTC
ENV PYTHONUNBUFFERED=1

# Use gevent for async if available, fallback to default
CMD ["python", "looter_app.py"]
