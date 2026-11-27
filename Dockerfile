FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including:
# - FFmpeg with full codec support for transcoding
# - Intel VAAPI/QuickSync drivers for hardware transcoding (requires /dev/dri passthrough)
# - Mesa VA drivers for AMD/Intel integrated graphics
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libx265-dev \
    libx264-dev \
    tzdata \
    # VAAPI/QuickSync support
    vainfo \
    libva2 \
    libva-drm2 \
    libva-x11-2 \
    intel-media-va-driver \
    mesa-va-drivers \
    # Built-in WireGuard VPN + kill switch (Pro; container needs --cap-add=NET_ADMIN)
    wireguard-tools \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY looter_app.py .

# Copy templates (required)
COPY templates/ templates/

# Copy static files (favicon, etc.)
COPY static/ static/

# Create directories
RUN mkdir -p /config /storage

EXPOSE 5000

# Set timezone (can be overridden with -e TZ=America/New_York)
ENV TZ=UTC
ENV PYTHONUNBUFFERED=1

# Use gevent for async if available, fallback to default
CMD ["python", "looter_app.py"]
