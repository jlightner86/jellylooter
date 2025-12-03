FROM python:3.11-slim

LABEL maintainer="jlightner86"
LABEL org.opencontainers.image.source="https://github.com/jlightner86/jellylooter"
LABEL org.opencontainers.image.description="Download media from remote Jellyfin/Emby servers"
LABEL org.opencontainers.image.licenses="MIT"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TZ=America/New_York

# Create app directory
WORKDIR /app

# Install dependencies
RUN pip install --no-cache-install flask requests schedule

# Copy application files
COPY looter_app.py /app/
COPY templates/ /app/templates/

# Create directories for config and storage
RUN mkdir -p /config /storage

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Run the application
CMD ["python", "looter_app.py"]
