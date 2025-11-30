FROM python:3.9-slim

# Install dependencies
RUN pip install flask requests schedule

# Setup working directory
WORKDIR /app

# Define volumes
VOLUME /config
VOLUME /storage

# Copy the application AND the templates
COPY looter_app.py .
COPY templates ./templates

# Run the application
CMD ["python", "-u", "looter_app.py"]
