# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies
RUN pip install --no-cache-dir -e .

# Copy sources after dependencies installation
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

# ----- Create a non-privileged use ------- #
# Use system group/user
# Create group and user without home, no-login
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Ensure entrypoint is executable so non-root can run it
RUN chmod +x /app/entrypoint.sh

# Set basic ownership
RUN chown -R appuser:appuser /app

# Create storage dirs with permissions at build time
RUN mkdir -p /app/storage/files /app/storage/rmap_watermarks \
 && chown -R appuser:appuser /app/storage \
 && chmod 755 /app/storage \
 && chmod 775 /app/storage/files /app/storage/rmap_watermarks

RUN mkdir -p /app/logs \
 && chown -R appuser:appuser /app/logs \
 && chmod 755 /app/logs
 
RUN mkdir -p /tmp/prometheus \
 && chown appuser:appuser /tmp/prometheus \
 && chmod 755 /tmp/prometheus

# Basic secure permissions
RUN find /app/src -type f -exec chmod 644 {} \; \
 && find /app/src -type d -exec chmod 755 {} \; \
 && chmod 644 /app/pyproject.toml \
 && chmod 600 /app/flag

# Switch to non-root user for runtime 
USER appuser

EXPOSE 5000

# Default command runs the web server
CMD ["./entrypoint.sh"]

