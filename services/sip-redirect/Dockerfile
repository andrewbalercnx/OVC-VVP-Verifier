# VVP SIP Redirect Service
# Sprint 42: SIP redirect signing service for VVP attestation

FROM python:3.12-slim

# Labels
LABEL org.opencontainers.image.title="VVP SIP Redirect"
LABEL org.opencontainers.image.description="SIP redirect signing service for VVP attestation"
LABEL org.opencontainers.image.version="0.1.0"

# Create non-root user
RUN useradd -m -u 1000 vvp

# Set working directory
WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy application
COPY app/ app/

# Create directories for logs and certs
RUN mkdir -p /var/log/vvp-sip && chown vvp:vvp /var/log/vvp-sip

# Switch to non-root user
USER vvp

# Expose SIP ports
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp

# Health check (simple process check since SIP doesn't have HTTP)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -f "python.*main" || exit 1

# Run the service
CMD ["python", "-m", "app.main"]
