FROM python:3.11-alpine

LABEL maintainer="github.com/wolffcatskyy"
LABEL description="CrowdSec bouncer for UniFi firewall"
LABEL version="1.3.0"

WORKDIR /app

# Install wget for healthcheck
RUN apk add --no-cache wget

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bouncer script
COPY bouncer.py .

# Expose health check port
EXPOSE 8080

# Run as non-root
RUN adduser -D -u 1000 bouncer
USER bouncer

CMD ["python", "-u", "bouncer.py"]
