FROM python:3.11-alpine

LABEL maintainer="github.com/wolffcatskyy"
LABEL description="CrowdSec bouncer for UniFi firewall"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy bouncer script
COPY bouncer.py .

# Run as non-root
RUN adduser -D -u 1000 bouncer
USER bouncer

CMD ["python", "-u", "bouncer.py"]
