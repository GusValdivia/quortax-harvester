FROM python:3.11-slim

# System deps for theHarvester
RUN apt-get update && apt-get install -y \
    git \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY main.py .

# Railway injects PORT env var
ENV PORT=8000

EXPOSE $PORT

CMD ["python", "main.py"]
