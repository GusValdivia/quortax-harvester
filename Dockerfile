FROM python:3.12-slim

# Cache bust: 2026-03-18
ARG CACHEBUST=2

# System deps
RUN apt-get update && apt-get install -y \
    git \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install theHarvester from GitHub (PyPI package is a placeholder)
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@master

# Install FastAPI + uvicorn (theHarvester já instala versões próprias, só garantir pydantic)
RUN pip install --no-cache-dir pydantic==2.9.2

# Copy app
COPY main.py .

ENV PORT=8000
EXPOSE $PORT

CMD ["python", "main.py"]
