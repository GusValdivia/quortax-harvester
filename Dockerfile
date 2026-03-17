FROM python:3.11-slim

# System deps for theHarvester
RUN apt-get update && apt-get install -y \
    git \
    dnsutils \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install theHarvester from GitHub (PyPI package is just a placeholder)
RUN pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@master

# Install FastAPI + uvicorn
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn[standard]==0.30.6 pydantic==2.9.2

# Copy app
COPY main.py .

# Railway injects PORT env var
ENV PORT=8000

EXPOSE $PORT

CMD ["python", "main.py"]
