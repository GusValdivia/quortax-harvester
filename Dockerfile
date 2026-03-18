FROM python:3.12-slim

WORKDIR /app

# Deps 100% PyPI — sem instalação via GitHub
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV PORT=8000
EXPOSE $PORT

CMD ["python", "main.py"]
