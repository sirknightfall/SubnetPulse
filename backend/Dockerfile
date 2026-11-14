FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install iputils-ping and libcap2-bin so non-root or container processes with NET_RAW can execute ICMP pings
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        libcap2-bin \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Ensure persistent SQLite volume mount directory exists
RUN mkdir -p /app/data

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
