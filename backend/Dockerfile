# PhishGuard Backend — Multi-stage Docker build

FROM python:3.11-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libgl1-mesa-glx libglib2.0-0 libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /install /usr/local
COPY . .
RUN groupadd -r phishguard && useradd -r -g phishguard phishguard
USER phishguard
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --retries=3 CMD python -c "import httpx; r=httpx.get('http://localhost:8000/health'); assert r.status_code==200" || exit 1
CMD ["python", "-m", "app.main"]
