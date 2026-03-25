# PhishGuard Backend — Multi-stage Docker build
# Works for both local Docker and Hugging Face Spaces

FROM python:3.11 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11
WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Port is configured via ENV — defaults to 7860 (HF Spaces compatible)
# Override with -e PORT=8000 for local Docker
ENV PORT=7860
EXPOSE ${PORT}

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import httpx; r=httpx.get('http://localhost:${PORT}/health'); assert r.status_code==200" || exit 1

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
