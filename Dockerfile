# VaultScope backend: FastAPI + the Stage 2 parser + Stage 5 report rendering.
FROM python:3.11-slim

# tshark backs pyshark (Stage 1); pango and cairo back weasyprint (Stage 5).
# DEBIAN_FRONTEND keeps tshark's "should non-root capture?" prompt from hanging
# the build -- the answer is no, this container only reads uploaded files.
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        tshark \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY api ./api
COPY reporting ./reporting
COPY data/mock ./data/mock
# The trained Stage 4b/4a artifacts. Without these the container falls back to
# an untrained classifier: every session reports traffic type "Other" at zero
# confidence and the technical report loses its confusion matrix.
COPY models ./models

# The database and rendered reports live on a volume, not in the image.
ENV VAULTSCOPE_DB=/var/lib/vaultscope/vaultscope.sqlite \
    VAULTSCOPE_REPORT_DIR=/var/lib/vaultscope/reports
RUN mkdir -p /var/lib/vaultscope/reports

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
