# Docker Hardening Hub v0.8
# build pe doua stadii: Node pentru frontend, apoi Python ca runtime
# scannere: Hadolint (linting static) + Trivy (configurari + CVE pe imaginea
# de baza) + OSV/NVD (CVE pe pachete) + analizoarele CIS + Dive (eficienta
# straturilor, prin pipeline-ul separat de analiza a imaginii)
# backend fara stare: fara baza de date, fara volum persistent; istoricul
# scanarilor sta in browser (localStorage)
# fara Podman, fara sandbox, fara --privileged, fara flaguri speciale
# pornire: podman run -d -p 8080:8080 licenta:latest

# stadiul 1: construiesc frontendul React
FROM docker.io/library/node:22-alpine AS frontend

WORKDIR /build
COPY frontend/package*.json ./
RUN npm install --ignore-scripts
COPY frontend/ .
RUN npm run build

# stadiul 2: runtime
FROM docker.io/library/python:3.12-slim-bookworm

LABEL maintainer="security-tools@example.com"
LABEL description="Docker Hardening Hub — Dockerfile + image security scanner"

ENV DEBIAN_FRONTEND=noninteractive

# dependinte de sistem: nginx, supervisor, curl, skopeo (aduce imaginea din
# registru ca arhiva, fara demon); un singur strat, cu curatare agresiva
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nginx \
        supervisor \
        curl \
        ca-certificates \
        skopeo && \
    rm -rf /var/lib/apt/lists/*

# Hadolint
ARG HADOLINT_VERSION=2.12.0
RUN curl -fsSL \
        "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
        -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Trivy
ARG TRIVY_VERSION=0.70.0
RUN curl -fsSL \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
        -o /tmp/trivy.deb && \
    dpkg -i /tmp/trivy.deb && \
    rm /tmp/trivy.deb

# Dive, analizorul de eficienta a straturilor pentru pipeline-ul de imagine
# citeste direct arhive docker-archive, fara demon
ARG DIVE_VERSION=0.13.1
RUN curl -fsSL \
        "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/dive.tar.gz && \
    tar -xzf /tmp/dive.tar.gz -C /usr/local/bin dive && \
    chmod +x /usr/local/bin/dive && \
    rm /tmp/dive.tar.gz

# dependinte Python
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# utilizator non-root; arhivele de imagine sunt scrise in /tmp de catre ruta
# (temporar, curatate de procesul de lucru dupa fiecare job); nu am nevoie de
# volum persistent, istoricul sta in localStorage-ul browserului
RUN useradd -u 1000 -m -s /bin/sh appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

# codul aplicatiei
COPY --chown=appuser:appuser backend/ /app/
COPY --from=frontend --chown=appuser:appuser /build/dist/ /app/static/
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 8080

USER appuser

CMD ["supervisord", "-c", "/etc/supervisord.conf"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8080/api/health || exit 1