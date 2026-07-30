# ─────────────────────────────────────────────────────────────
#  SecuraX Backend — Hugging Face Spaces (Docker SDK)
#  Free tier, no credit card, no outbound network whitelist.
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm

# Layer 1: system tools + Arabic fonts for PDF reports
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap perl libnet-ssleay-perl libio-socket-ssl-perl \
        fonts-freefont-ttf \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: nikto from Debian repos (non-fatal — nmap still works if nikto unavailable)
RUN apt-get update -qq && apt-get install -y --no-install-recommends nikto \
    && rm -rf /var/lib/apt/lists/* \
    || echo "WARNING: nikto not available in apt — DAST scanning will be limited"

# Spaces run containers as a non-root user (uid 1000) — match that here
# so the app can write securax.db and other runtime files.
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY --chown=user . .

ENV PORT=7860
EXPOSE 7860

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
