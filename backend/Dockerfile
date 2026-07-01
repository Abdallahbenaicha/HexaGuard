# ─────────────────────────────────────────────────────────────
#  HexaGuard Backend — Hugging Face Spaces (Docker SDK)
#  Free tier, no credit card, no outbound network whitelist.
# ─────────────────────────────────────────────────────────────
FROM python:3.11-slim

# nmap: network scanner | nikto: web server DAST checks
RUN apt-get update && apt-get install -y --no-install-recommends nmap nikto \
    && rm -rf /var/lib/apt/lists/*

# Spaces run containers as a non-root user (uid 1000) — match that here
# so the app can write hexaguard.db and other runtime files.
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
