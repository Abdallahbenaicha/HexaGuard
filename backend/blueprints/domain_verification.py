"""SecurAx — domain ownership verification blueprint.

Verification is OPTIONAL — it never blocks scans.
It adds a trust badge so clients know their domain is legitimately registered.

Methods:
  - DNS TXT:  add  `securax-verify=<token>`  as a TXT record on  `_securax.<domain>`
  - Meta tag: add  `<meta name="securax-verification" content="<token>">`  to the site root
  - Admin:    admin can approve any domain instantly via  PATCH /api/admin/users/<uid>/verify-domain
"""

import logging
from html.parser import HTMLParser

import requests as _requests
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from database import (
    admin_verify_domain,
    get_domain_verification,
    mark_domain_verified,
    request_domain_verification,
)
from utils import admin_required

logger = logging.getLogger(__name__)

domain_bp = Blueprint("domain", __name__)

_DNS_TIMEOUT  = 8   # seconds for Cloudflare DoH query
_HTTP_TIMEOUT = 10  # seconds for meta-tag page fetch
_MAX_HTML     = 30_000  # bytes — only scan the first 30 KB for the meta tag


# ── helpers ───────────────────────────────────────────────────────────────────

def _check_dns_txt(domain: str, token: str) -> bool:
    """Query Cloudflare DNS-over-HTTPS for  _securax.<domain>  TXT records."""
    expected = f"securax-verify={token}"
    try:
        resp = _requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": f"_securax.{domain}", "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=_DNS_TIMEOUT,
        )
        data = resp.json()
        for answer in data.get("Answer", []):
            txt = (answer.get("data") or "").strip('"').strip()
            if txt == expected:
                return True
    except Exception as exc:
        logger.debug("DNS TXT check failed: %s", exc)
    return False


class _MetaParser(HTMLParser):
    def __init__(self, token: str):
        super().__init__()
        self._token = token
        self.found  = False

    def handle_starttag(self, tag, attrs):
        if self.found or tag != "meta":
            return
        d = dict(attrs)
        if d.get("name") == "securax-verification" and d.get("content") == self._token:
            self.found = True


def _check_meta_tag(domain: str, token: str) -> bool:
    """Fetch the site root page and look for the securax-verification meta tag."""
    for scheme in ("https", "http"):
        try:
            resp = _requests.get(
                f"{scheme}://{domain}",
                timeout=_HTTP_TIMEOUT,
                verify=False,
                headers={"User-Agent": "SecurAx-DomainVerifier/1.0"},
                stream=True,
            )
            html = b""
            for chunk in resp.iter_content(chunk_size=4096):
                html += chunk
                if len(html) >= _MAX_HTML:
                    break
            parser = _MetaParser(token)
            parser.feed(html.decode("utf-8", errors="replace"))
            if parser.found:
                return True
        except Exception as exc:
            logger.debug("Meta check failed (%s://%s): %s", scheme, domain, exc)
    return False


# ── user endpoints ────────────────────────────────────────────────────────────

@domain_bp.route("/api/domain/status")
@login_required
def api_domain_status():
    """Return the current user's domain verification status."""
    info = get_domain_verification(current_user.id)
    if not info:
        return jsonify({"verified": False, "domain": None, "token": None})
    return jsonify({
        "verified":     bool(info["verified"]),
        "domain":       info["domain"],
        "verify_token": info["verify_token"],
        "verified_at":  info.get("verified_at"),
        "verified_by":  info.get("verified_by"),
    })


@domain_bp.route("/api/domain/request", methods=["POST"])
@login_required
def api_domain_request():
    """
    Request verification for a domain.

    Body: {"domain": "example.com"}

    Returns the token and instructions.
    Calling this again resets any existing (unverified) request.
    """
    data   = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip().lower()
    domain = domain.removeprefix("http://").removeprefix("https://").split("/")[0]

    if not domain or "." not in domain:
        return jsonify({"error": "Domaine invalide."}), 400

    token = request_domain_verification(current_user.id, domain)
    return jsonify({
        "domain": domain,
        "verify_token": token,
        "methods": {
            "dns": {
                "record_type": "TXT",
                "host":        f"_securax.{domain}",
                "value":       f"securax-verify={token}",
                "instructions": (
                    f"Ajoutez un enregistrement TXT sur '_securax.{domain}' "
                    f"avec la valeur : securax-verify={token}"
                ),
            },
            "meta": {
                "tag": f'<meta name="securax-verification" content="{token}">',
                "instructions": (
                    f"Ajoutez cette balise dans le <head> de votre page d'accueil "
                    f"puis cliquez sur 'Vérifier'."
                ),
            },
        },
    })


@domain_bp.route("/api/domain/verify/dns", methods=["POST"])
@login_required
def api_domain_verify_dns():
    """Trigger a DNS TXT record check for the user's pending verification."""
    info = get_domain_verification(current_user.id)
    if not info:
        return jsonify({"error": "Aucune demande de vérification en cours. Appelez /api/domain/request d'abord."}), 400
    if info["verified"]:
        return jsonify({"verified": True, "domain": info["domain"], "message": "Domaine déjà vérifié."})

    ok = _check_dns_txt(info["domain"], info["verify_token"])
    if ok:
        mark_domain_verified(current_user.id, "dns_txt")
        return jsonify({"verified": True, "domain": info["domain"], "method": "dns_txt"})
    return jsonify({
        "verified": False,
        "domain":   info["domain"],
        "message":  (
            f"Enregistrement TXT introuvable sur _securax.{info['domain']}. "
            "La propagation DNS peut prendre jusqu'à 24h."
        ),
    }), 200


@domain_bp.route("/api/domain/verify/meta", methods=["POST"])
@login_required
def api_domain_verify_meta():
    """Trigger a meta-tag check for the user's pending verification."""
    info = get_domain_verification(current_user.id)
    if not info:
        return jsonify({"error": "Aucune demande de vérification en cours. Appelez /api/domain/request d'abord."}), 400
    if info["verified"]:
        return jsonify({"verified": True, "domain": info["domain"], "message": "Domaine déjà vérifié."})

    ok = _check_meta_tag(info["domain"], info["verify_token"])
    if ok:
        mark_domain_verified(current_user.id, "meta_tag")
        return jsonify({"verified": True, "domain": info["domain"], "method": "meta_tag"})
    return jsonify({
        "verified": False,
        "domain":   info["domain"],
        "message":  (
            f"Balise meta introuvable sur {info['domain']}. "
            "Vérifiez que la balise est dans le <head> et que le cache est vidé."
        ),
    }), 200


# ── admin endpoint ────────────────────────────────────────────────────────────

@domain_bp.route("/api/admin/users/<int:uid>/verify-domain", methods=["POST"])
@admin_required
def api_admin_verify_domain(uid: int):
    """
    Admin bypass: approve a domain for a user without any DNS/meta check.

    Use this for trusted users (university admin, known clients, etc.).

    Body: {"domain": "univ-constantine.dz"}
    """
    data   = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain or "." not in domain:
        return jsonify({"error": "Domaine invalide."}), 400

    admin_verify_domain(uid, domain)
    return jsonify({"ok": True, "uid": uid, "domain": domain, "verified_by": "admin"})
