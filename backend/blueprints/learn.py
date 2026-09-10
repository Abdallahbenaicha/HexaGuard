"""SecuraX — Education & Vulnerability Learning Blueprint.

Single Source of Truth (SSoT) API endpoint serving:
  - Canonical Vulnerability Taxonomy (all 11 scanner engines)
  - Incident & SOC Forensic Taxonomy (Blue Team MITRE ATT&CK)
  - Module 0: Universal Assessment Methodology
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from flask import Blueprint, jsonify, request

try:
    from vuln_taxonomy import VULN_TAXONOMY, INCIDENT_TAXONOMY, SCANNERS, get_vuln_type
except ImportError:
    from backend.vuln_taxonomy import VULN_TAXONOMY, INCIDENT_TAXONOMY, SCANNERS, get_vuln_type

try:
    from assessment_methodology import ASSESSMENT_METHODOLOGY
except ImportError:
    try:
        from backend.assessment_methodology import ASSESSMENT_METHODOLOGY
    except ImportError:
        ASSESSMENT_METHODOLOGY = {}

logger = logging.getLogger(__name__)

learn_bp = Blueprint("learn", __name__, url_prefix="/api/learn")


@learn_bp.route("/taxonomy", methods=["GET"])
def get_taxonomy():
    """Return the entire canonical taxonomy: offensive engines + Blue Team incidents."""
    return jsonify({
        "ok": True,
        "total_vulns": len(VULN_TAXONOMY),
        "total_incidents": len(INCIDENT_TAXONOMY),
        "scanners": SCANNERS,
        "vulns": VULN_TAXONOMY,
        "incidents": INCIDENT_TAXONOMY,
    })


@learn_bp.route("/taxonomy/<vuln_id>", methods=["GET"])
def get_single_topic(vuln_id: str):
    """Return full lesson and taxonomy details for a single vulnerability or incident."""
    if not vuln_id:
        return jsonify({"ok": False, "error": "Missing topic identifier."}), 400

    topic_id = vuln_id.strip().lower()

    # Check offensive taxonomy first
    if topic_id in VULN_TAXONOMY:
        return jsonify({
            "ok": True,
            "topic_type": "offensive",
            "topic": VULN_TAXONOMY[topic_id],
        })

    # Check incident taxonomy
    if topic_id in INCIDENT_TAXONOMY:
        return jsonify({
            "ok": True,
            "topic_type": "incident",
            "topic": INCIDENT_TAXONOMY[topic_id],
        })

    return jsonify({
        "ok": False,
        "error": f"Vulnerability or incident '{vuln_id}' not found in canonical taxonomy."
    }), 404


@learn_bp.route("/methodology", methods=["GET"])
def get_methodology():
    """Return Module 0: Universal Assessment Methodology & Decision Matrix."""
    return jsonify({
        "ok": True,
        "methodology": ASSESSMENT_METHODOLOGY,
    })
