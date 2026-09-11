"""Seed initial Phase 1 learning exercises into the learning_exercises table.

Creates 4 core exercises:
- XSS Knowledge (Assessment)
- XSS Lab Exploitation (Lab)
- SQLi Knowledge (Assessment)
- SQLi Lab Exploitation (Lab)
"""

import json
import logging
from database import init_db, _get_db, create_exercise

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_learning")

SEED_EXERCISES = [
    {
        "vuln_type": "xss",
        "capability": "knowledge",
        "exercise_type": "assessment",
        "title_en": "Cross-Site Scripting (XSS) Mechanics & Contexts",
        "description_en": "Explain Reflected, Stored, and DOM XSS attack vectors, execution sinks, and contextual output encoding defense.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["escaping", "sanitization", "csp", "dom", "context"],
        },
        "cert_hint": "Covers PortSwigger BSCP and OffSec OSWE XSS curriculum.",
    },
    {
        "vuln_type": "xss",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "Reflected & DOM XSS Sandbox Lab",
        "description_en": "Exploit reflected input vectors in the isolated Adversarial Twin Sandbox environment.",
        "difficulty": "medium",
        "content_json": {
            "sandbox_target": "xss",
            "proof_flag": "FLAG{xss_dom_reflection_conquered_2026}",
        },
        "cert_hint": "eWPTX / OSWE hands-on lab proof capture.",
    },
    {
        "vuln_type": "sqli",
        "capability": "knowledge",
        "exercise_type": "assessment",
        "title_en": "SQL Injection Mechanics & Parameterized Defenses",
        "description_en": "Explain syntax breakout, tautologies, UNION queries, and parameterized query compilation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["parameterization", "prepared statements", "union", "orm", "syntax"],
        },
        "cert_hint": "Maps to OWASP A05 and CompTIA PenTest+ SQLi modules.",
    },
    {
        "vuln_type": "sqli",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "UNION-Based SQLi Hash Extraction Lab",
        "description_en": "Exploit classic SQL injection in the isolated DVWA container to capture the proof flag.",
        "difficulty": "hard",
        "content_json": {
            "sandbox_target": "sqli",
            "proof_flag": "FLAG{sqli_union_select_admin_extracted}",
        },
        "cert_hint": "OSWE / eWPT Database Extraction Practical.",
    },
]


def seed():
    init_db()
    db = _get_db()

    for item in SEED_EXERCISES:
        existing = db.execute(
            "SELECT id FROM learning_exercises WHERE vuln_type = ? AND capability = ? AND exercise_type = ?",
            (item["vuln_type"], item["capability"], item["exercise_type"]),
        ).fetchone()

        if not existing:
            created = create_exercise(
                vuln_type=item["vuln_type"],
                capability=item["capability"],
                exercise_type=item["exercise_type"],
                title_en=item["title_en"],
                description_en=item["description_en"],
                difficulty=item["difficulty"],
                content_json=item["content_json"],
                cert_hint=item["cert_hint"],
            )
            logger.info("Created exercise: %s (%s - %s)", created["title_en"], created["vuln_type"], created["capability"])
        else:
            logger.info("Exercise already exists: %s (%s - %s)", item["title_en"], item["vuln_type"], item["capability"])


if __name__ == "__main__":
    seed()
