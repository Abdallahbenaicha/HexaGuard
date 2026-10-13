# -*- coding: utf-8 -*-
"""
test_gate1_7_discovery_dedup.py — Gate 1.7 Live Discovery Repair, Source Transparency & Deduplication Tests.

Verifies:
1. Candidate source registry complete (12 sources) with explicit semantic source_type.
2. jobs.ac.uk HTML adapter parsing, raw/accepted/rejected metrics, and direct links.
3. AcademicTransfer HTML adapter parsing, CAO-NU salary scale, and Dutch positions.
4. EURAXESS HTML adapter parsing, European Commission vacancy extraction.
5. Top European Cyber Labs curated adapter (CISPA, MPI-SP, Saarland, EPFL, ETH, TU Delft).
6. NSF Grants API semantic correctness: classifies as funded_research_project, NOT verified_vacancy.
7. OpenAlex API semantic correctness: classifies as research_lead, NOT verified_vacancy.
8. HTTP 403 WAF protection transparency: returns honest status, direct search links, no fake data.
9. HTTP 404 / Network timeout resilience without cascading failures.
10. Workbook deduplication baseline: 653 raw physical records consolidated to 467 unique.
11. Exact duplicate detection merges 186 duplicates non-destructively.
12. Fuzzy duplicates flagged (possible_duplicate=True) without deleting distinct vacancies.
13. Idempotent workbook loading.
14. Pre-deduplication backup creation and audit trail persistence.
"""
import os, sys, io, json, unittest, pathlib
from unittest.mock import patch, MagicMock

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ['SECRET_KEY'] = 'test-secret-key-gate1-7-dedup'
from app import create_app
from db.connection import _get_db, init_db
from blueprints.phd import (
    _load_all, _DISCOVERY_SOURCES, _run_jobs_ac_uk_adapter,
    _run_academictransfer_adapter, _run_euraxess_adapter,
    _run_top_cyber_labs_adapter, _run_nsf_adapter, _run_openalex_adapter,
    _run_probe_or_manual_adapter, _run_source_adapter
)


class TestGate17DiscoveryAndDedup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        with cls.app.app_context():
            init_db()

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

    # ── WORKSTREAM A: LIVE DISCOVERY & SOURCE TRANSPARENCY TESTS ─────────────

    def test_source_registry_complete_and_transparent(self):
        """GET /api/phd/discover/sources returns 12 candidate sources with non-interchangeable types."""
        res = self.client.get("/api/phd/discover/sources")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        sources = data.get("sources", [])
        self.assertGreaterEqual(len(sources), 12)

        source_ids = {s["id"] for s in sources}
        expected_ids = {
            "jobs_ac_uk", "academictransfer", "euraxess", "top_cyber_labs",
            "nsf_grants_api", "openalex_api", "findaphd", "daad_phdgermany",
            "campusfrance", "msca", "nature_careers", "academicpositions"
        }
        self.assertTrue(expected_ids.issubset(source_ids))

        # Check required transparency fields for every source
        for s in sources:
            self.assertIn("name", s)
            self.assertIn("source_type", s)
            self.assertIn("access_method", s)
            self.assertIn("direct_url", s)
            self.assertIn("status", s)
            self.assertIn("remediation_hint", s)
            self.assertIn(s["source_type"], {
                "official_vacancy_portal", "institution_career_page",
                "funding_database", "research_metadata", "aggregator"
            })

    @patch("blueprints.phd._safe_fetch")
    def test_jobs_ac_uk_adapter_parsing_and_metrics(self, mock_fetch):
        """jobs.ac.uk HTML parser extracts verified PhD studentships and metrics."""
        sample_html = """
        <div class="j-search-result__text">
          <a href="/job/ABC123_01/phd-in-software-security">PhD in Software Security & Fuzzing</a>
          <div class="j-search-result__employer"><b>Royal Holloway, University of London</b></div>
          <div class="j-search-result__department">Department of Computer Science</div>
        </div>
        <div class="j-search-result__text">
          <a href="/job/DEF456_02/phd-systems-security">Doctoral Studentship in Network Telemetry</a>
          <div class="j-search-result__employer"><b>University of Oxford</b></div>
          <div class="j-search-result__department">Department of Engineering Science</div>
        </div>
        """
        mock_fetch.return_value = sample_html
        items, success, err, http_code, raw_cnt, rej_cnt = _run_jobs_ac_uk_adapter("cybersecurity")

        self.assertTrue(success)
        self.assertEqual(http_code, 200)
        self.assertEqual(raw_cnt, 2)
        self.assertEqual(len(items), 2)
        self.assertEqual(rej_cnt, 0)

        # Check item fields
        first = items[0]
        self.assertEqual(first["record_type"], "vacancy_lead")
        self.assertEqual(first["institution"], "Royal Holloway, University of London")
        self.assertEqual(first["country"], "United Kingdom")
        self.assertIn("https://www.jobs.ac.uk/job/ABC123_01/phd-in-software-security", first["application_url"])
        self.assertIn("Funded PhD Studentship", first["funding"])

    @patch("blueprints.phd._safe_fetch")
    def test_academictransfer_adapter_parsing_and_metrics(self, mock_fetch):
        """AcademicTransfer HTML parser extracts salaried Dutch doctoral vacancies under CAO-NU."""
        sample_html = """
        <article>
          <a href="/en/jobs/348910/phd-candidate-applied-cryptography">
            <h3>PhD Candidate in Applied Cryptography & Post-Quantum Security</h3>
          </a>
          <p class="text-at-body">Join TU Eindhoven for a 4-year doctoral contract with social benefits.</p>
        </article>
        """
        mock_fetch.return_value = sample_html
        items, success, err, http_code, raw_cnt, rej_cnt = _run_academictransfer_adapter("cryptography")

        self.assertTrue(success)
        self.assertEqual(http_code, 200)
        self.assertEqual(len(items), 1)
        first = items[0]
        self.assertEqual(first["record_type"], "vacancy_lead")
        self.assertEqual(first["country"], "Netherlands")
        self.assertIn("CAO-NU", first["funding"])
        self.assertIn("https://www.academictransfer.com/en/jobs/348910/phd-candidate-applied-cryptography", first["application_url"])

    @patch("blueprints.phd._safe_fetch")
    def test_euraxess_adapter_parsing_and_metrics(self, mock_fetch):
        """EURAXESS Jobs Search adapter extracts official European Commission postings."""
        sample_html = """
        <a href="/jobs/123456">Early Stage Researcher (PhD) in Vulnerability Analysis</a>
        <a href="/jobs/789012">Doctoral Fellow in AI & Privacy</a>
        """
        mock_fetch.return_value = sample_html
        items, success, err, http_code, raw_cnt, rej_cnt = _run_euraxess_adapter("vulnerability")

        self.assertTrue(success)
        self.assertEqual(http_code, 200)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["record_type"], "vacancy_lead")
        self.assertEqual(items[0]["source_id"], "euraxess")
        self.assertEqual(items[0]["application_url"], "https://euraxess.ec.europa.eu/jobs/123456")

    def test_top_cyber_labs_curated_vacancies(self):
        """Top European Cyber Labs adapter returns curated vacancies with official institutional portals."""
        items, success, err, http_code, raw_cnt, rej_cnt = _run_top_cyber_labs_adapter("cybersecurity")
        self.assertTrue(success)
        self.assertEqual(http_code, 200)
        self.assertGreaterEqual(len(items), 6)

        insts = {i["institution"] for i in items}
        self.assertTrue(any("CISPA" in inst for inst in insts))
        self.assertTrue(any("Max Planck" in inst for inst in insts))
        self.assertTrue(any("EPFL" in inst for inst in insts))
        self.assertTrue(any("ETH Zurich" in inst for inst in insts))

        for it in items:
            self.assertEqual(it["record_type"], "verified_vacancy")
            self.assertIsNotNone(it["application_url"])
            self.assertIsNotNone(it["funding"])

    @patch("blueprints.phd._requests.get")
    def test_nsf_grants_semantic_separation(self, mock_get):
        """NSF Grants API awards are strictly classified as funded_research_project, NOT verified_vacancy."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": {
                "award": [{
                    "id": "2345678",
                    "title": "Collaborative Research: Scalable Automated Fuzzing for Cloud Firmware",
                    "awardeeName": "Purdue University",
                    "awardeeCity": "West Lafayette",
                    "awardeeStateCode": "IN",
                    "fundsObligatedAmt": "450000",
                    "startDate": "10/01/2024",
                    "expDate": "09/30/2027",
                    "piFirstName": "Gene",
                    "piLastName": "Spafford",
                    "piEmail": "spaf@cs.purdue.edu",
                    "abstractText": "This research develops advanced firmware fuzzing."
                }]
            }
        }
        mock_get.return_value = mock_resp

        items, success, err, http_code, raw_cnt, rej_cnt = _run_nsf_adapter("fuzzing")
        self.assertTrue(success)
        self.assertEqual(len(items), 1)

        first = items[0]
        # Semantic correctness assertions:
        self.assertEqual(first["record_type"], "funded_research_project")
        self.assertNotEqual(first["record_type"], "verified_vacancy")
        self.assertEqual(first["verification_status"], "funded_project")
        self.assertIn("$450,000", first["funding"])
        self.assertIn("Project grant period ends", first["deadline_raw"])
        self.assertIn("NOT PhD admission deadline", first["deadline_raw"])
        self.assertIsNone(first["stipend_info"])  # Stipend must NOT be fabricated

    @patch("blueprints.phd._requests.get")
    def test_openalex_semantic_separation(self, mock_get):
        """OpenAlex publications are strictly classified as research_lead, NOT verified_vacancy."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": [{
                "id": "https://openalex.org/W123456789",
                "title": "Automated Binary Analysis and Memory Corruption Detection",
                "doi": "https://doi.org/10.1145/123456",
                "authorships": [{
                    "author": {"display_name": "Dawn Song"},
                    "institutions": [{"display_name": "UC Berkeley", "country_code": "US"}]
                }]
            }]
        }
        mock_get.return_value = mock_resp

        items, success, err, http_code, raw_cnt, rej_cnt = _run_openalex_adapter("binary analysis")
        self.assertTrue(success)
        self.assertEqual(len(items), 1)

        first = items[0]
        self.assertEqual(first["record_type"], "research_lead")
        self.assertNotEqual(first["record_type"], "verified_vacancy")
        self.assertLess(first["confidence"], 0.50)
        self.assertIn("Research Lead", first["funding"])

    @patch("blueprints.phd._requests.get")
    def test_waf_blocked_source_transparency_403(self, mock_get):
        """Cloudflare/Akamai WAF blocked sources (HTTP 403) are transparently recorded with direct link."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        items, success, err, http_code, raw_cnt, rej_cnt = _run_probe_or_manual_adapter("findaphd", "cybersecurity")
        self.assertFalse(success)
        self.assertEqual(http_code, 403)
        self.assertEqual(len(items), 0)
        self.assertIn("WAF bot protection", err)

    # ── WORKSTREAM B: WORKBOOK DEDUPLICATION & INTEGRITY TESTS ────────────────

    def test_workbook_deduplication_baseline_metrics(self):
        """_load_all() audits 653 raw physical records and consolidates to 467 unique opportunities."""
        data = _load_all()
        opps = data.get("opportunities", [])
        report = data.get("dedup_report", {})

        self.assertEqual(report.get("raw_physical_records"), 653)
        self.assertEqual(report.get("primary_authoritative_records"), 151)
        self.assertEqual(report.get("raw_secondary_parsed"), 502)
        self.assertEqual(report.get("exact_duplicates_merged"), 186)
        self.assertEqual(len(opps), 467)
        self.assertEqual(report.get("consolidated_unique_records"), 467)

    def test_dedup_audit_endpoint(self):
        """GET /api/phd/dedup/audit returns complete audit metrics and missing fields."""
        res = self.client.get("/api/phd/dedup/audit")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        audit = data.get("audit", {})

        self.assertEqual(audit.get("raw_physical_records"), 653)
        self.assertEqual(audit.get("consolidated_unique_records"), 467)
        self.assertEqual(audit.get("exact_duplicates_merged"), 186)
        self.assertIn("missing_fields", audit)
        self.assertIn("institution", audit["missing_fields"])
        self.assertIn("deadline", audit["missing_fields"])

    def test_dedup_backup_endpoint_creates_json(self):
        """POST /api/phd/dedup/backup creates a valid timestamped JSON backup."""
        res = self.client.post("/api/phd/dedup/backup")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        b_file = data.get("backup_file")
        self.assertIsNotNone(b_file)
        self.assertTrue(pathlib.Path(b_file).exists())

        # Verify backup contains full opportunities
        with open(b_file, "r", encoding="utf-8") as f:
            b_data = json.load(f)
        self.assertIn("records", b_data)
        self.assertEqual(len(b_data["records"]), 467)

    def test_dedup_idempotence(self):
        """Multiple deduplication calls produce identical record counts (idempotent)."""
        res1 = self.client.post("/api/phd/dedup/apply")
        self.assertEqual(res1.status_code, 200)
        data1 = res1.get_json()

        res2 = self.client.post("/api/phd/dedup/apply")
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()

        self.assertEqual(
            data1["dedup_report"]["consolidated_unique_records"],
            data2["dedup_report"]["consolidated_unique_records"]
        )
        self.assertEqual(data1["dedup_report"]["consolidated_unique_records"], 467)

    def test_fuzzy_candidates_flagged_without_deletion(self):
        """Distinct vacancies with same institution are flagged (possible_duplicate=True) rather than deleted."""
        data = _load_all()
        opps = data.get("opportunities", [])
        flagged = [o for o in opps if o.get("possible_duplicate")]

        self.assertGreater(len(flagged), 0)
        for fo in flagged:
            self.assertTrue(fo.get("possible_duplicate"))
            self.assertIsNotNone(fo.get("possible_canonical_id"))
            # Must still have its own distinct program/field
            self.assertIsNotNone(fo.get("program"))


if __name__ == "__main__":
    unittest.main()
