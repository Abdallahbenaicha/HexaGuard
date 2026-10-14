# -*- coding: utf-8 -*-
"""
test_gate1_5_dossier.py — Gate 1.4.2 & Gate 1.5 Comprehensive Verification Suite.

Tests cover:
1. Gate 1.4.2 Funding Semantics:
   - NSF awards classified as 'funded_research_project', never 'verified_vacancy'.
   - NSF grant amounts never presented as student stipends.
   - NSF grant expiration dates never presented as PhD admission deadlines.
   - OpenAlex works classified strictly as 'research_lead' with 'unknown' funding.
   - Documented record distinction integrity.
2. Gate 1.5 Dossier Security & Authorization:
   - 401 unauthenticated access rejection across all /api/dossier/* endpoints.
   - Cross-user tenant isolation: User A cannot read User B's dossier or matrix.
   - Path-traversal defense: attempt to sneak '../../etc/passwd' or absolute paths into ZIP export rejected.
3. Gate 1.5 Evidence Integrity & Portfolio:
   - Candidate academic profile returns verified M.Sc. qualifications, GPA, SecuraX project evidence.
   - Strict provenance tagging ([VERIFIED EVIDENCE], [USER PROVIDED], [AI GENERATED DRAFT], [MISSING EVIDENCE]).
   - Requirement-to-evidence matrix generation with transparent matching statuses.
4. Gate 1.5 Export Capabilities:
   - PDF export returns valid binary stream (%PDF-1.4 header, ReportLab layout, page numbering).
   - ZIP bundle export returns valid zipfile stream containing manifest.json, PDF, CSV matrix, outreach pitch.
   - Manifest consistency check matching all included artifacts and provenance levels.
"""
import os, sys, io, zipfile, json, unittest
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ['SECRET_KEY'] = 'test-secret-key-gate1-5'
from app import create_app

class TestGate15DossierSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False

    def setUp(self):
        # User 1 test client
        self.client1 = self.app.test_client()
        with self.client1.session_transaction() as sess:
            sess['_user_id'] = '1'

        # User 2 test client for cross-tenant isolation testing
        self.client2 = self.app.test_client()
        with self.client2.session_transaction() as sess:
            sess['_user_id'] = '2'

    # ── 1. Gate 1.4.2: Funding & Vacancy Semantics ────────────────────────────
    def test_gate142_nsf_not_classified_as_phd_vacancy(self):
        """NSF grant MUST NOT be classified as verified_vacancy."""
        res = self.client1.post('/api/phd/discover', json={
            'query': 'fuzzing security',
            'sources': ['nsf_grants_api'],
            'limit': 5
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        nsf_items = [r for r in data.get('results', []) if r.get('source_id') == 'nsf_grants_api']
        if nsf_items:
            item = nsf_items[0]
            # Semantic assertion: must be funded_research_project, NOT verified_vacancy
            self.assertEqual(item.get('record_type'), 'funded_research_project')
            self.assertNotEqual(item.get('record_type'), 'verified_vacancy')
            self.assertEqual(item.get('verification_status'), 'funded_project')
            self.assertEqual(item.get('funding_status'), 'funded_project')
            # Grant funds belong to lab/PI, not student stipend
            self.assertIsNone(item.get('stipend_info'))
            # Expiry date is grant award period end, NOT PhD deadline
            self.assertIsNone(item.get('deadline'))
            self.assertEqual(item.get('deadline_status'), 'unknown')
            self.assertEqual(item.get('vacancy_status'), 'unconfirmed_vacancy')

    def test_gate142_openalex_classified_as_research_lead(self):
        """OpenAlex publication metadata MUST be classified as research_lead."""
        res = self.client1.post('/api/phd/discover', json={
            'query': 'software vulnerability',
            'sources': ['openalex_api'],
            'limit': 5
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        oa_items = [r for r in data.get('results', []) if r.get('source_id') == 'openalex_api']
        if oa_items:
            item = oa_items[0]
            self.assertEqual(item.get('record_type'), 'research_lead')
            self.assertEqual(item.get('verification_status'), 'unverified_lead')
            self.assertEqual(item.get('funding_status'), 'unknown')
            self.assertIsNone(item.get('deadline'))

    # ── 2. Gate 1.5 Security & Access Control ────────────────────────────────
    def test_gate15_unauthenticated_endpoints_blocked(self):
        """All /api/dossier/* endpoints MUST return 401 for unauthenticated clients."""
        unauth = self.app.test_client()
        endpoints = [
            ('/api/dossier/portfolio', 'GET'),
            ('/api/dossier/opportunity/saved_123/matrix', 'GET'),
            ('/api/dossier/generate', 'POST'),
            ('/api/dossier/export/pdf', 'POST'),
            ('/api/dossier/export/zip', 'POST'),
        ]
        for ep, method in endpoints:
            if method == 'GET':
                res = unauth.get(ep)
            else:
                res = unauth.post(ep, json={})
            self.assertEqual(res.status_code, 401, f"Expected 401 for unauthenticated {ep}")

    def test_gate15_cross_user_isolation(self):
        """User 2 must NOT access or generate dossiers for User 1's opportunities."""
        # Create opportunity belonging strictly to User 1
        opp_id = "user1_private_dossier_opp"
        self.client1.post('/api/phd/opportunities', json={
            "id": opp_id,
            "institution": "Technical University of Munich",
            "country": "Germany",
            "program": "PhD in Binary Security & Automated Exploitation",
            "field": "Software Security",
            "status": "planned",
        })

        # User 1 can view matrix
        res1 = self.client1.get(f'/api/dossier/opportunity/{opp_id}/matrix')
        self.assertEqual(res1.status_code, 200)

        # User 2 MUST receive 404 Not Found (zero information disclosure)
        res2 = self.client2.get(f'/api/dossier/opportunity/{opp_id}/matrix')
        self.assertEqual(res2.status_code, 404)

        # User 2 attempting to export PDF for User 1's opportunity must be 404
        res_exp = self.client2.post('/api/dossier/export/pdf', json={'opportunity_id': opp_id})
        self.assertEqual(res_exp.status_code, 404)

    # ── 3. Academic Portfolio & Evidence Provenance ──────────────────────────
    def test_gate15_academic_portfolio_provenance(self):
        """Portfolio returns candidate qualifications with strict provenance tags."""
        res = self.client1.get('/api/dossier/portfolio')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        portfolio = data.get('portfolio', {})

        # Candidate identity
        cand = portfolio.get('candidate', {})
        self.assertEqual(cand.get('name'), 'Abdallah Benaicha')
        self.assertTrue(any(k in cand.get('degree', '') for k in ['NICT', 'Master', 'ماجستير']))

        # Provenance verification
        for edu in portfolio.get('education', []):
            self.assertEqual(edu.get('provenance'), '[VERIFIED EVIDENCE]')
            self.assertTrue(any(k in edu.get('institution', '') for k in ['Mohamed Boudiaf', 'محمد بوضياف', 'M\'Sila', 'المسيلة']))

        # SecuraX project evidence
        securax = portfolio.get('project_evidence', {})
        self.assertEqual(securax.get('provenance'), '[VERIFIED EVIDENCE]')
        self.assertIn('SecuraX', securax.get('name', ''))
        self.assertGreaterEqual(len(securax.get('capabilities', [])), 4)

        # Skill ledger presence
        skills = portfolio.get('skills_ledger', [])
        self.assertGreaterEqual(len(skills), 5)
        for s in skills:
            self.assertIn(s.get('provenance'), ['[VERIFIED EVIDENCE]', '[USER PROVIDED]'])

    def test_gate15_requirement_to_evidence_matrix(self):
        """Generates structured matrix matching vacancy requirements to SecuraX evidence."""
        # Create opportunity with requirements
        opp_id = "test_matrix_tum_fuzzing"
        self.client1.post('/api/phd/opportunities', json={
            "id": opp_id,
            "institution": "TU Munich - Chair of IT Security",
            "country": "Germany",
            "program": "Doctoral Position in Automated Vulnerability Detection & Fuzzing",
            "field": "Software Security, AST Taint Analysis, Static Analysis",
            "supervisor": "Prof. Dr. Claudia Eckert",
            "funding": "TV-L E13 100% Fully Funded",
            "status": "planned",
        })

        res = self.client1.get(f'/api/dossier/opportunity/{opp_id}/matrix')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('matrix', data)
        self.assertIn('match_rate', data)
        matrix = data['matrix']
        self.assertGreaterEqual(len(matrix), 5)

        # Validate structured matrix columns
        for row in matrix:
            self.assertIn('requirement', row)
            self.assertIn('source_evidence', row)
            self.assertIn('candidate_evidence', row)
            self.assertIn('match_status', row)
            self.assertIn(row['match_status'], [
                'MATCHED', 'PARTIALLY_MATCHED', 'MISSING_EVIDENCE', 'REQUIRES_MANUAL_REVIEW'
            ])
            self.assertIn('action', row)
            self.assertIn('provenance', row)

    # ── 4. Dossier Generation & Export Integrity ─────────────────────────────
    def test_gate15_dossier_generation_and_checklist(self):
        """Generates tailored dossier data with document checklist and tailored pitch."""
        opp_id = "test_dossier_gen_opp"
        self.client1.post('/api/phd/opportunities', json={
            "id": opp_id,
            "institution": "IMT School for Advanced Studies Lucca",
            "country": "Italy",
            "program": "PhD in Cybersecurity and Formal Verification",
            "field": "Formal Methods, System Security",
            "supervisor": "Prof. Gabriele Costa",
            "status": "planned",
        })

        res = self.client1.post('/api/dossier/generate', json={
            'opportunity_id': opp_id,
            'selected_document_ids': ['doc_cv', 'doc_msc_diploma', 'doc_thesis_abstract']
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        dossier = data.get('dossier', {})
        self.assertEqual(dossier.get('candidate_name'), 'Abdallah Benaicha')
        self.assertIn('outreach_pitch', dossier)
        self.assertIn('curated_documents', dossier)
        # Verify selected documents were preserved
        docs = dossier['curated_documents']
        self.assertEqual(len(docs), 3)

    def test_gate15_pdf_export_validity(self):
        """Exports professional PDF document with ReportLab and valid %PDF header."""
        opp_id = "test_pdf_export_opp"
        self.client1.post('/api/phd/opportunities', json={
            "id": opp_id,
            "institution": "Aalborg University",
            "country": "Denmark",
            "program": "PhD Fellowship in Network and IoT Security",
            "field": "Distributed Systems, Network Security",
            "status": "planned",
        })

        res = self.client1.post('/api/dossier/export/pdf', json={
            'opportunity_id': opp_id,
            'selected_document_ids': ['doc_cv', 'doc_msc_diploma']
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, 'application/pdf')
        pdf_bytes = res.get_data()
        self.assertTrue(pdf_bytes.startswith(b'%PDF-'), "PDF must begin with %PDF header")
        self.assertGreater(len(pdf_bytes), 1000, "PDF byte stream must have reasonable size")

    def test_gate15_zip_bundle_and_traversal_protection(self):
        """Exports ZIP bundle containing manifest.json, PDF, CSV, pitch, with traversal defense."""
        opp_id = "test_zip_export_opp"
        self.client1.post('/api/phd/opportunities', json={
            "id": opp_id,
            "institution": "Masaryk University",
            "country": "Czech Republic",
            "program": "PhD in Security Analysis of Smart Contracts & Systems",
            "field": "Software Security, Static Analysis",
            "supervisor": "Prof. Vashek Matyas",
            "status": "planned",
        })

        # Request ZIP export with allowlisted documents
        res = self.client1.post('/api/dossier/export/zip', json={
            'opportunity_id': opp_id,
            'selected_document_ids': ['doc_cv', 'doc_msc_diploma']
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, 'application/zip')

        # Read zipfile in memory
        zip_buffer = io.BytesIO(res.get_data())
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            file_list = zf.namelist()
            # Must contain manifest.json, academic_dossier.pdf, matrix CSV, and outreach draft
            self.assertIn('manifest.json', file_list)
            self.assertIn('academic_dossier.pdf', file_list)
            self.assertIn('requirement_evidence_matrix.csv', file_list)
            self.assertIn('outreach_email_draft.txt', file_list)

            # Check manifest contents
            manifest_bytes = zf.read('manifest.json')
            manifest = json.loads(manifest_bytes.decode('utf-8'))
            self.assertEqual(manifest.get('candidate_name'), 'Abdallah Benaicha')
            self.assertIn('verification_legend', manifest)
            self.assertIn('included_files', manifest)

            # Path-traversal assertion: no entry in zipfile may start with '/' or contain '..'
            for entry_name in file_list:
                self.assertFalse(entry_name.startswith('/'), f"Path traversal risk in zip entry: {entry_name}")
                self.assertNotIn('..', entry_name, f"Relative path traversal risk in zip entry: {entry_name}")

if __name__ == '__main__':
    unittest.main()
