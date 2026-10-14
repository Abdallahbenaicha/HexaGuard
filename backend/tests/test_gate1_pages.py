"""
test_gate1_pages.py -- Comprehensive unit tests for Gate 1 pages:
- How SecuraX Was Built (journey_bp)
- Cybersecurity Intelligence (intelligence_bp)
- Personal PhD Tracker (phd_bp)

Verifies:
1. Strict 401 protection for unauthenticated requests.
2. 200 responses with exact contract schema for authenticated sessions.
3. Search validation, filtering, and error handling.
4. Data provenance metadata in PhD stats.
"""

import os, sys
import unittest
from flask import session

# Ensure sys.path includes backend directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Ensure SECRET_KEY is set for test app creation
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-gate1-verification-123456789')

from app import create_app


class TestGate1PagesEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False

    def setUp(self):
        self.client = self.app.test_client()

    def _login_session(self):
        """Simulate an active authenticated session."""
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

    # ── 1. Unauthenticated Access Tests (Security Guard) ───────────────
    def test_unauthenticated_access_is_blocked(self):
        endpoints = [
            '/api/journey',
            '/api/journey/meta/stats',
            '/api/journey/phase-0',
            '/api/intelligence/feeds',
            '/api/intelligence/recent',
            '/api/intelligence/search?q=test',
            '/api/intelligence/stats',
            '/api/phd/labs',
            '/api/phd/funding',
            '/api/phd/professors',
            '/api/phd/stats',
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 401, f"Expected 401 for unauth request to {ep}, got {res.status_code}")

    # ── 2. Journey Endpoints (Authenticated) ───────────────────────────
    def test_journey_endpoints(self):
        self._login_session()

        # Full journey
        res = self.client.get('/api/journey')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('phases', data)
        self.assertGreater(len(data['phases']), 0)
        first_phase = data['phases'][0]
        self.assertIn('id', first_phase)
        self.assertIn('title_en', first_phase)
        self.assertIn('title_ar', first_phase)
        self.assertIn('decisions', first_phase)

        # Meta stats
        res_stats = self.client.get('/api/journey/meta/stats')
        self.assertEqual(res_stats.status_code, 200)
        stats = res_stats.get_json().get('stats', {})
        self.assertIn('total_phases', stats)
        self.assertIn('total_decisions', stats)
        self.assertIn('total_lessons', stats)

        # Single phase lookup
        res_single = self.client.get(f"/api/journey/{first_phase['id']}")
        self.assertEqual(res_single.status_code, 200)
        self.assertEqual(res_single.get_json()['phase']['id'], first_phase['id'])

        # Unknown phase 404
        res_404 = self.client.get('/api/journey/nonexistent-phase-999')
        self.assertEqual(res_404.status_code, 404)

    # ── 3. Intelligence Endpoints (Authenticated) ──────────────────────
    def test_intelligence_endpoints(self):
        self._login_session()

        # Feeds taxonomy
        res_feeds = self.client.get('/api/intelligence/feeds')
        self.assertEqual(res_feeds.status_code, 200)
        feeds = res_feeds.get_json().get('feeds', [])
        self.assertGreater(len(feeds), 0)
        feed_ids = [f['id'] for f in feeds]
        self.assertIn('cve', feed_ids)
        self.assertIn('kev', feed_ids)

        # Stats
        res_stats = self.client.get('/api/intelligence/stats')
        self.assertEqual(res_stats.status_code, 200)
        stats = res_stats.get_json().get('stats', {})
        self.assertIn('total_items', stats)
        self.assertIn('by_category', stats)
        self.assertIn('by_severity', stats)

        # Recent items
        res_recent = self.client.get('/api/intelligence/recent')
        self.assertEqual(res_recent.status_code, 200)
        items = res_recent.get_json().get('items', [])
        self.assertGreater(len(items), 0)

        # Category filter
        res_filtered = self.client.get('/api/intelligence/recent?category=cve')
        self.assertEqual(res_filtered.status_code, 200)
        cve_items = res_filtered.get_json().get('items', [])
        for item in cve_items:
            self.assertEqual(item['category'], 'cve')

        # Search validation
        res_short = self.client.get('/api/intelligence/search?q=a')
        self.assertEqual(res_short.status_code, 400)

        res_search = self.client.get('/api/intelligence/search?q=cve')
        self.assertEqual(res_search.status_code, 200)
        search_items = res_search.get_json().get('items', [])
        self.assertGreater(len(search_items), 0)

    # ── 4. PhD Tracker Endpoints (Authenticated) ───────────────────────
    def test_phd_endpoints(self):
        self._login_session()

        # Labs
        res_labs = self.client.get('/api/phd/labs')
        self.assertEqual(res_labs.status_code, 200)
        labs = res_labs.get_json().get('labs', [])
        self.assertGreater(len(labs), 0)
        self.assertIn('name', labs[0])
        self.assertIn('country', labs[0])
        self.assertIn('focus', labs[0])

        # Funding
        res_fund = self.client.get('/api/phd/funding')
        self.assertEqual(res_fund.status_code, 200)
        funding = res_fund.get_json().get('funding', [])
        self.assertGreater(len(funding), 0)

        # Professors
        res_profs = self.client.get('/api/phd/professors')
        self.assertEqual(res_profs.status_code, 200)
        profs = res_profs.get_json().get('professors', [])
        self.assertGreater(len(profs), 0)

        # Stats & Workbook Provenance
        res_stats = self.client.get('/api/phd/stats')
        self.assertEqual(res_stats.status_code, 200)
        stats = res_stats.get_json().get('stats', {})
        self.assertIn('total_labs', stats)
        self.assertIn('total_funding_sources', stats)
        self.assertIn('total_professors', stats)
        self.assertIn('xlsx_pipeline', stats)
        pipeline = stats['xlsx_pipeline']
        self.assertIn('provenance', pipeline)
        self.assertIn('available', pipeline)


if __name__ == '__main__':
    unittest.main()
