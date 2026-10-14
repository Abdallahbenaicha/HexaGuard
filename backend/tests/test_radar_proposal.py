# -*- coding: utf-8 -*-
import os, sys, io, unittest
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ['SECRET_KEY'] = 'test-secret'
from app import create_app

class TestPhdRadarAndProposal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

    def test_phd_radar_endpoint(self):
        res = self.client.get('/api/phd/radar')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('ok'))
        self.assertIn('radar', data)
        radar = data['radar']
        self.assertIn('total_candidates', radar)
        self.assertIn('critical_45d', radar)
        self.assertIn('rolling_open', radar)
        self.assertIn('upcoming_90d', radar)
        self.assertIn('top_funded_high', radar)
        self.assertGreater(radar['total_candidates'], 0)
        self.assertGreater(radar['top_funded_count'], 0)

    def test_phd_radar_ics_export(self):
        res = self.client.get('/api/phd/radar/export-ics')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, 'text/calendar')
        content = res.get_data(as_text=True)
        self.assertIn('BEGIN:VCALENDAR', content)
        self.assertIn('END:VCALENDAR', content)

    def test_generate_proposal_hook_endpoint(self):
        # Fetch an opportunity first
        res_opps = self.client.get('/api/phd/opportunities?limit=1')
        self.assertEqual(res_opps.status_code, 200)
        opps = res_opps.get_json().get('opportunities', [])
        self.assertGreater(len(opps), 0)
        opp_id = opps[0]['id']

        # Test English generation
        res_en = self.client.post('/api/phd/generate-proposal-hook', json={
            'opportunity_id': opp_id,
            'language': 'en',
            'custom_notes': 'Highlighting distributed AST fuzzing experience.'
        })
        self.assertEqual(res_en.status_code, 200)
        data_en = res_en.get_json()
        self.assertTrue(data_en.get('ok'))
        self.assertIn('subject_line', data_en)
        self.assertIn('salutation', data_en)
        self.assertIn('opening_hook', data_en)
        self.assertIn('securax_pitch', data_en)
        self.assertIn('call_to_action', data_en)
        self.assertIn('full_email', data_en)
        self.assertIn('SecuraX', data_en['full_email'])

        # Test Arabic generation
        res_ar = self.client.post('/api/phd/generate-proposal-hook', json={
            'opportunity_id': opp_id,
            'language': 'ar',
            'custom_notes': 'التركيز على رسالة الماستر ونموذج التدقيق المؤتمت.'
        })
        self.assertEqual(res_ar.status_code, 200)
        data_ar = res_ar.get_json()
        self.assertTrue(data_ar.get('ok'))
        self.assertIn('طلب دكتوراه', data_ar['subject_line'])

if __name__ == '__main__':
    unittest.main()
