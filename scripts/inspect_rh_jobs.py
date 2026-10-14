#!/usr/bin/env python3
import urllib.request
import re
import json

headers = {'User-Agent': 'Mozilla/5.0'}
for jid in ['DSV232', 'DTB328']:
    url = f"https://www.jobs.ac.uk/job/{jid}/"
    req = urllib.request.Request(url, headers=headers)
    html = urllib.request.urlopen(req, timeout=15).read().decode('utf-8', errors='ignore')
    m_json = re.findall(r'<script\s+type="application/ld\+json">([\s\S]*?)</script>', html)
    print(f"=== {jid} ===")
    for s in m_json:
        try:
            d = json.loads(s.strip())
            if isinstance(d, dict) and d.get('@type') == 'JobPosting':
                print("  Title:", d.get('title'))
                org = d.get('hiringOrganization')
                org_name = org.get('name') if isinstance(org, dict) else org
                print("  Org:", org_name)
                print("  Deadline:", d.get('validThrough'))
                desc = d.get('description', '')
                keywords_found = [kw for kw in ['cybersecurity', 'cyber security', 'information security', 'network security', 'vulnerability', 'cryptography', 'privacy', 'software security', 'security'] if kw in desc.lower()]
                print("  Keywords found in description:", keywords_found)
                # Check snippet
                clean_desc = re.sub(r'<[^>]+>', ' ', desc)
                print("  Snippet:", clean_desc[:200])
        except Exception as e:
            pass
