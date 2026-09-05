// Hunt Guide — Vulnerability Methodology Library
export const HUNT_PHASES = {
  recon:  { id: 'recon',  label: 'Phase 1 — Recon', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30' },
  enum:   { id: 'enum',   label: 'Phase 2 — Enumeration', color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/30' },
  test:   { id: 'test',   label: 'Phase 3 — Vuln Testing', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  report: { id: 'report', label: 'Phase 4 — Report & PoC', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30' },
};

export const PLATFORM_META = {
  hackerone: { label: 'HackerOne', color: 'bg-orange-500/20 text-orange-300 border-orange-500/30', icon: '🔶' },
  bugcrowd:  { label: 'Bugcrowd',  color: 'bg-red-500/20 text-red-300 border-red-500/30',           icon: '🔴' },
  yeswehack: { label: 'YesWeHack', color: 'bg-green-500/20 text-green-300 border-green-500/30',     icon: '🟢' },
};

export const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'bg-red-500/15 text-red-400 border-red-500/30', dot: 'bg-red-400' },
  high:     { label: 'High',     color: 'bg-orange-500/15 text-orange-400 border-orange-500/30', dot: 'bg-orange-400' },
  medium:   { label: 'Medium',   color: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400' },
  low:      { label: 'Low',      color: 'bg-blue-500/15 text-blue-400 border-blue-500/30', dot: 'bg-blue-400' },
};

export const ASSET_TYPE_META = {
  URL:             { label: 'Web App URL', icon: '🌐', desc: 'Specific web application URL' },
  WILDCARD:        { label: 'Wildcard', icon: '🔀', desc: 'All subdomains of a domain' },
  DOMAIN:          { label: 'Domain', icon: '🏠', desc: 'Root domain and all subdomains' },
  WEB_APPLICATION: { label: 'Web App', icon: '⚙️', desc: 'Full web application scope' },
};

export const METHODOLOGY = {
  URL: {
    summary: 'Testing a specific web application. Focus on web vulnerabilities, auth flaws, and business logic.',
    phases: [
      {
        phase: 'recon',
        steps: [
          {
            title: 'Technology Fingerprinting',
            cmd: 'whatweb <target> -v\ncurl -I <target>',
            desc: 'Identify tech stack: framework, server, CMS, CDN. Use Wappalyzer browser extension for quick analysis.',
          },
          {
            title: 'JavaScript File Mining',
            cmd: 'python3 LinkFinder.py -i <target> -d\nwaybackurls <domain> | grep "\\.js$"',
            desc: 'Extract hidden endpoints, API keys, and secrets from JS bundles.',
          },
          {
            title: 'Historical URL Discovery',
            cmd: 'waybackurls <domain> | tee urls.txt\ngau <domain> >> urls.txt\ncat urls.txt | sort -u',
            desc: 'Find old endpoints, parameters, and deprecated features via Wayback Machine.',
          },
          {
            title: 'Directory & File Bruteforce',
            cmd: 'ffuf -u <target>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,403\nferoxbuster -u <target> -w big.txt',
            desc: 'Discover hidden admin panels, backup files (.bak, .zip), and sensitive paths.',
          },
        ],
      },
      {
        phase: 'enum',
        steps: [
          {
            title: 'Parameter Discovery',
            cmd: 'paramspider -d <domain>\narjun -u <target>/endpoint -m GET,POST',
            desc: 'Find all GET/POST parameters. Hidden params often lead to injection vulnerabilities.',
          },
          {
            title: 'Authentication Flow Mapping',
            cmd: '# Burp Suite: Spider/Crawl all auth endpoints\n# Map: /login, /register, /reset-password, /2fa',
            desc: 'Understand the complete auth flow before testing bypass techniques.',
          },
          {
            title: 'API Endpoint Enumeration',
            cmd: 'ffuf -u <target>/api/FUZZ -w api-wordlist.txt\n# Check: /swagger.json, /openapi.json, /graphql',
            desc: 'Enumerate API routes. Check for versioning (v1 vs v2) and deprecated endpoints.',
          },
        ],
      },
      {
        phase: 'test',
        steps: [
          {
            title: 'XSS — Cross-Site Scripting',
            cmd: 'dalfox url "<target>?q=test"\nkxss < urls.txt\n# Manual: <script>alert(1)</script>',
            desc: 'Test reflected, stored, and DOM-based XSS across all input parameters.',
            vuln: 'xss',
          },
          {
            title: 'SQL Injection',
            cmd: 'sqlmap -u "<target>?id=1" --dbs --batch\nsqlmap -r request.txt --level=5 --risk=3',
            desc: 'Test all parameters for SQLi. Export Burp requests to use with sqlmap -r.',
            vuln: 'sqli',
          },
          {
            title: 'IDOR & Broken Access Control',
            cmd: '# Change user IDs in API calls:\n# GET /api/users/1001 → try 1002, 1003\n# Use Burp Intruder for mass testing',
            desc: 'Replace numeric IDs and UUIDs with other values. Test cross-user resource access.',
            vuln: 'idor',
          },
          {
            title: 'SSRF Detection',
            cmd: 'ssrfmap -r request.txt\n# Inject: http://169.254.169.254/latest/meta-data/\n# Use interactsh.com for out-of-band',
            desc: 'Inject external URLs in image fetch, webhook, redirect, and import parameters.',
            vuln: 'ssrf',
          },
          {
            title: 'CSRF Testing',
            cmd: '# Intercept state-changing requests in Burp\n# Remove/modify CSRF token\n# Test: token absence, reuse, other-user token',
            desc: 'Test all state-changing POST/PUT/DELETE requests for CSRF protection.',
            vuln: 'csrf',
          },
          {
            title: 'Nuclei Automated Scan',
            cmd: 'nuclei -u <target> -t ~/nuclei-templates/ -severity medium,high,critical -o nuclei_results.txt',
            desc: 'Run full Nuclei scan. Review results manually to eliminate false positives.',
          },
        ],
      },
      {
        phase: 'report',
        steps: [
          {
            title: 'Create Reproducible PoC',
            cmd: '# Screen recording of the attack\n# Minimal HTML PoC for XSS/CSRF\n# Burp repeater screenshots (request + response)',
            desc: 'The PoC must be clear, step-by-step, and reproducible by the triage team.',
          },
          {
            title: 'Calculate CVSS Score',
            cmd: '# https://www.first.org/cvss/calculator/3.1\n# Example XSS Stored: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
            desc: 'Use CVSS 3.1 calculator. Document the full vector string in your report.',
          },
          {
            title: 'Write the Report',
            cmd: '# Title: [Type] in [Feature/Endpoint]\n# Summary: 2-3 line impact explanation\n# Steps to Reproduce: numbered list\n# Impact: business impact\n# Remediation: suggested fix',
            desc: 'Follow the platform template. Be concise, professional, and impact-focused.',
          },
        ],
      },
    ],
    tips: [
      'Always test IDOR when you see numeric IDs or UUIDs in API calls.',
      'Check rate limiting on password reset and OTP endpoints.',
      'Test file uploads for webshell upload and path traversal.',
      'Look for sensitive data in JS files: API keys, tokens, internal URLs.',
      'Verify security headers: Content-Security-Policy, HSTS, X-Frame-Options.',
      'Test OAuth/OIDC flows for state parameter manipulation and redirect_uri bypass.',
    ],
  },

  WILDCARD: {
    summary: 'Testing all subdomains. Start with enumeration, then look for takeovers and forgotten assets.',
    phases: [
      {
        phase: 'recon',
        steps: [
          {
            title: 'Subdomain Enumeration',
            cmd: 'subfinder -d <domain> -o subs.txt\namass enum -passive -d <domain> >> subs.txt\nassetfinder <domain> >> subs.txt\ncat subs.txt | sort -u > all_subs.txt',
            desc: 'Use multiple tools for maximum coverage. Each tool finds different subdomains.',
          },
          {
            title: 'Live Host Discovery',
            cmd: 'cat all_subs.txt | dnsx -a -resp-only -o ips.txt\nhttpx -l all_subs.txt -title -status-code -tech-detect -o live.txt',
            desc: 'Resolve DNS and check which subdomains are actually serving HTTP(S).',
          },
          {
            title: 'Port Scanning',
            cmd: 'naabu -list all_subs.txt -p top-100 -o ports.txt\nnmap -iL ips.txt -sV --open -T4',
            desc: 'Find non-standard ports. Services on 8080, 8443, 3000 are often less secure.',
          },
          {
            title: 'Visual Recon Screenshots',
            cmd: 'gowitness file -f live.txt --screenshot-path ./screens\n# Review screenshots for interesting apps',
            desc: 'Take screenshots of all live subdomains. Quickly identify forgotten/dev apps.',
          },
        ],
      },
      {
        phase: 'enum',
        steps: [
          {
            title: 'Subdomain Takeover Check',
            cmd: 'subjack -w all_subs.txt -t 100 -ssl -o takeover.txt\nsubzy run --targets all_subs.txt',
            desc: 'Find dangling DNS records. High-value bug: subdomains pointing to unclaimed services.',
            vuln: 'takeover',
          },
          {
            title: 'Cloud Storage Discovery',
            cmd: 'cat all_subs.txt | grep -iE "s3|storage|cdn|backup|assets"\nS3Scanner scan --buckets-file buckets.txt',
            desc: 'Find misconfigured S3 buckets, Azure Blobs, and GCP storage.',
          },
          {
            title: 'JS Files Across All Subs',
            cmd: 'cat live.txt | waybackurls | grep "\\.js$" | sort -u | tee js_files.txt\ncat js_files.txt | while read f; do curl -s "$f" | grep -E "api_key|secret|token"; done',
            desc: 'Extract and analyze all JS files from all subdomains for secrets.',
          },
        ],
      },
      {
        phase: 'test',
        steps: [
          {
            title: 'Nuclei on All Live Subs',
            cmd: 'nuclei -l live.txt -t ~/nuclei-templates/ -severity medium,high,critical -o results.txt',
            desc: 'Mass automated scan. Focus manual effort on high findings.',
          },
          {
            title: 'CORS Misconfiguration Scan',
            cmd: 'cat live.txt | CORScanner\ncorstest -t live.txt',
            desc: 'Overly permissive CORS can allow cross-origin data theft.',
            vuln: 'cors',
          },
          {
            title: 'Exploit Subdomain Takeover',
            cmd: '# Claim the external service (GitHub Pages, Heroku, Netlify...)\n# Host: <html><body>Subdomain Takeover PoC</body></html>\n# Screenshot showing your control',
            desc: 'After confirming a takeover, claim the external service to prove impact.',
            vuln: 'takeover',
          },
        ],
      },
      {
        phase: 'report',
        steps: [
          {
            title: 'Takeover PoC Demonstration',
            cmd: '# Screenshot 1: DNS lookup showing CNAME → external service\n# Screenshot 2: Your PoC page hosted at the subdomain\n# Screenshot 3: Cookies accessible from parent domain',
            desc: 'Show actual control of the subdomain. Demonstrate what an attacker could do.',
          },
          {
            title: 'Impact Statement',
            cmd: '# Cookie theft from parent domain\n# Phishing page hosting under trusted domain\n# CSP bypass if wildcard in policy\n# OAuth redirect_uri manipulation',
            desc: 'Quantify the maximum impact clearly. Takeovers are usually P2/P3.',
          },
        ],
      },
    ],
    tips: [
      'Check subdomain takeover on GitHub Pages: CNAME → *.github.io unclaimed.',
      'Forgotten dev/staging subdomains often have weaker authentication.',
      'Try: curl https://<sub>/.git/HEAD to detect exposed git repos.',
      'API gateways on subdomains may lack proper authentication.',
      'Check for HTTP→HTTPS redirect issues that could leak cookies.',
    ],
  },
};

METHODOLOGY.DOMAIN = METHODOLOGY.WILDCARD;
METHODOLOGY.WEB_APPLICATION = METHODOLOGY.URL;

export const VULN_RESOURCES = {
  xss: {
    label: 'Cross-Site Scripting (XSS)',
    portswigger: 'https://portswigger.net/web-security/cross-site-scripting',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting',
    owasp: 'https://owasp.org/www-community/attacks/xss/',
    youtube: [
      { title: 'XSS For Bug Bounty Hunters — NahamSec', url: 'https://www.youtube.com/results?search_query=nahamsec+XSS+bug+bounty' },
      { title: 'PortSwigger XSS Labs', url: 'https://portswigger.net/web-security/all-labs#cross-site-scripting' },
    ],
  },
  sqli: {
    label: 'SQL Injection',
    portswigger: 'https://portswigger.net/web-security/sql-injection',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/sql-injection',
    owasp: 'https://owasp.org/www-community/attacks/SQL_Injection',
    youtube: [
      { title: 'SQL Injection Full Course — TryHackMe', url: 'https://www.youtube.com/results?search_query=SQL+injection+bug+bounty+2024' },
    ],
  },
  ssrf: {
    label: 'SSRF',
    portswigger: 'https://portswigger.net/web-security/ssrf',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery',
    owasp: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
    youtube: [
      { title: 'SSRF Bug Bounty — Full Guide', url: 'https://www.youtube.com/results?search_query=SSRF+bug+bounty+2024' },
    ],
  },
  idor: {
    label: 'IDOR / Broken Access Control',
    portswigger: 'https://portswigger.net/web-security/access-control/idor',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/idor',
    owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
    youtube: [
      { title: 'IDOR — The Ultimate Guide', url: 'https://www.youtube.com/results?search_query=IDOR+bug+bounty+2024+tutorial' },
    ],
  },
  csrf: {
    label: 'CSRF',
    portswigger: 'https://portswigger.net/web-security/csrf',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery',
    owasp: 'https://owasp.org/www-community/attacks/csrf',
    youtube: [
      { title: 'CSRF Bug Bounty — Practical Guide', url: 'https://www.youtube.com/results?search_query=CSRF+bug+bounty' },
    ],
  },
  takeover: {
    label: 'Subdomain Takeover',
    portswigger: 'https://portswigger.net/web-security/host-header/exploiting',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover',
    owasp: 'https://owasp.org/www-project-web-security-testing-guide/',
    youtube: [
      { title: 'Subdomain Takeover — Full Guide', url: 'https://www.youtube.com/results?search_query=subdomain+takeover+bug+bounty+2024' },
    ],
  },
  cors: {
    label: 'CORS Misconfiguration',
    portswigger: 'https://portswigger.net/web-security/cors',
    hacktricks: 'https://book.hacktricks.xyz/pentesting-web/cors-bypass',
    owasp: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
    youtube: [
      { title: 'CORS Bugs — Bug Bounty', url: 'https://www.youtube.com/results?search_query=CORS+misconfiguration+bug+bounty' },
    ],
  },
};

export const TOOLS_BY_PHASE = {
  recon: [
    { name: 'Subfinder',   url: 'https://github.com/projectdiscovery/subfinder', desc: 'Passive subdomain enumeration', category: 'subdomain' },
    { name: 'Amass',       url: 'https://github.com/owasp-amass/amass', desc: 'Attack surface mapping', category: 'subdomain' },
    { name: 'GAU',         url: 'https://github.com/lc/gau', desc: 'Fetch known URLs (Wayback, AlienVault)', category: 'urls' },
    { name: 'Shodan',      url: 'https://www.shodan.io/', desc: 'Search exposed services', category: 'osint' },
    { name: 'Censys',      url: 'https://search.censys.io/', desc: 'Internet-wide scanning data', category: 'osint' },
  ],
  enum: [
    { name: 'ffuf',        url: 'https://github.com/ffuf/ffuf', desc: 'Fast web fuzzer (dirs, params)', category: 'fuzz' },
    { name: 'Feroxbuster', url: 'https://github.com/epi052/feroxbuster', desc: 'Recursive content discovery', category: 'fuzz' },
    { name: 'Arjun',       url: 'https://github.com/s0md3v/Arjun', desc: 'HTTP parameter discovery', category: 'params' },
    { name: 'httpx',       url: 'https://github.com/projectdiscovery/httpx', desc: 'Fast HTTP probing', category: 'probe' },
    { name: 'gowitness',   url: 'https://github.com/sensepost/gowitness', desc: 'Web screenshot utility', category: 'screenshot' },
  ],
  test: [
    { name: 'Burp Suite',  url: 'https://portswigger.net/burp', desc: 'Industry standard web proxy', category: 'proxy' },
    { name: 'Nuclei',      url: 'https://github.com/projectdiscovery/nuclei', desc: 'Template-based vuln scanner', category: 'scanner' },
    { name: 'SQLMap',      url: 'https://sqlmap.org/', desc: 'Automatic SQL injection', category: 'sqli' },
    { name: 'Dalfox',      url: 'https://github.com/hahwul/dalfox', desc: 'Powerful XSS scanner', category: 'xss' },
    { name: 'SSRFmap',     url: 'https://github.com/swisskyrepo/SSRFmap', desc: 'SSRF detection & exploitation', category: 'ssrf' },
    { name: 'Subjack',     url: 'https://github.com/haccer/subjack', desc: 'Subdomain takeover detection', category: 'takeover' },
  ],
  report: [
    { name: 'CVSS 3.1 Calc', url: 'https://www.first.org/cvss/calculator/3.1', desc: 'Official severity calculator', category: 'scoring' },
    { name: 'interactsh',  url: 'https://app.interactsh.com/', desc: 'Out-of-band interaction server', category: 'oob' },
    { name: 'Carbon',      url: 'https://carbon.now.sh/', desc: 'Beautiful code screenshots', category: 'presentation' },
  ],
};
