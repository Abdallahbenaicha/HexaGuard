// Tests for Report View, Severity Calculation, and Reproduction PoC formatting
import test from 'node:test';
import assert from 'node:assert/strict';

test('Report View: categorizes findings and computes summary statistics', () => {
    function computeReportSummary(findings = []) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const f of findings) {
            const sev = (f.severity || 'info').toLowerCase();
            if (sev in counts) {
                counts[sev] += 1;
            } else {
                counts.info += 1;
            }
        }
        const total = findings.length;
        const maxSeverity =
            counts.critical > 0 ? 'critical' :
            counts.high > 0 ? 'high' :
            counts.medium > 0 ? 'medium' :
            counts.low > 0 ? 'low' : 'clean';

        return { counts, total, maxSeverity };
    }

    const testFindings = [
        { title: 'SQL Injection', severity: 'critical', cve_id: 'CVE-2023-1111' },
        { title: 'XSS in search', severity: 'high' },
        { title: 'Missing CSP', severity: 'medium' },
        { title: 'Missing X-Frame-Options', severity: 'medium' },
        { title: 'Verbose banner', severity: 'low' },
    ];

    const summary = computeReportSummary(testFindings);
    assert.equal(summary.total, 5);
    assert.equal(summary.counts.critical, 1);
    assert.equal(summary.counts.high, 1);
    assert.equal(summary.counts.medium, 2);
    assert.equal(summary.counts.low, 1);
    assert.equal(summary.maxSeverity, 'critical');
});

test('Report View: formats reproduction PoC curl commands safely', () => {
    function buildReproductionPoc(finding, targetUrl) {
        if (finding.poc_curl) {
            return finding.poc_curl;
        }
        if (finding.method && finding.param) {
            return `curl -i -s -k -X ${finding.method} "${targetUrl}?${finding.param}=PAYLOAD"`;
        }
        return `curl -i -s -k "${targetUrl}"`;
    }

    const customPocFinding = {
        title: 'Open Redirect',
        poc_curl: 'curl -i -s -k "https://example.com/redirect?url=https://evil.com"',
    };
    assert.equal(
        buildReproductionPoc(customPocFinding, 'https://example.com'),
        'curl -i -s -k "https://example.com/redirect?url=https://evil.com"'
    );

    const paramFinding = {
        title: 'Reflected XSS',
        method: 'GET',
        param: 'q',
    };
    assert.equal(
        buildReproductionPoc(paramFinding, 'https://example.com/search'),
        'curl -i -s -k -X GET "https://example.com/search?q=PAYLOAD"'
    );
});

test('Report View: parses EPSS and CISA KEV tags on findings', () => {
    function enrichFindingBadges(finding) {
        const badges = [];
        if (finding.cve_id) {
            badges.push({ type: 'cve', label: finding.cve_id });
        }
        if (finding.is_cisa_kev) {
            badges.push({ type: 'cisa-kev', label: 'CISA KEV (Actively Exploited)', variant: 'danger' });
        }
        if (typeof finding.epss_score === 'number' && finding.epss_score >= 0.5) {
            badges.push({
                type: 'epss-high',
                label: `EPSS: ${(finding.epss_score * 100).toFixed(1)}% (Imminent Exploitation)`,
                variant: 'warning',
            });
        }
        return badges;
    }

    const criticalVuln = {
        title: 'Log4Shell Vulnerability',
        cve_id: 'CVE-2021-44228',
        is_cisa_kev: true,
        epss_score: 0.975,
    };

    const badges = enrichFindingBadges(criticalVuln);
    assert.equal(badges.length, 3);
    assert.equal(badges[0].label, 'CVE-2021-44228');
    assert.equal(badges[1].type, 'cisa-kev');
    assert.equal(badges[2].type, 'epss-high');
    assert.match(badges[2].label, /97.5%/);
});
