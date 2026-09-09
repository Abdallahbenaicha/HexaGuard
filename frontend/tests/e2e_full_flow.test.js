// End-to-End full flow test: Login -> Target Input -> Scan Job Dispatch -> Report View
import test from 'node:test';
import assert from 'node:assert/strict';

test('E2E Flow: Full User Lifecycle (Login -> Scan Dispatch -> Polling -> Report)', async () => {
    // Simulated backend state
    const mockDb = {
        users: {
            'analyst@securax.local': { id: 2, username: 'analyst', role: 'analyst', password: 'Password1!' },
        },
        jobs: {},
        reports: {},
    };

    // Step 1: User Login
    function handleLogin(email, password) {
        const user = mockDb.users[email];
        if (!user || user.password !== password) {
            return { ok: false, status: 401, error: 'Invalid credentials' };
        }
        return {
            ok: true,
            status: 200,
            token: 'auth-jwt-token-123',
            user: { id: user.id, username: user.username, role: user.role },
        };
    }

    const authRes = handleLogin('analyst@securax.local', 'Password1!');
    assert.equal(authRes.ok, true);
    assert.equal(authRes.user.role, 'analyst');

    // Step 2: Submit Scan Target
    function handleStartScan(authToken, payload) {
        if (!authToken) {
            return { ok: false, status: 401, error: 'Unauthorized' };
        }
        const { target, scan_type } = payload;
        if (!target) {
            return { ok: false, status: 400, error: 'Target required' };
        }
        const jobId = 'job-' + Math.random().toString(36).substring(2, 9);
        mockDb.jobs[jobId] = {
            id: jobId,
            target,
            scan_type,
            status: 'running',
            progress: 10,
        };
        return { ok: true, status: 202, job_id: jobId, message: 'Scan initiated' };
    }

    const scanRes = handleStartScan(authRes.token, { target: 'https://example.com', scan_type: 'web' });
    assert.equal(scanRes.ok, true);
    assert.match(scanRes.job_id, /^job-/);

    // Step 3: Poll Scan Job until finished
    function pollJobStatus(jobId, step = 0) {
        const job = mockDb.jobs[jobId];
        if (!job) return { ok: false, status: 404 };

        if (step >= 2) {
            job.status = 'completed';
            job.progress = 100;
            const reportId = 'rep-' + jobId;
            job.report_id = reportId;
            mockDb.reports[reportId] = {
                id: reportId,
                target: job.target,
                scan_type: job.scan_type,
                findings: [
                    { title: 'Missing Content-Security-Policy', severity: 'high' },
                    { title: 'Missing X-Content-Type-Options', severity: 'medium' },
                ],
            };
        } else {
            job.progress = 50 * step;
        }
        return { ok: true, job };
    }

    const poll1 = pollJobStatus(scanRes.job_id, 1);
    assert.equal(poll1.job.status, 'running');

    const poll2 = pollJobStatus(scanRes.job_id, 2);
    assert.equal(poll2.job.status, 'completed');
    assert.equal(poll2.job.progress, 100);

    // Step 4: Fetch Final Report View
    function fetchReport(reportId) {
        const rep = mockDb.reports[reportId];
        if (!rep) return { ok: false, status: 404 };
        return { ok: true, report: rep };
    }

    const reportRes = fetchReport(poll2.job.report_id);
    assert.equal(reportRes.ok, true);
    assert.equal(reportRes.report.target, 'https://example.com');
    assert.equal(reportRes.report.findings.length, 2);
    assert.equal(reportRes.report.findings[0].severity, 'high');
});
