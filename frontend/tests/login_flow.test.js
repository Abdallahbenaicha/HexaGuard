// Tests for Login Page and Authentication Flow
import test from 'node:test';
import assert from 'node:assert/strict';

test('Login Form: rejects empty username or password', () => {
    function validateLoginForm(username, password) {
        const errors = {};
        if (!username || !username.trim()) {
            errors.username = 'Username is required';
        }
        if (!password || !password.trim()) {
            errors.password = 'Password is required';
        }
        return {
            isValid: Object.keys(errors).length === 0,
            errors,
        };
    }

    const resEmpty = validateLoginForm('', '');
    assert.equal(resEmpty.isValid, false);
    assert.equal(resEmpty.errors.username, 'Username is required');
    assert.equal(resEmpty.errors.password, 'Password is required');

    const resValid = validateLoginForm('analyst', 'SecuraX@2026!');
    assert.equal(resValid.isValid, true);
    assert.deepEqual(resValid.errors, {});
});

test('CSRF Protection: extracts XSRF cookie and injects X-CSRFToken header', () => {
    function extractCsrfToken(cookieString) {
        const match = cookieString.match(/(?:^|;\s*)(?:csrf_access_token|XSRF-TOKEN|csrf_token)=([^;]+)/);
        return match ? decodeURIComponent(match[1]) : null;
    }

    function createAuthenticatedRequestHeaders(cookieString, extraHeaders = {}) {
        const token = extractCsrfToken(cookieString);
        const headers = { ...extraHeaders };
        if (token) {
            headers['X-CSRFToken'] = token;
        }
        return headers;
    }

    const testCookie = 'session=abc123xyz; csrf_access_token=token-super-secret-99; lang=en';
    const headers = createAuthenticatedRequestHeaders(testCookie, { 'Content-Type': 'application/json' });

    assert.equal(headers['X-CSRFToken'], 'token-super-secret-99');
    assert.equal(headers['Content-Type'], 'application/json');
});

test('Session State: maps user roles and permissions accurately', () => {
    function parseUserSession(apiResponseUser) {
        const role = apiResponseUser.role || 'viewer';
        const permissions = Array.isArray(apiResponseUser.permissions) ? apiResponseUser.permissions : [];
        const canRunScans = role === 'admin' || role === 'analyst' || permissions.includes('run_scan');

        return {
            id: apiResponseUser.id,
            username: apiResponseUser.username,
            role,
            canRunScans,
            isAdmin: role === 'admin',
        };
    }

    const viewerUser = parseUserSession({ id: 5, username: 'newbie', role: 'viewer', permissions: [] });
    assert.equal(viewerUser.canRunScans, false);
    assert.equal(viewerUser.isAdmin, false);

    const approvedViewer = parseUserSession({ id: 5, username: 'newbie', role: 'viewer', permissions: ['run_scan'] });
    assert.equal(approvedViewer.canRunScans, true);

    const adminUser = parseUserSession({ id: 1, username: 'admin', role: 'admin', permissions: ['all'] });
    assert.equal(adminUser.canRunScans, true);
    assert.equal(adminUser.isAdmin, true);
});
