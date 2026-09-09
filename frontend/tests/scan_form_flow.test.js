// Tests for Scan Form validation and SSRF/Target-lock checks
import test from 'node:test';
import assert from 'node:assert/strict';

test('Scan Form: normalizes target and enforces protocol', () => {
    function normalizeScanTarget(targetInput) {
        if (!targetInput || !targetInput.trim()) {
            throw new Error('Target cannot be empty');
        }
        let clean = targetInput.trim();
        if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
            clean = 'https://' + clean;
        }
        const url = new URL(clean);
        return {
            fullUrl: url.href,
            hostname: url.hostname.toLowerCase(),
            protocol: url.protocol,
        };
    }

    const t1 = normalizeScanTarget('example.com');
    assert.equal(t1.fullUrl, 'https://example.com/');
    assert.equal(t1.hostname, 'example.com');

    const t2 = normalizeScanTarget('http://testphp.vulnweb.com/search.php?test=query');
    assert.equal(t2.hostname, 'testphp.vulnweb.com');
    assert.equal(t2.protocol, 'http:');

    assert.throws(() => normalizeScanTarget(''), /Target cannot be empty/);
});

test('Scan Form: blocks SSRF targets on the frontend before dispatch', () => {
    function validateTargetAgainstSSRF(hostname) {
        const lower = hostname.toLowerCase().trim();
        if (
            lower === 'localhost' ||
            lower === '127.0.0.1' ||
            lower === '0.0.0.0' ||
            lower === '::1' ||
            lower.startsWith('10.') ||
            lower.startsWith('192.168.') ||
            lower.startsWith('172.16.') ||
            lower.startsWith('172.31.') ||
            lower.startsWith('169.254.')
        ) {
            return { isAllowed: false, reason: 'Private/Loopback IP and localhost targets are forbidden' };
        }
        return { isAllowed: true };
    }

    assert.equal(validateTargetAgainstSSRF('127.0.0.1').isAllowed, false);
    assert.equal(validateTargetAgainstSSRF('localhost').isAllowed, false);
    assert.equal(validateTargetAgainstSSRF('192.168.1.50').isAllowed, false);
    assert.equal(validateTargetAgainstSSRF('10.0.0.1').isAllowed, false);
    assert.equal(validateTargetAgainstSSRF('169.254.169.254').isAllowed, false);

    assert.equal(validateTargetAgainstSSRF('scanme.nmap.org').isAllowed, true);
    assert.equal(validateTargetAgainstSSRF('example.com').isAllowed, true);
});

test('Scan Form: enforces target-lock if user has a locked target', () => {
    function checkTargetLockConstraint(submittedTarget, lockedTarget) {
        if (!lockedTarget || !lockedTarget.trim()) {
            return { allowed: true }; // No lock
        }
        const cleanLock = lockedTarget.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        const cleanSub = submittedTarget.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');

        if (cleanSub !== cleanLock && !cleanSub.endsWith('.' + cleanLock)) {
            return {
                allowed: false,
                reason: `Target is locked to '${lockedTarget}'. You cannot scan '${submittedTarget}'.`,
            };
        }
        return { allowed: true };
    }

    const resLockedOk = checkTargetLockConstraint('api.company.com', 'company.com');
    assert.equal(resLockedOk.allowed, true);

    const resLockedExact = checkTargetLockConstraint('company.com', 'company.com');
    assert.equal(resLockedExact.allowed, true);

    const resLockedBlocked = checkTargetLockConstraint('attacker.com', 'company.com');
    assert.equal(resLockedBlocked.allowed, false);
    assert.match(resLockedBlocked.reason, /Target is locked to 'company.com'/);
});
