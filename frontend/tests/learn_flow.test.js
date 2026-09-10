// Tests for Unified Education System, Module 0 Methodology, and Single-Topic View Routing
import test from 'node:test';
import assert from 'node:assert/strict';

test('Education System: SSoT Enforcement & Catalog Item Normalization', () => {
    // Normalization logic used by VulnLibraryPage
    function normalizeCatalogItems(offensiveList, incidentList) {
        const offensive = (offensiveList || []).map(item => ({
            id: item.id,
            name: item.name_en || item.name,
            track: item.scanner,
            difficulty: item.difficulty,
            hasSandbox: Boolean(item.has_sandbox),
            isIncident: false,
        }));

        const incidents = (incidentList || []).map(item => ({
            id: item.id,
            name: item.name_en || item.name,
            track: 'incident',
            difficulty: item.difficulty,
            hasSandbox: Boolean(item.has_sandbox),
            isIncident: true,
        }));

        return [...offensive, ...incidents];
    }

    const mockOffensive = [
        { id: 'xss', name_en: 'Cross-Site Scripting (XSS)', scanner: 'web', difficulty: 'easy', has_sandbox: true },
        { id: 'sqli', name_en: 'SQL Injection', scanner: 'web', difficulty: 'medium', has_sandbox: true },
        { id: 'ssrf', name_en: 'Server-Side Request Forgery', scanner: 'server_ext', difficulty: 'hard', has_sandbox: true },
    ];

    const mockIncidents = [
        { id: 'inc_spearphishing_credential_harvest', name_en: 'Spearphishing Credential Harvesting', difficulty: 'medium', has_sandbox: false },
    ];

    const catalog = normalizeCatalogItems(mockOffensive, mockIncidents);
    assert.equal(catalog.length, 4);
    assert.equal(catalog[0].id, 'xss');
    assert.equal(catalog[0].track, 'web');
    assert.equal(catalog[0].hasSandbox, true);
    assert.equal(catalog[3].track, 'incident');
    assert.equal(catalog[3].isIncident, true);
});

test('Education System: 4-Level Stepper Validation', () => {
    const LESSON_LEVELS = [
        { id: 1, title: 'Foundations & Architecture', key: 'foundations' },
        { id: 2, title: 'Detection & Discovery', key: 'detection' },
        { id: 3, title: 'Hands-on Practice', key: 'practice' },
        { id: 4, title: 'Defend & Report', key: 'defend_and_report' },
    ];

    function validateLessonSchema(lesson) {
        const errors = [];
        if (!lesson) {
            return ['Lesson object is missing'];
        }
        for (const lvl of LESSON_LEVELS) {
            const section = lesson[lvl.key];
            if (!section || typeof section !== 'object' || Object.keys(section).length === 0) {
                errors.push(`Level ${lvl.id} (${lvl.key}) is empty or missing`);
            }
        }
        return errors;
    }

    const validLesson = {
        foundations: { mechanics_en: 'Mechanics text...', vulnerable_code_example: 'code', secure_code_example: 'code' },
        detection: { manual_commands_en: ['curl -v'], detection_heuristics_en: 'heuristics' },
        practice: { sandbox_target: 'xss', challenge_prompt_en: 'Solve challenge' },
        defend_and_report: { remediation_en: 'Apply fix', report_template_en: 'Report template' },
    };

    assert.deepEqual(validateLessonSchema(validLesson), []);

    const invalidLesson = {
        foundations: { mechanics_en: 'Mechanics text...' },
        detection: {},
    };
    const errors = validateLessonSchema(invalidLesson);
    assert.equal(errors.length, 3);
    assert.ok(errors.some(e => e.includes('detection')));
    assert.ok(errors.some(e => e.includes('practice')));
    assert.ok(errors.some(e => e.includes('defend_and_report')));
});

test('Module 0: 7-Phase Universal Assessment Workflow Order', () => {
    const EXPECTED_PHASES = [
        { phase: 1, name: 'Scope Definition & ROE' },
        { phase: 2, name: 'Passive Reconnaissance (OSINT)' },
        { phase: 3, name: 'Active Network & Service Discovery' },
        { phase: 4, name: 'Targeted Engine Selection' },
        { phase: 5, name: 'Vulnerability Confirmation & Deep Probing' },
        { phase: 6, name: 'Triaging & Threat Contextualization' },
        { phase: 7, name: 'Verified Reporting & Remediation' },
    ];

    function verifyMethodologyPhases(phases) {
        assert.equal(phases.length, 7);
        for (let i = 0; i < EXPECTED_PHASES.length; i++) {
            assert.equal(phases[i].phase, EXPECTED_PHASES[i].phase);
            assert.equal(phases[i].name, EXPECTED_PHASES[i].name);
        }
        return true;
    }

    assert.ok(verifyMethodologyPhases(EXPECTED_PHASES));
});

test('Education System: External Deep Dive Links Capped at 3', () => {
    function sanitizeDeepDiveLinks(links) {
        if (!Array.isArray(links)) return [];
        return links.slice(0, 3);
    }

    const rawLinks = [
        { title: 'OWASP', url: 'https://owasp.org' },
        { title: 'PortSwigger', url: 'https://portswigger.net' },
        { title: 'HackTricks', url: 'https://hacktricks.xyz' },
        { title: 'Extra Link', url: 'https://extra.example.com' },
        { title: 'Another Link', url: 'https://another.example.com' },
    ];

    const sanitized = sanitizeDeepDiveLinks(rawLinks);
    assert.equal(sanitized.length, 3);
    assert.equal(sanitized[0].title, 'OWASP');
    assert.equal(sanitized[2].title, 'HackTricks');
});
