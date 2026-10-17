import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { formatFinding, escapeHtml } from '../src/utils/logicProtection.js';
import { renderMarkdown } from '../src/utils/markdownRenderer.js';

test('XSS Sanitization: formatFinding neutralizes Stored XSS payloads in all fields', () => {
    assert.strictEqual(escapeHtml('<script>'), '&lt;script&gt;');
    const maliciousFinding = {
        message: 'Normal text <img src=x onerror="alert(\'msg_xss\')"> injected',
        fix: 'Apply patch <script>alert("fix_xss")</script>',
        evidence: 'Vulnerable param: <svg/onload=alert("evidence_xss")>',
        cwe: 'CWE-79 <b onmouseover="alert(\'cwe\')">XSS</b>',
        owasp: 'A03 <iframe src="javascript:alert(\'owasp\')"></iframe>',
    };

    const formatted = formatFinding(maliciousFinding);

    // Simulate DOM rendering into a container
    const dom = new JSDOM(`<!DOCTYPE html><div id="root">${formatted}</div>`);
    const doc = dom.window.document;

    // Assert that NO dangerous executable elements or event handlers exist in the DOM
    assert.equal(doc.querySelector('img[onerror]'), null, 'img with onerror must not exist in DOM');
    assert.equal(doc.querySelector('script'), null, 'script tag must not exist in DOM');
    assert.equal(doc.querySelector('svg'), null, 'svg tag must not exist in DOM');
    assert.equal(doc.querySelector('b[onmouseover]'), null, 'b tag with onmouseover must not exist in DOM');
    assert.equal(doc.querySelector('iframe'), null, 'iframe tag must not exist in DOM');

    // The text content should safely display the literal payload characters
    assert.ok(doc.getElementById('root').textContent.includes('<img src=x onerror='));
});

test('XSS Sanitization: renderMarkdown neutralizes XSS in AI and user chat content', () => {
    const chatAttackPayload = `
### Header Title
Check this exploit:
<img src=x onerror=alert(document.cookie)>
<script>window.pwned=true</script>
\`\`\`javascript
const safeCode = "<img src=x onerror=alert(1)>";
\`\`\`
*italic* and **bold**
`;

    const renderedHtml = renderMarkdown(chatAttackPayload);
    const dom = new JSDOM(`<!DOCTYPE html><div id="chat-root">${renderedHtml}</div>`);
    const doc = dom.window.document;

    assert.equal(doc.querySelector('img[onerror]'), null, 'Chat rendered HTML must not contain img[onerror]');
    assert.equal(doc.querySelector('script'), null, 'Chat rendered HTML must not contain script tags');

    // Headers and markdown should still format correctly
    assert.ok(doc.querySelector('h3') !== null, 'h3 tag should be properly formatted');
    assert.ok(doc.querySelector('strong') !== null, 'strong tag should be properly formatted');
    assert.ok(doc.querySelector('em') !== null, 'em tag should be properly formatted');
});
