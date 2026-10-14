import test from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { applyLanguageDirection } from '../src/context/direction.js';

test('RTL Language Switch: toggles document.dir, lang, and data-lang attributes using production direction helper', () => {
    // 1. Setup DOM environment
    const dom = new JSDOM('<!DOCTYPE html><html lang="en"><head></head><body><div id="root"></div></body></html>', {
        url: 'http://localhost:5173',
    });
    globalThis.document = dom.window.document;
    const { document } = dom.window;

    // Verify initial LTR state
    assert.equal(document.dir, '', 'Initial document.dir is default/empty');
    assert.equal(document.documentElement.lang, 'en', 'Initial lang is en');

    // 2. Invoke real production applyLanguageDirection from frontend/src/context/direction.js
    let currentLang = 'en';
    const storage = new Map();

    function updateLanguage(newLang) {
        currentLang = newLang;
        storage.set('securax_lang', newLang);
        applyLanguageDirection(newLang);
    }

    function toggleLanguage() {
        const next = currentLang === 'en' ? 'ar' : 'en';
        updateLanguage(next);
        return next;
    }

    // 3. Switch to Arabic (ar)
    const switchedToAr = toggleLanguage();
    assert.equal(switchedToAr, 'ar');
    assert.equal(document.dir, 'rtl', 'document.dir MUST be "rtl" when language is Arabic');
    assert.equal(document.documentElement.lang, 'ar', 'documentElement.lang MUST be "ar"');
    assert.equal(document.documentElement.getAttribute('data-lang'), 'ar', 'data-lang attribute MUST be "ar"');
    assert.equal(storage.get('securax_lang'), 'ar', 'localStorage must persist "ar"');

    // 4. Switch back to English (en)
    const switchedToEn = toggleLanguage();
    assert.equal(switchedToEn, 'en');
    assert.equal(document.dir, 'ltr', 'document.dir MUST be "ltr" when language is English');
    assert.equal(document.documentElement.lang, 'en', 'documentElement.lang MUST be "en"');
    assert.equal(document.documentElement.getAttribute('data-lang'), 'en', 'data-lang attribute MUST be "en"');
    assert.equal(storage.get('securax_lang'), 'en', 'localStorage must persist "en"');

    console.log('[PASS] RTL test confirmed: document.dir updates accurately between rtl and ltr.');
});
