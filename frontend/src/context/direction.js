/**
 * Direction & RTL helper for SecuraX.
 * Applied on language toggle to synchronize DOM direction attributes.
 */
export function applyLanguageDirection(lang) {
    if (typeof document !== 'undefined') {
        document.dir = lang === 'ar' ? 'rtl' : 'ltr';
        if (document.documentElement) {
            document.documentElement.lang = lang;
            document.documentElement.setAttribute('data-lang', lang);
        }
    }
}
