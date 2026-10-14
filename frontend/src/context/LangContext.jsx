import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import translations from '../i18n/translations';
import { applyLanguageDirection } from './direction.js';

const LangContext = createContext(null);

export const LangProvider = ({ children }) => {
    const [lang, setLang] = useState(() => localStorage.getItem('securax_lang') || 'en');

    useEffect(() => {
        applyLanguageDirection(lang);
    }, [lang]);

    const toggleLang = useCallback(() => {
        setLang(prev => {
            const next = prev === 'en' ? 'ar' : 'en';
            localStorage.setItem('securax_lang', next);
            return next;
        });
    }, []);

    const t = useCallback((key) =>
        translations[lang]?.[key] ?? translations['en']?.[key] ?? key,
    [lang]);

    return (
        <LangContext.Provider value={{ lang, toggleLang, t }}>
            {children}
        </LangContext.Provider>
    );
};

export const useLang = () => {
    const ctx = useContext(LangContext);
    if (!ctx) throw new Error('useLang must be used within LangProvider');
    return ctx;
};
