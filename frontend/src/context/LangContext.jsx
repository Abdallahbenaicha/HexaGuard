import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import translations from '../i18n/translations';

const LangContext = createContext(null);

export const LangProvider = ({ children }) => {
    const [lang, setLang] = useState(() => localStorage.getItem('hexaguard_lang') || 'en');

    useEffect(() => {
        document.dir = lang === 'ar' ? 'rtl' : 'ltr';
        document.documentElement.lang = lang;
        document.documentElement.setAttribute('data-lang', lang);
    }, [lang]);

    const toggleLang = useCallback(() => {
        setLang(prev => {
            const next = prev === 'en' ? 'ar' : 'en';
            localStorage.setItem('hexaguard_lang', next);
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
