import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';
import { Shield, Globe, BarChart2, Clock, ChevronRight, X, Zap } from 'lucide-react';

const TOUR_KEY = 'hexaguard_tour_done';

const STEPS = [
    {
        icon: Shield,
        color: 'text-cyan-400',
        bg: 'bg-cyan-500/10',
        titleKey: 'tour_welcome_title',
        descKey: 'tour_welcome_desc',
        action: null,
    },
    {
        icon: Globe,
        color: 'text-indigo-400',
        bg: 'bg-indigo-500/10',
        titleKey: 'tour_scan_title',
        descKey: 'tour_scan_desc',
        action: { labelKey: 'tour_scan_action', to: '/scan/web' },
    },
    {
        icon: Zap,
        color: 'text-orange-400',
        bg: 'bg-orange-500/10',
        titleKey: 'tour_bg_title',
        descKey: 'tour_bg_desc',
        action: null,
    },
    {
        icon: Clock,
        color: 'text-purple-400',
        bg: 'bg-purple-500/10',
        titleKey: 'tour_schedule_title',
        descKey: 'tour_schedule_desc',
        action: { labelKey: 'tour_schedule_action', to: '/scheduled' },
    },
    {
        icon: BarChart2,
        color: 'text-green-400',
        bg: 'bg-green-500/10',
        titleKey: 'tour_dash_title',
        descKey: 'tour_dash_desc',
        action: { labelKey: 'tour_dash_action', to: '/dashboard' },
    },
];

// Fallback strings for keys not yet in translations
const FALLBACKS = {
    tour_welcome_title:   'Welcome to HexaGuard',
    tour_welcome_desc:    'Your all-in-one security platform. Let\'s take a quick tour of the key features.',
    tour_scan_title:      'Run Your First Scan',
    tour_scan_desc:       'Choose from 7 scan types: Web, Network, DAST, SSL, Server, Code, and Dependencies.',
    tour_scan_action:     'Start Web Scan →',
    tour_bg_title:        'Background Scans',
    tour_bg_desc:         'Toggle "Run in Background" on any scan page — navigate freely while scans run and get browser notifications when done.',
    tour_schedule_title:  'Scheduled Scans',
    tour_schedule_desc:   'Set up daily, weekly, or monthly recurring scans so you never miss a new vulnerability.',
    tour_schedule_action: 'Manage Schedule →',
    tour_dash_title:      'Track Your Posture',
    tour_dash_desc:       'The Dashboard shows your Security Posture score, vulnerability trends, and recent scan results at a glance.',
    tour_dash_action:     'Go to Dashboard →',
};

export default function OnboardingTour() {
    const { user } = useAuth();
    const { t } = useLang();
    const navigate = useNavigate();
    const [step, setStep]       = useState(0);
    const [visible, setVisible] = useState(false);

    const _t = (key) => {
        const v = t(key);
        return (v && v !== key) ? v : (FALLBACKS[key] || key);
    };

    useEffect(() => {
        if (!user) return;
        const done = localStorage.getItem(TOUR_KEY);
        if (!done) {
            const timer = setTimeout(() => setVisible(true), 800);
            return () => clearTimeout(timer);
        }
    }, [user]);

    const dismiss = () => {
        localStorage.setItem(TOUR_KEY, '1');
        setVisible(false);
    };

    const next = () => {
        if (step < STEPS.length - 1) {
            setStep(s => s + 1);
        } else {
            dismiss();
        }
    };

    const goTo = (to) => {
        dismiss();
        navigate(to);
    };

    if (!visible) return null;

    const current = STEPS[step];
    const Icon = current.icon;

    return (
        <AnimatePresence>
            {visible && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        key="backdrop"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[9998]"
                        onClick={dismiss}
                    />

                    {/* Modal */}
                    <motion.div
                        key="modal"
                        initial={{ opacity: 0, scale: 0.92, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.92, y: 20 }}
                        transition={{ type: 'spring', stiffness: 300, damping: 25 }}
                        className="fixed inset-0 z-[9999] flex items-center justify-center p-4"
                        role="dialog"
                        aria-modal="true"
                        aria-label="Onboarding Tour"
                    >
                        <div className="w-full max-w-md bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden">
                            {/* Header */}
                            <div className="flex items-center justify-between px-6 pt-5 pb-0">
                                <div className="flex gap-1.5">
                                    {STEPS.map((_, i) => (
                                        <button
                                            key={i}
                                            onClick={() => setStep(i)}
                                            className={`h-1.5 rounded-full transition-all duration-300 ${
                                                i === step
                                                    ? 'w-6 bg-cyan-500'
                                                    : i < step
                                                    ? 'w-3 bg-cyan-300 dark:bg-cyan-700'
                                                    : 'w-3 bg-slate-200 dark:bg-slate-700'
                                            }`}
                                            aria-label={`Step ${i + 1}`}
                                        />
                                    ))}
                                </div>
                                <button
                                    onClick={dismiss}
                                    className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
                                    aria-label="Close tour"
                                >
                                    <X className="w-4 h-4" />
                                </button>
                            </div>

                            {/* Content */}
                            <AnimatePresence mode="wait">
                                <motion.div
                                    key={step}
                                    initial={{ opacity: 0, x: 20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: -20 }}
                                    transition={{ duration: 0.2 }}
                                    className="px-6 py-8 text-center"
                                >
                                    <div className={`w-16 h-16 rounded-2xl ${current.bg} flex items-center justify-center mx-auto mb-5`}>
                                        <Icon className={`w-8 h-8 ${current.color}`} />
                                    </div>
                                    <h2 className="text-xl font-bold text-slate-900 dark:text-white mb-3">
                                        {_t(current.titleKey)}
                                    </h2>
                                    <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">
                                        {_t(current.descKey)}
                                    </p>
                                </motion.div>
                            </AnimatePresence>

                            {/* Footer */}
                            <div className="px-6 pb-6 flex items-center gap-3">
                                {current.action ? (
                                    <button
                                        onClick={() => goTo(current.action.to)}
                                        className="flex-1 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 text-sm font-medium hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                                    >
                                        {_t(current.action.labelKey)}
                                    </button>
                                ) : (
                                    <button
                                        onClick={dismiss}
                                        className="flex-1 py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 text-sm hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                                    >
                                        Skip Tour
                                    </button>
                                )}
                                <button
                                    onClick={next}
                                    className="flex-1 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-semibold flex items-center justify-center gap-1.5 transition-colors"
                                >
                                    {step === STEPS.length - 1 ? 'Get Started' : 'Next'}
                                    <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
}
