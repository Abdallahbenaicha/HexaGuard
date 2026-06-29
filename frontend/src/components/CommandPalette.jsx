import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Globe, Zap, Layers, Lock, Network, FileSearch,
    Shield, Package, LayoutDashboard, FileText,
    Users, ScrollText, Settings, MessageSquare,
    Search, ArrowRight, ScanLine, Activity, Clock, HelpCircle,
    Box, LayoutGrid,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const ALL_COMMANDS = [
    { category: 'Scanners', label: 'Web Application Scan', desc: 'OWASP Top 10 + injection tests', to: '/scan/web',          icon: Globe,          keywords: 'web url http' },
    { category: 'Scanners', label: 'SSL/TLS Audit',        desc: 'Cert, cipher & protocol check', to: '/scan/ssl',           icon: Lock,           keywords: 'ssl tls cert certificate https' },
    { category: 'Scanners', label: 'Network Recon',        desc: 'Port scan, service detection',  to: '/scan/network',       icon: Network,        keywords: 'network nmap port scan' },
    { category: 'Scanners', label: 'Dynamic Analysis',     desc: 'DAST runtime testing',          to: '/scan/dast',          icon: Zap,            keywords: 'dast dynamic runtime' },
    { category: 'Scanners', label: 'Code Audit (SAST)',    desc: 'Static source code analysis',   to: '/scan/code',          icon: Layers,         keywords: 'sast code static source' },
    { category: 'Scanners', label: 'Config Audit',         desc: 'Apache/Nginx config review',    to: '/scan/apache',        icon: FileSearch,     keywords: 'config apache nginx server' },
    { category: 'Scanners', label: 'Server Audit',         desc: 'External server probing',       to: '/scan/server-ext',    icon: Shield,         keywords: 'server external probe' },
    { category: 'Scanners', label: 'Dependency Check',     desc: 'Supply chain vuln scan',        to: '/scan/dependencies',  icon: Package,        keywords: 'dependencies supply chain npm pip' },
    { category: 'Scanners', label: 'Docker Security',      desc: 'Dockerfile & compose audit',    to: '/scan/docker',        icon: Box,            keywords: 'docker container dockerfile compose devops' },
    { category: 'Scanners', label: 'DNS & Email Security', desc: 'SPF, DMARC, DKIM, DNSSEC',     to: '/scan/dns',           icon: Globe,          keywords: 'dns spf dmarc dkim email mx dnssec zone' },
    { category: 'Scanners', label: 'WordPress Audit',      desc: 'WordPress site security scan',  to: '/scan/wordpress',     icon: LayoutGrid,     keywords: 'wordpress wp cms xmlrpc user enum admin' },
    { category: 'Navigate', label: 'Dashboard',            desc: 'Security overview & stats',     to: '/dashboard',          icon: LayoutDashboard, keywords: 'home dashboard overview' },
    { category: 'Navigate', label: 'Reports',              desc: 'All scan reports & exports',    to: '/reports',            icon: FileText,       keywords: 'reports export pdf' },
    { category: 'Navigate', label: 'Scheduled Scans',      desc: 'Recurring daily/weekly scans',  to: '/scheduled',          icon: Clock,          keywords: 'schedule recurring cron daily weekly' },
    { category: 'Navigate', label: 'Help & Docs',          desc: 'Guides, FAQ, scan reference',   to: '/help',               icon: HelpCircle,     keywords: 'help docs faq guide' },
    { category: 'Navigate', label: 'ARIA AI Chat',         desc: 'AI security assistant',         to: '/chat',               icon: MessageSquare,  keywords: 'ai chat aria assistant' },
    { category: 'Account',  label: 'Profile & Settings',  desc: 'Password, 2FA, API tokens',     to: '/profile',            icon: Settings,       keywords: 'profile settings password 2fa token' },
    { category: 'Admin',    label: 'User Management',      desc: 'Create & revoke accounts',      to: '/admin/users',        icon: Users,          keywords: 'users admin manage', adminOnly: true },
    { category: 'Admin',    label: 'Scan Records',         desc: 'All platform scan history',     to: '/admin/scans',        icon: ScanLine,       keywords: 'scans history admin', adminOnly: true },
    { category: 'Admin',    label: 'Audit Log',            desc: 'Immutable event trail',         to: '/audit',              icon: ScrollText,     keywords: 'audit log events trail', adminOnly: true },
];

const CATEGORY_ORDER = ['Scanners', 'Navigate', 'Account', 'Admin'];

const CommandPalette = () => {
    const { user } = useAuth();
    const navigate  = useNavigate();
    const [open, setOpen]     = useState(false);
    const [query, setQuery]   = useState('');
    const [cursor, setCursor] = useState(0);
    const inputRef  = useRef(null);
    const listRef   = useRef(null);

    const commands = ALL_COMMANDS.filter(c => !c.adminOnly || user?.role === 'admin');

    const filtered = query.trim()
        ? commands.filter(c => {
            const q = query.toLowerCase();
            return (
                c.label.toLowerCase().includes(q) ||
                c.desc.toLowerCase().includes(q) ||
                c.keywords.includes(q)
            );
          })
        : commands;

    const grouped = CATEGORY_ORDER.reduce((acc, cat) => {
        const items = filtered.filter(c => c.category === cat);
        if (items.length) acc[cat] = items;
        return acc;
    }, {});

    const flat = Object.values(grouped).flat();

    const close = useCallback(() => {
        setOpen(false);
        setQuery('');
        setCursor(0);
    }, []);

    const go = useCallback((cmd) => {
        close();
        navigate(cmd.to);
    }, [close, navigate]);

    // Open on Ctrl+K / Cmd+K
    useEffect(() => {
        const onKey = (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                setOpen(o => !o);
            }
            if (e.key === 'Escape') close();
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, [close]);

    // Custom event from Navbar button
    useEffect(() => {
        const handler = () => setOpen(o => !o);
        window.addEventListener('hexaguard-cmd-palette', handler);
        return () => window.removeEventListener('hexaguard-cmd-palette', handler);
    }, []);

    // Focus input when opened
    useEffect(() => {
        if (open) {
            setCursor(0);
            setTimeout(() => inputRef.current?.focus(), 50);
        }
    }, [open]);

    // Arrow key navigation
    const onKeyDown = (e) => {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setCursor(c => Math.min(c + 1, flat.length - 1));
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setCursor(c => Math.max(c - 1, 0));
        } else if (e.key === 'Enter' && flat[cursor]) {
            go(flat[cursor]);
        }
    };

    // Scroll active item into view
    useEffect(() => {
        const el = listRef.current?.querySelector(`[data-idx="${cursor}"]`);
        el?.scrollIntoView({ block: 'nearest' });
    }, [cursor]);

    if (!open) return null;

    let flatIdx = 0;

    return (
        <div
            className="fixed inset-0 z-[9000] flex items-start justify-center pt-[10vh] px-4"
            onClick={close}
        >
            {/* Backdrop */}
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

            {/* Panel */}
            <div
                className="relative w-full max-w-xl bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden animate-in fade-in slide-in-from-top-4 duration-200"
                onClick={e => e.stopPropagation()}
            >
                {/* Search input */}
                <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-200 dark:border-slate-800">
                    <Search className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    <input
                        ref={inputRef}
                        value={query}
                        onChange={e => { setQuery(e.target.value); setCursor(0); }}
                        onKeyDown={onKeyDown}
                        placeholder="Search scanners, pages, admin tools…"
                        className="flex-1 bg-transparent text-sm text-slate-900 dark:text-white placeholder-slate-400 outline-none"
                    />
                    <kbd className="hidden sm:block text-[10px] text-slate-400 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 rounded font-mono">
                        ESC
                    </kbd>
                </div>

                {/* Results */}
                <div ref={listRef} className="max-h-[60vh] overflow-y-auto py-2">
                    {flat.length === 0 && (
                        <div className="px-6 py-10 text-center text-sm text-slate-400">
                            No results for "<span className="text-slate-600 dark:text-slate-300">{query}</span>"
                        </div>
                    )}

                    {Object.entries(grouped).map(([cat, items]) => (
                        <div key={cat}>
                            <div className="px-4 pt-3 pb-1 text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
                                {cat}
                            </div>
                            {items.map((cmd) => {
                                const idx = flatIdx++;
                                const Icon = cmd.icon;
                                const active = cursor === idx;
                                return (
                                    <button
                                        key={cmd.to}
                                        data-idx={idx}
                                        onClick={() => go(cmd)}
                                        onMouseEnter={() => setCursor(idx)}
                                        className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                                            active
                                                ? 'bg-primary-50 dark:bg-primary-500/10'
                                                : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                                        }`}
                                    >
                                        <div className={`p-1.5 rounded-lg flex-shrink-0 ${
                                            active
                                                ? 'bg-primary-100 dark:bg-primary-500/20 text-primary-600 dark:text-primary-400'
                                                : 'bg-slate-100 dark:bg-slate-800 text-slate-500'
                                        }`}>
                                            <Icon className="w-3.5 h-3.5" />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className={`text-sm font-medium leading-tight ${
                                                active ? 'text-primary-700 dark:text-primary-300' : 'text-slate-800 dark:text-slate-200'
                                            }`}>
                                                {cmd.label}
                                            </div>
                                            <div className="text-xs text-slate-400 mt-0.5 truncate">{cmd.desc}</div>
                                        </div>
                                        {active && <ArrowRight className="w-3.5 h-3.5 text-primary-500 flex-shrink-0" />}
                                    </button>
                                );
                            })}
                        </div>
                    ))}
                </div>

                {/* Footer hint */}
                <div className="flex items-center justify-between px-4 py-2 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                    <div className="flex items-center gap-3 text-[10px] text-slate-400">
                        <span><kbd className="font-mono bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 px-1 rounded">↑↓</kbd> navigate</span>
                        <span><kbd className="font-mono bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 px-1 rounded">↵</kbd> open</span>
                        <span><kbd className="font-mono bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 px-1 rounded">Esc</kbd> close</span>
                    </div>
                    <div className="flex items-center gap-1 text-[10px] text-slate-400">
                        <Activity className="w-3 h-3" />
                        HexaGuard
                    </div>
                </div>
            </div>
        </div>
    );
};

export default CommandPalette;
