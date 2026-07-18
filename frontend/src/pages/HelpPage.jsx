import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
    HelpCircle, Globe, Server, Zap, Lock, Settings,
    Package, Layers, ChevronDown, BookOpen, Shield,
    Clock, FileText, BarChart2, MessageSquare, Key,
} from 'lucide-react';

const SCANS = [
    {
        icon: Globe, color: 'text-indigo-500', bg: 'bg-indigo-500/10',
        title: 'Web Vulnerability Scan',
        to: '/scan/web',
        desc: 'Tests public-facing web applications for OWASP Top 10 issues: SQL injection, XSS, CSRF, open redirects, insecure headers, and more.',
        tips: ['Use QUICK mode for a fast overview', 'Use DEEP mode for thorough testing', 'Background mode lets you navigate while scanning'],
    },
    {
        icon: Server, color: 'text-blue-500', bg: 'bg-blue-500/10',
        title: 'Network Scan',
        to: '/scan/network',
        desc: 'Discovers open ports, running services, OS fingerprints, and known CVEs on a given IP address or hostname.',
        tips: ['External: scans from outside the network', 'Internal: scans from inside (enter LAN IP)'],
    },
    {
        icon: Zap, color: 'text-orange-500', bg: 'bg-orange-500/10',
        title: 'DAST (Dynamic Application Security Testing)',
        to: '/scan/dast',
        desc: 'Actively interacts with a running web application to find vulnerabilities that static analysis misses — runtime injection, auth bypass, and session flaws.',
        tips: ['Only test applications you own or have permission to test', 'Best run against staging environments'],
    },
    {
        icon: Lock, color: 'text-emerald-500', bg: 'bg-emerald-500/10',
        title: 'SSL / TLS Analysis',
        to: '/scan/ssl',
        desc: 'Checks certificate validity, expiry, cipher suites, protocol versions (TLS 1.0/1.1 detection), HSTS, and known SSL vulnerabilities (BEAST, POODLE, Heartbleed).',
        tips: ['Enter just the hostname — no https://', 'Set up alerts before certificates expire'],
    },
    {
        icon: Settings, color: 'text-slate-500', bg: 'bg-slate-500/10',
        title: 'Server Configuration Audit',
        to: '/scan/apache',
        desc: 'Reviews Apache / Nginx / server configuration files for insecure directives, exposed sensitive files, missing security headers, and misconfigurations.',
        tips: ['Upload your config file (no secrets are stored)', 'Or scan a live server URL'],
    },
    {
        icon: Layers, color: 'text-purple-500', bg: 'bg-purple-500/10',
        title: 'Code / SAST Scan',
        to: '/scan/code',
        desc: 'Static analysis of source code — detects hardcoded secrets, SQL injection patterns, unsafe eval(), insecure deserialization, and more across Python, JS, PHP, and Java.',
        tips: ['Upload a ZIP of your source code', 'Results show exact file and line numbers'],
    },
    {
        icon: Package, color: 'text-yellow-500', bg: 'bg-yellow-500/10',
        title: 'Dependency Scanner',
        to: '/scan/dependencies',
        desc: 'Checks your project\'s dependencies (requirements.txt, package.json, pom.xml) against known CVE databases to find vulnerable packages.',
        tips: ['Upload your dependency manifest file', 'Update flagged packages immediately — most fixes are a version bump'],
    },
];

const FAQS = [
    {
        q: 'How do background scans work?',
        a: 'Toggle "Run in Background" on any scan page before starting. The scan runs in the background while you navigate — the floating widget at the bottom-right shows progress. You\'ll get a browser notification when it completes.',
    },
    {
        q: 'What are scheduled scans?',
        a: 'Go to Scheduled Scans to set up recurring scans (daily, weekly, monthly). HexaGuard will automatically run the scan and save the results in your Reports. You\'ll be notified on completion.',
    },
    {
        q: 'How is my risk score calculated?',
        a: 'The risk score (0–10) uses a weighted formula: critical findings have the highest weight, with logarithmic decay for duplicate findings. Internet-facing assets and high-impact vulnerability types (RCE, SQLi) receive score boosts.',
    },
    {
        q: 'Can I be restricted to a single target?',
        a: 'Yes — admins can lock analyst accounts to a specific target (hostname/IP). Analysts can only scan that approved target. Contact your admin to change the assignment.',
    },
    {
        q: 'How do I export a report as PDF?',
        a: 'Open any scan report from Reports → click the Download PDF button at the top right of the report detail page.',
    },
    {
        q: 'Is my data stored securely?',
        a: 'Yes — scan results are stored in an encrypted SQLite database on the server. Passwords use bcrypt hashing. Sessions are HTTPOnly, and all API calls require CSRF tokens.',
    },
    {
        q: 'What is ARIA?',
        a: 'ARIA is the built-in AI security assistant. Ask it questions about vulnerabilities in your reports, remediation steps, or general security guidance — in Arabic or English.',
    },
];

function FaqItem({ q, a }) {
    const [open, setOpen] = useState(false);
    return (
        <div className="border-b border-slate-100 dark:border-slate-800 last:border-0">
            <button
                onClick={() => setOpen(v => !v)}
                className="w-full flex items-center justify-between py-4 text-left group"
                aria-expanded={open}
            >
                <span className="text-sm font-medium text-slate-800 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors pr-4">
                    {q}
                </span>
                <ChevronDown className={`w-4 h-4 flex-shrink-0 text-slate-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
            </button>
            <AnimatePresence>
                {open && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <p className="pb-4 text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{a}</p>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

export default function HelpPage() {
    return (
        <div className="space-y-10 animate-in fade-in duration-500 max-w-3xl">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <BookOpen className="w-6 h-6 text-cyan-500" />
                    Help & Documentation
                </h1>
                <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
                    Everything you need to get the most out of HexaGuard.
                </p>
            </div>

            {/* Quick links */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                    { icon: Shield,       label: 'Scan Types',    href: '#scans'     },
                    { icon: Clock,        label: 'Scheduling',    href: '#faq'       },
                    { icon: BarChart2,    label: 'Dashboard',     to: '/dashboard'   },
                    { icon: MessageSquare,label: 'Ask ARIA',      to: '/chat'        },
                ].map((item) => {
                    const Icon = item.icon;
                    const cls = 'flex flex-col items-center gap-2 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 text-xs font-medium hover:border-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-all';
                    if (item.to) {
                        return <Link key={item.label} to={item.to} className={cls}><Icon className="w-5 h-5" />{item.label}</Link>;
                    }
                    return <a key={item.label} href={item.href} className={cls}><Icon className="w-5 h-5" />{item.label}</a>;
                })}
            </div>

            {/* Scan type guide */}
            <section id="scans">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Scan Types</h2>
                <div className="space-y-3">
                    {SCANS.map((s) => {
                        const Icon = s.icon;
                        return (
                            <div key={s.title} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm">
                                <div className="flex items-start gap-4">
                                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${s.bg}`}>
                                        <Icon className={`w-5 h-5 ${s.color}`} />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{s.title}</h3>
                                            <Link to={s.to} className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline">Launch →</Link>
                                        </div>
                                        <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">{s.desc}</p>
                                        <ul className="space-y-0.5">
                                            {s.tips.map((tip) => (
                                                <li key={tip} className="text-xs text-slate-400 flex items-start gap-1.5">
                                                    <span className="text-cyan-400 mt-0.5">·</span> {tip}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </section>

            {/* FAQ */}
            <section id="faq">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                    <HelpCircle className="w-5 h-5 text-slate-400" /> Frequently Asked Questions
                </h2>
                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl px-6 shadow-sm">
                    {FAQS.map((faq) => <FaqItem key={faq.q} {...faq} />)}
                </div>
            </section>

            {/* Contact */}
            <section className="bg-gradient-to-br from-cyan-500/10 to-purple-500/10 border border-cyan-200 dark:border-cyan-500/20 rounded-2xl p-6 text-center">
                <Key className="w-8 h-8 text-cyan-500 mx-auto mb-3" />
                <h3 className="font-semibold text-slate-900 dark:text-white mb-1">Need more help?</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">
                    Ask the AI assistant, or contact the HexaGuard team.
                </p>
                <div className="flex gap-3 justify-center flex-wrap">
                    <Link
                        to="/chat"
                        className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-semibold transition-colors"
                    >
                        Ask ARIA
                    </Link>
                    <a
                        href="mailto:innovation.team.dz@gmail.com"
                        className="px-4 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm font-medium hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                        Contact Support
                    </a>
                </div>
            </section>
        </div>
    );
}
