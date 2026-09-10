import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
    HelpCircle, Globe, Server, Zap, Lock, Settings,
    Package, Layers, ChevronDown, BookOpen, Shield,
    Clock, FileText, BarChart2, MessageSquare, Key,
    GraduationCap, Crosshair, Award, CheckCircle2, Target,
    Sparkles, ShieldCheck, Terminal, Compass,
} from 'lucide-react';
import AssessmentMethodologyBanner from '../components/AssessmentMethodologyBanner';

const METRICS = [
    { label: 'Automated Tests', value: '286+ Passing', sub: '100% Pass Rate', color: 'text-emerald-400', bg: 'bg-emerald-500/10' },
    { label: 'Curriculum Topics', value: '68 Topics', sub: '58 Offensive · 10 Incidents', color: 'text-cyan-400', bg: 'bg-cyan-500/10' },
    { label: 'Specialized Scanners', value: '11 Engines', sub: 'DAST, SAST, Network, SSL, Docker', color: 'text-purple-400', bg: 'bg-purple-500/10' },
    { label: 'Canonical Taxonomy', value: '15 Vuln Classes', sub: 'SSoT Ground Truth Invariant', color: 'text-amber-400', bg: 'bg-amber-500/10' },
];

const ROADMAP_TRACKS = [
    {
        id: 'bug-bounty-hunter',
        name: 'Bug Bounty Hunter Track',
        nameAr: 'صائد الثغرات (Red Team)',
        icon: Crosshair,
        color: 'text-orange-400',
        bg: 'bg-orange-500/10',
        border: 'border-orange-500/30',
        summary: 'End-to-end path from passive reconnaissance and wildcard enumeration to professional PoC reporting and reward optimization.',
        pillars: ['Encyclopedia & Methodology', 'Wildcard Recon & crt.sh Probing', 'Adversarial Twin Sandbox Labs', 'Live Bug Bounty Learn+Earn Bridge'],
        link: '/tracks',
    },
    {
        id: 'soc-analyst',
        name: 'SOC Analyst / Blue Team Track',
        nameAr: 'محلل مركز العمليات الأمنية (Blue Team)',
        icon: ShieldCheck,
        color: 'text-blue-400',
        bg: 'bg-blue-500/10',
        border: 'border-blue-500/30',
        summary: 'Defensive incident response, SIEM triage, MITRE ATT&CK mapping, and realistic SOC forensic investigation case files.',
        pillars: ['Log & Traffic Forensics', 'MITRE ATT&CK Matrix Mapping', 'Socratic Evidence Evaluation', 'Defensive Incident Case Files'],
        link: '/casefiles',
    },
    {
        id: 'cert-readiness',
        name: 'eJPT & OSCP Certification Readiness',
        nameAr: 'مؤشر الجاهزية للشهادات الاحترافية',
        icon: Award,
        color: 'text-emerald-400',
        bg: 'bg-emerald-500/10',
        border: 'border-emerald-500/30',
        summary: 'Personalized readiness index computed deterministically from verified skill coverage across industry-standard certification domains.',
        pillars: ['Skill Ledger Verification', 'Domain Coverage Radar', 'Hands-on Practice Flags', 'Readiness Radar Breakdown'],
        link: '/tracks',
    },
];

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
        q: 'What is Module 0: Universal Assessment Methodology?',
        a: 'Module 0 provides the standard 7-phase methodology (Scope -> Passive OSINT -> Active Recon -> Engine Selection -> Vulnerability Confirmation -> Triaging & Prioritization -> Verified Reporting) for structuring professional security assessments and deciding which scanner engines to deploy.',
    },
    {
        q: 'How does HexaGuard select lessons and practice challenges?',
        a: 'The platform employs an adaptive gap-prioritization algorithm. Instead of static linear syllabi, the Micro-Dojo and Learning Compass analyze your Skill Ledger. If you have mastered SQLi but have unverified gaps in SSRF or Broken Auth, daily exercises, shadow backlog tasks, and recommended bug bounty targets automatically surface those exact vulnerabilities first.',
    },
    {
        q: 'Why does reading a lesson only award "theory_only" status?',
        a: 'To guarantee real competence and eliminate fake progress, HexaGuard enforces an anti-self-reporting gate. Reading encyclopedia entries or watching guides gives "theory_only". To earn "practiced_verified", you must exploit an isolated target in the Adversarial Twin Sandbox and submit the cryptographic proof flag.',
    },
    {
        q: 'How does the Learn+Earn Bug Bounty composite score work?',
        a: 'The Learn+Earn formula balances legal permission (automation factor), financial reward (payout factor), and personal skill synergy. Targets matching vulnerabilities where you have verified competence receive a synergy boost, while targets offering practice in your skill gaps are prioritized for training.',
    },
    {
        q: 'How do background scans work?',
        a: 'Toggle "Run in Background" on any scan page before starting. The scan runs in the background while you navigate — the floating widget at the bottom-right shows progress. You\'ll get a browser notification when it completes.',
    },
    {
        q: 'What are scheduled scans?',
        a: 'Go to Scheduled Scans to set up recurring scans (daily, weekly, monthly). SecuraX will automatically run the scan and save the results in your Reports. You\'ll be notified on completion.',
    },
    {
        q: 'How is my risk score calculated?',
        a: 'The risk score (0–10) uses a weighted formula: critical findings have the highest weight, with logarithmic decay for duplicate findings. Internet-facing assets and high-impact vulnerability types (RCE, SQLi) receive score boosts, integrated with live EPSS threat intelligence from FIRST.org.',
    },
    {
        q: 'Is my data stored securely?',
        a: 'Yes — scan results are stored in an encrypted SQLite database on the server. Passwords use bcrypt hashing. Sessions are HTTPOnly, and all API calls require CSRF tokens. If AI data-sharing opt-out is enabled, zero telemetry or scan findings are ever transmitted to external AI endpoints.',
    },
    {
        q: 'What is ARIA?',
        a: 'ARIA is the built-in AI security assistant and Socratic red-team mentor. When asked for guidance, it provides hints, questions, and methodology without spoiling direct flag answers unless explicitly requested.',
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
        <div className="space-y-10 animate-in fade-in duration-500 max-w-4xl mx-auto pb-12">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <BookOpen className="w-6 h-6 text-cyan-500" />
                    Help, Architecture & Learning Roadmap
                </h1>
                <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
                    Complete reference for SecuraX / HexaGuard: scanning engines, adaptive learning methodology, and real metrics.
                </p>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {METRICS.map((m) => (
                    <div key={m.label} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                        <div className="text-xs text-slate-400 font-medium">{m.label}</div>
                        <div className={`text-xl font-bold mt-1 ${m.color}`}>{m.value}</div>
                        <div className="text-[11px] text-slate-500 mt-1">{m.sub}</div>
                    </div>
                ))}
            </div>

            {/* Assessment Methodology Primer */}
            <div>
                <AssessmentMethodologyBanner />
            </div>

            {/* Quick links */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                    { icon: Compass,      label: 'Learning Tracks', to: '/tracks'     },
                    { icon: ShieldCheck,  label: 'Case Files',    to: '/casefiles'  },
                    { icon: Crosshair,    label: 'Bounty Radar',  to: '/bounty'     },
                    { icon: MessageSquare,label: 'Ask ARIA',      to: '/chat'       },
                ].map((item) => {
                    const Icon = item.icon;
                    return (
                        <Link
                            key={item.label}
                            to={item.to}
                            className="flex flex-col items-center gap-2 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 text-xs font-medium hover:border-cyan-400 hover:text-cyan-600 dark:hover:text-cyan-400 transition-all shadow-sm"
                        >
                            <Icon className="w-5 h-5 text-cyan-500" />
                            {item.label}
                        </Link>
                    );
                })}
            </div>

            {/* COMPASS OS: Adaptive Learning Methodology */}
            <section className="bg-gradient-to-br from-purple-950/20 via-slate-900 to-indigo-950/20 border border-purple-500/25 rounded-2xl p-6 space-y-4">
                <div className="flex items-center gap-2">
                    <Sparkles className="w-5 h-5 text-purple-400" />
                    <h2 className="text-lg font-bold text-white">HexaGuard COMPASS OS — Adaptive Learning Methodology</h2>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed">
                    HexaGuard bridges offensive reconnaissance, automated vulnerability scanning, and personalized education into an integrated, closed-loop ecosystem:
                </p>
                <div className="grid md:grid-cols-3 gap-4 pt-2">
                    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
                        <div className="text-xs font-bold text-purple-300 flex items-center gap-1.5">
                            <Target className="w-4 h-4 text-purple-400" /> 1. SSoT Taxonomy
                        </div>
                        <p className="text-xs text-slate-400">
                            15 canonical vulnerability classes defined across all datasets, benchmark ground truth, and scanning engines. Zero fragmented terminology.
                        </p>
                    </div>
                    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
                        <div className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                            <Shield className="w-4 h-4 text-cyan-400" /> 2. Proof-Gated Ledger
                        </div>
                        <p className="text-xs text-slate-400">
                            Progress requires verifiable hands-on demonstration. Self-reporting is capped at <code className="text-yellow-400">theory_only</code>; verification requires sandbox flags.
                        </p>
                    </div>
                    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 space-y-2">
                        <div className="text-xs font-bold text-emerald-300 flex items-center gap-1.5">
                            <Zap className="w-4 h-4 text-emerald-400" /> 3. Learn+Earn Synergy
                        </div>
                        <p className="text-xs text-slate-400">
                            Live bug bounty scopes are matched bidirectionally with training labs. Master skills in local sandboxes, then hunt matching live targets.
                        </p>
                    </div>
                </div>
            </section>

            {/* Learning Roadmap Tracks */}
            <section className="space-y-4">
                <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <GraduationCap className="w-5 h-5 text-indigo-400" /> Structured Learning Roadmap
                    </h2>
                    <Link to="/tracks" className="text-xs text-cyan-400 hover:underline">Explore All Tracks →</Link>
                </div>
                <div className="space-y-3">
                    {ROADMAP_TRACKS.map((t) => {
                        const Icon = t.icon;
                        return (
                            <div key={t.id} className={`bg-white dark:bg-slate-900 border ${t.border} rounded-xl p-5 shadow-sm`}>
                                <div className="flex items-start gap-4">
                                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 ${t.bg}`}>
                                        <Icon className={`w-5 h-5 ${t.color}`} />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                                            <h3 className="text-sm font-bold text-slate-900 dark:text-white">{t.name}</h3>
                                            <span className="text-xs text-slate-400">({t.nameAr})</span>
                                            <Link to={t.link} className="text-xs text-cyan-500 hover:underline ml-auto">View Track →</Link>
                                        </div>
                                        <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">{t.summary}</p>
                                        <div className="flex flex-wrap gap-2">
                                            {t.pillars.map((p) => (
                                                <span key={p} className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                                                    <CheckCircle2 className="w-3 h-3 text-cyan-400" /> {p}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </section>

            {/* Scan type guide */}
            <section id="scans">
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Scanning Engines (11 Core Modules)</h2>
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
                <h3 className="font-semibold text-slate-900 dark:text-white mb-1">Need more guidance?</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-3">
                    Ask ARIA Socratic Red-Team Mentor, or reach out to the HexaGuard team.
                </p>
                <div className="flex gap-3 justify-center flex-wrap">
                    <Link
                        to="/chat"
                        className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-semibold transition-colors"
                    >
                        Ask ARIA
                    </Link>
                    <a
                        href="mailto:Abdallahbenaichatech@gmail.com"
                        className="px-4 py-2 rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-sm font-medium hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                    >
                        Contact Support
                    </a>
                </div>
            </section>
        </div>
    );
}
