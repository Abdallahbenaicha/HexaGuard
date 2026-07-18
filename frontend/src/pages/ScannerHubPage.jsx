import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
    Globe, Lock, Network, Zap, Layers, FileSearch,
    Shield, Package, Box, Mail, LayoutGrid,
    ChevronRight, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';

// ── Scanner catalogue ──────────────────────────────────────────────────────────
const SCANNER_GROUPS = [
    {
        groupLabel: 'Web & Application',
        groupLabelAr: 'الويب والتطبيقات',
        color: 'blue',
        scanners: [
            {
                slug: 'web', to: '/scan/web',
                label: 'Web Application Scan', labelAr: 'فحص تطبيقات الويب',
                desc:  'OWASP Top 10, injection, XSS, authentication flaws, misconfigurations.',
                descAr: 'OWASP Top 10، حقن SQL/XSS، ثغرات المصادقة والإعدادات.',
                icon: Globe,
                tags: ['OWASP', 'XSS', 'SQLi'],
            },
            {
                slug: 'dast', to: '/scan/dast',
                label: 'Dynamic Analysis (DAST)', labelAr: 'التحليل الديناميكي',
                desc:  'Runtime black-box testing — probe a live application for real vulnerabilities.',
                descAr: 'اختبار أسود حي — كشف ثغرات التطبيق أثناء تشغيله.',
                icon: Zap,
                tags: ['Runtime', 'Black-box'],
            },
            {
                slug: 'wordpress', to: '/scan/wordpress',
                label: 'WordPress Audit', labelAr: 'فحص ووردبريس',
                desc:  'Version disclosure, xmlrpc, user enum, debug logs, security headers.',
                descAr: 'كشف الإصدار، xmlrpc، تعداد المستخدمين، سجلات التصحيح.',
                icon: LayoutGrid,
                tags: ['CMS', 'WP'],
            },
            {
                slug: 'deps', to: '/scan/dependencies',
                label: 'Dependency Check', labelAr: 'فحص التبعيات',
                desc:  'Supply chain CVE scan — detect vulnerable npm, pip, composer packages.',
                descAr: 'فحص CVE لسلسلة التوريد — اكتشاف الحزم المعرضة للخطر.',
                icon: Package,
                tags: ['CVE', 'Supply chain'],
            },
        ],
    },
    {
        groupLabel: 'Server & Infrastructure',
        groupLabelAr: 'الخوادم والبنية التحتية',
        color: 'purple',
        scanners: [
            {
                slug: 'network', to: '/scan/network',
                label: 'Network Recon', labelAr: 'استطلاع الشبكة',
                desc:  'Port scan, service detection, OS fingerprinting, banner grabbing.',
                descAr: 'مسح المنافذ، اكتشاف الخدمات، بصمة نظام التشغيل.',
                icon: Network,
                tags: ['Nmap', 'Ports'],
            },
            {
                slug: 'ssl', to: '/scan/ssl',
                label: 'SSL/TLS Audit', labelAr: 'فحص SSL/TLS',
                desc:  'Certificate validity, weak ciphers, protocol downgrades, HSTS.',
                descAr: 'صلاحية الشهادة، تشفير ضعيف، تخفيض البروتوكول، HSTS.',
                icon: Lock,
                tags: ['TLS', 'Certs'],
            },
            {
                slug: 'server', to: '/scan/server-ext',
                label: 'Server Audit', labelAr: 'فحص الخادم',
                desc:  'External probe — headers, version disclosure, security posture.',
                descAr: 'فحص خارجي — الترويسات، كشف الإصدار، وضعية الأمان.',
                icon: Shield,
                tags: ['Headers', 'External'],
            },
            {
                slug: 'dns', to: '/scan/dns',
                label: 'DNS & Email Security', labelAr: 'أمان DNS والبريد',
                desc:  'SPF, DMARC, DKIM, DNSSEC, CAA, zone transfer, MX security.',
                descAr: 'SPF، DMARC، DKIM، DNSSEC، CAA، نقل المنطقة.',
                icon: Mail,
                tags: ['SPF', 'DMARC', 'DNSSEC'],
            },
        ],
    },
    {
        groupLabel: 'Code & Configuration',
        groupLabelAr: 'الكود والإعدادات',
        color: 'emerald',
        scanners: [
            {
                slug: 'code', to: '/scan/code',
                label: 'Code Audit (SAST)', labelAr: 'تحليل الكود الثابت',
                desc:  'Static analysis — detect hardcoded secrets, injection sinks, unsafe patterns.',
                descAr: 'تحليل ثابت — كلمات مرور مخفية، نقاط حقن، أنماط غير آمنة.',
                icon: Layers,
                tags: ['SAST', 'Secrets'],
            },
            {
                slug: 'config', to: '/scan/apache',
                label: 'Config Audit', labelAr: 'فحص الإعدادات',
                desc:  'Apache/Nginx config review — misconfigs, directory listing, unsafe directives.',
                descAr: 'مراجعة إعدادات Apache/Nginx — تهيئة خاطئة، قوائم المجلدات.',
                icon: FileSearch,
                tags: ['Apache', 'Nginx'],
            },
            {
                slug: 'docker', to: '/scan/docker',
                label: 'Docker Security', labelAr: 'أمان Docker',
                desc:  'Dockerfile & compose audit — root containers, exposed secrets, privileged mode.',
                descAr: 'فحص Dockerfile وcompose — حاويات root، أسرار مكشوفة، وضع مميز.',
                icon: Box,
                tags: ['Containers', 'DevOps'],
            },
        ],
    },
];

const COLOR = {
    blue:    { ring: 'ring-blue-500/30',    bg: 'bg-blue-500/10',    text: 'text-blue-400',    badge: 'bg-blue-500/10 text-blue-400'    },
    purple:  { ring: 'ring-purple-500/30',  bg: 'bg-purple-500/10',  text: 'text-purple-400',  badge: 'bg-purple-500/10 text-purple-400'  },
    emerald: { ring: 'ring-emerald-500/30', bg: 'bg-emerald-500/10', text: 'text-emerald-400', badge: 'bg-emerald-500/10 text-emerald-400' },
};

function ScannerCard({ scanner, locked, color }) {
    const { lang } = useLang();
    const Icon = scanner.icon;
    const c    = COLOR[color];
    const label = lang === 'ar' ? scanner.labelAr : scanner.label;
    const desc  = lang === 'ar' ? scanner.descAr  : scanner.desc;

    if (locked) {
        return (
            <div className="relative group rounded-xl border border-slate-700/50 bg-slate-800/40 p-5 opacity-60 cursor-not-allowed select-none overflow-hidden">
                {/* Lock overlay */}
                <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-900/80 backdrop-blur-sm rounded-xl z-10 opacity-0 group-hover:opacity-100 transition-all duration-200">
                    <Lock className="w-8 h-8 text-slate-400 mb-2" />
                    <p className="text-xs text-slate-300 font-medium text-center px-4">
                        {lang === 'ar' ? 'غير مفعّل في خطتك' : 'Not in your plan'}
                    </p>
                    <p className="text-[10px] text-slate-500 mt-1 text-center px-4">
                        {lang === 'ar' ? 'تواصل مع المدير لتفعيله' : 'Contact admin to enable'}
                    </p>
                </div>
                <div className={`w-9 h-9 rounded-lg ${c.bg} flex items-center justify-center mb-3`}>
                    <Icon className={`w-4.5 h-4.5 ${c.text}`} />
                </div>
                <h3 className="text-sm font-semibold text-slate-300 mb-1">{label}</h3>
                <p className="text-xs text-slate-500 leading-relaxed line-clamp-2">{desc}</p>
                <div className="flex flex-wrap gap-1 mt-3">
                    {scanner.tags.map(t => (
                        <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-500">{t}</span>
                    ))}
                </div>
            </div>
        );
    }

    return (
        <Link to={scanner.to} className="block group">
            <motion.div
                whileHover={{ y: -2, scale: 1.01 }}
                transition={{ duration: 0.15 }}
                className={`relative rounded-xl border border-slate-700/50 bg-slate-800/60 p-5 h-full
                    hover:border-slate-600 hover:bg-slate-800 hover:ring-1 ${c.ring}
                    transition-all duration-200 cursor-pointer overflow-hidden`}
            >
                {/* Subtle gradient glow */}
                <div className={`absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${c.bg} blur-xl scale-150`} />

                <div className="relative z-10">
                    <div className="flex items-start justify-between mb-3">
                        <div className={`w-9 h-9 rounded-lg ${c.bg} flex items-center justify-center`}>
                            <Icon className={`w-4.5 h-4.5 ${c.text}`} />
                        </div>
                        <ChevronRight className={`w-4 h-4 text-slate-600 group-hover:${c.text} group-hover:translate-x-0.5 transition-all`} />
                    </div>
                    <h3 className="text-sm font-semibold text-slate-100 mb-1.5 group-hover:text-white">{label}</h3>
                    <p className="text-xs text-slate-400 leading-relaxed line-clamp-2 group-hover:text-slate-300">{desc}</p>
                    <div className="flex flex-wrap gap-1 mt-3">
                        {scanner.tags.map(t => (
                            <span key={t} className={`text-[10px] px-1.5 py-0.5 rounded ${c.badge} font-medium`}>{t}</span>
                        ))}
                    </div>
                </div>
            </motion.div>
        </Link>
    );
}

export default function ScannerHubPage() {
    const { user } = useAuth();
    const { lang } = useLang();
    const isAdmin  = user?.role === 'admin';

    // null = unrestricted; list = whitelist
    const allowed = user?.allowed_scanners ?? null;

    const canUse = (slug) => {
        if (isAdmin) return true;
        if (allowed === null) return true;
        return allowed.includes(slug);
    };

    const totalScanners  = SCANNER_GROUPS.flatMap(g => g.scanners).length;
    const unlockedCount  = SCANNER_GROUPS.flatMap(g => g.scanners).filter(s => canUse(s.slug)).length;

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100">
            <div className="max-w-6xl mx-auto px-4 py-10">

                {/* Header */}
                <motion.div
                    initial={{ opacity: 0, y: -12 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35 }}
                    className="mb-10"
                >
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-primary-500/10 flex items-center justify-center">
                            <ShieldAlert className="w-5 h-5 text-primary-400" />
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold text-white">
                                {lang === 'ar' ? 'مركز الفاحصات' : 'Scanner Hub'}
                            </h1>
                            <p className="text-sm text-slate-400">
                                {lang === 'ar'
                                    ? `${unlockedCount} فاحص متاح من أصل ${totalScanners}`
                                    : `${unlockedCount} of ${totalScanners} scanners available`}
                            </p>
                        </div>
                    </div>

                    {/* Access summary bar */}
                    <div className={`mt-4 flex items-center gap-2.5 px-4 py-2.5 rounded-lg text-sm
                        ${isAdmin || allowed === null
                            ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-300'
                            : 'bg-amber-500/10 border border-amber-500/20 text-amber-300'
                        }`}>
                        {isAdmin || allowed === null
                            ? <ShieldCheck className="w-4 h-4 flex-shrink-0" />
                            : <ShieldAlert className="w-4 h-4 flex-shrink-0" />
                        }
                        <span>
                            {isAdmin
                                ? (lang === 'ar' ? 'مدير — وصول كامل لجميع الفاحصات' : 'Admin — full access to all scanners')
                                : allowed === null
                                    ? (lang === 'ar' ? 'وصول غير مقيد' : 'Unrestricted access')
                                    : (lang === 'ar'
                                        ? `خطتك تتضمن ${unlockedCount} فاحص${unlockedCount !== totalScanners ? ` — تواصل مع المدير لإضافة المزيد` : ''}`
                                        : `Your plan includes ${unlockedCount} scanner${unlockedCount !== totalScanners ? ' — contact admin for more' : 's'}`
                                    )
                            }
                        </span>
                    </div>
                </motion.div>

                {/* Groups */}
                {SCANNER_GROUPS.map((group, gi) => (
                    <motion.section
                        key={group.groupLabel}
                        initial={{ opacity: 0, y: 16 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: gi * 0.08, duration: 0.3 }}
                        className="mb-10"
                    >
                        <div className="flex items-center gap-2 mb-4">
                            <div className={`h-px flex-1 ${COLOR[group.color].bg}`} />
                            <h2 className={`text-xs font-semibold uppercase tracking-widest ${COLOR[group.color].text}`}>
                                {lang === 'ar' ? group.groupLabelAr : group.groupLabel}
                            </h2>
                            <div className={`h-px flex-1 ${COLOR[group.color].bg}`} />
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                            {group.scanners.map((scanner) => (
                                <ScannerCard
                                    key={scanner.slug}
                                    scanner={scanner}
                                    locked={!canUse(scanner.slug)}
                                    color={group.color}
                                />
                            ))}
                        </div>
                    </motion.section>
                ))}
            </div>
        </div>
    );
}
