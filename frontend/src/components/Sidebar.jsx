import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Users, ScanLine, ScrollText, LayoutDashboard,
    LogOut, Settings, Clock, HelpCircle,
    Box, Globe, LayoutGrid, Crosshair, GraduationCap,
    CreditCard, Award, Flame, Compass, ShieldAlert,
    BookOpen, ChevronDown, ChevronRight, Bug, Target,
    FlaskConical, Search, FileText, Zap,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';

// ── Section grouping for the sidebar ──────────────────────────────────────────
// Each group has a label and an array of nav items.
// Items without a group key are shown in a flat "Other" section.

const Sidebar = () => {
    const { user, logout } = useAuth();
    const { pathname } = useLocation();
    const { lang, toggleLang, t } = useLang();
    const [isHovered, setIsHovered] = useState(false);
    const [expandedGroups, setExpandedGroups] = useState({
        learn: true,
        security: false,
        bounty: false,
        admin: false,
        other: false,
    });

    if (!user) return null;

    const toggleGroup = (key) => {
        if (!isHovered) return; // only interactive when expanded
        setExpandedGroups(prev => ({ ...prev, [key]: !prev[key] }));
    };

    const isAdmin = user.role === 'admin';

    // ── Nav groups definition ────────────────────────────────────────────────
    const NAV_GROUPS = [
        {
            key: 'main',
            label: null, // no header for main items
            items: [
                { labelKey: 'my_dashboard', descKey: 'dashboard_desc', to: '/dashboard', icon: LayoutDashboard },
            ],
        },
        {
            key: 'learn',
            label: 'Learn',
            items: [
                { labelKey: 'vuln_library',       descKey: 'vuln_library_desc',       to: '/learn/vulnerabilities', icon: BookOpen },
                { labelKey: 'manual_testing',     descKey: 'manual_testing_desc',      to: '/hunt/manual',           icon: Search },
                { labelKey: 'learning_tracks',    descKey: 'learning_tracks_desc',     to: '/tracks',                icon: Compass },
                { labelKey: 'skill_ledger',       descKey: 'skill_ledger_desc',        to: '/skills',                icon: Award },
                { labelKey: 'daily_dojo',         descKey: 'daily_dojo_desc',          to: '/dojo',                  icon: Flame },
                { labelKey: 'certification_prep', descKey: 'certification_prep_desc',  to: '/learn/certification',   icon: GraduationCap },
            ],
        },
        {
            key: 'security',
            label: 'Security Testing',
            items: [
                { labelKey: 'scanner_hub',       descKey: 'scanner_hub_desc',    to: '/scan',             icon: Zap },
                { labelKey: 'reports',           descKey: 'reports_desc',         to: '/reports',          icon: FileText },
                { labelKey: 'case_files',        descKey: 'case_files_desc',      to: '/casefiles',        icon: ShieldAlert },
                { labelKey: 'scheduled_scans',   descKey: 'scheduled_desc',       to: '/scheduled',        icon: Clock },
                { labelKey: 'docker_scan',       descKey: 'docker_scan_desc',     to: '/scan/docker',      icon: Box },
                { labelKey: 'dns_scan',          descKey: 'dns_scan_desc',        to: '/scan/dns',         icon: Globe },
                { labelKey: 'wordpress_scan',    descKey: 'wp_scan_desc',         to: '/scan/wordpress',   icon: LayoutGrid },
            ],
        },
        {
            key: 'bounty',
            label: 'Bug Bounty',
            show: import.meta.env.VITE_ENABLE_BOUNTY === 'true',
            items: [
                { labelKey: 'bounty_radar',       descKey: 'bounty_radar_desc',         to: '/admin/bounty-targets', icon: Target },
                { labelKey: 'manual_hunt_guide',  descKey: 'manual_hunt_desc',           to: '/hunt/manual',          icon: Crosshair },
            ],
        },
        {
            key: 'admin',
            label: 'Admin',
            adminOnly: true,
            items: [
                { labelKey: 'user_management',  descKey: 'user_mgmt_desc',    to: '/admin/users', icon: Users },
                { labelKey: 'scan_records',     descKey: 'scan_records_desc', to: '/admin/scans', icon: ScanLine },
                { labelKey: 'audit_log',        descKey: 'audit_log_desc',    to: '/audit',       icon: ScrollText },
            ],
        },
        {
            key: 'other',
            label: null,
            items: [
                { labelKey: 'pricing_plans',    descKey: 'pricing_desc',    to: '/pricing', icon: CreditCard },
                { labelKey: 'help',             descKey: 'help_desc',       to: '/help',    icon: HelpCircle },
                { labelKey: 'profile_settings', descKey: 'profile_desc',    to: '/profile', icon: Settings },
            ],
        },
    ];

    const ROLE_BADGE = {
        admin:   'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400',
        analyst: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400',
    };

    const isActive = (to) => {
        if (to === '/dashboard') return pathname === to;
        return pathname === to || pathname.startsWith(to + '/');
    };

    return (
        <aside
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            className={`
                relative flex flex-col flex-shrink-0 h-full
                bg-white dark:bg-slate-900
                border-r border-slate-200 dark:border-slate-800
                transition-all duration-300 ease-in-out z-30
                ${isHovered ? 'w-64 shadow-xl' : 'w-16'}
            `}
        >
            {/* Nav Items */}
            <nav className="flex-1 py-4 px-2 space-y-0.5 overflow-y-auto">
                {NAV_GROUPS.map((group) => {
                    // Skip admin groups for non-admins
                    if (group.adminOnly && !isAdmin) return null;
                    // Skip groups with show=false
                    if (group.show === false) return null;

                    const visibleItems = group.items.filter(item => {
                        // Legacy bounty-targets hidden when feature flag off
                        if (item.to === '/admin/bounty-targets' && import.meta.env.VITE_ENABLE_BOUNTY !== 'true') return false;
                        return true;
                    });

                    if (!visibleItems.length) return null;

                    const isExpanded = !group.label || expandedGroups[group.key];

                    return (
                        <div key={group.key} className="mb-1">
                            {/* Group Header */}
                            {group.label && isHovered && (
                                <button
                                    onClick={() => toggleGroup(group.key)}
                                    className="w-full flex items-center justify-between px-3 py-1.5 text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest hover:text-slate-600 dark:hover:text-slate-300 transition-colors rounded-md"
                                >
                                    <span>{group.label}</span>
                                    {isExpanded
                                        ? <ChevronDown className="w-3 h-3" />
                                        : <ChevronRight className="w-3 h-3" />
                                    }
                                </button>
                            )}
                            {/* Group separator line when collapsed */}
                            {group.label && !isHovered && (
                                <div className="mx-3 my-2 border-t border-slate-100 dark:border-slate-800" />
                            )}

                            {/* Items */}
                            {(isExpanded || !group.label) && visibleItems.map(item => {
                                const Icon = item.icon;
                                const active = isActive(item.to);

                                return (
                                    <Link
                                        key={item.to + item.labelKey}
                                        to={item.to}
                                        title={!isHovered ? t(item.labelKey) : undefined}
                                        className={`
                                            group flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-150
                                            ${!isHovered ? 'justify-center' : ''}
                                            ${active
                                                ? 'bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-300'
                                                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-slate-100'
                                            }
                                        `}
                                    >
                                        <div className={`
                                            flex-shrink-0 p-1.5 rounded-md transition-colors
                                            ${active
                                                ? 'bg-primary-100 dark:bg-primary-500/20 text-primary-600 dark:text-primary-400'
                                                : 'bg-slate-100 dark:bg-slate-800 text-slate-500 group-hover:bg-slate-200 dark:group-hover:bg-slate-700'
                                            }
                                        `}>
                                            <Icon className="w-3.5 h-3.5" />
                                        </div>

                                        <div
                                            className={`
                                                min-w-0 flex-1 transition-all duration-300
                                                ${isHovered ? 'opacity-100 max-w-full' : 'opacity-0 max-w-0 overflow-hidden pointer-events-none'}
                                            `}
                                        >
                                            <div className="text-sm font-semibold leading-tight truncate">{t(item.labelKey)}</div>
                                            {item.descKey && (
                                                <div className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 leading-tight truncate">{t(item.descKey)}</div>
                                            )}
                                        </div>
                                    </Link>
                                );
                            })}
                        </div>
                    );
                })}
            </nav>

            {/* Footer */}
            <div className="flex-shrink-0 border-t border-slate-200 dark:border-slate-800 p-3 space-y-3">
                {/* User info */}
                <div className="flex items-center gap-2.5 px-2 py-2 rounded-lg bg-slate-50 dark:bg-slate-800/60">
                    <div
                        className="w-7 h-7 rounded-full bg-primary-100 dark:bg-primary-900/50 flex items-center justify-center flex-shrink-0"
                        title={!isHovered ? `${user.username} (${user.role})` : undefined}
                    >
                        <span className="text-xs font-bold text-primary-600 dark:text-primary-400 uppercase">
                            {user.username?.[0]}
                        </span>
                    </div>
                    <div
                        className={`
                            min-w-0 flex-1 transition-all duration-300
                            ${isHovered ? 'opacity-100 max-w-full' : 'opacity-0 max-w-0 overflow-hidden'}
                        `}
                    >
                        <div className="text-xs font-semibold text-slate-800 dark:text-slate-200 truncate">{user.username}</div>
                        <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded capitalize ${ROLE_BADGE[user.role] || ROLE_BADGE.analyst}`}>
                            {user.role}
                        </span>
                    </div>
                </div>

                {/* AR / EN toggle + logout */}
                <div className={`flex items-center gap-1.5 ${isHovered ? 'flex-row' : 'flex-col'}`}>
                    <button
                        onClick={toggleLang}
                        title={lang === 'en' ? t('switch_to_arabic') : t('switch_to_english')}
                        className={`flex items-center justify-center font-semibold text-[11px] border rounded-md transition-all
                            text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700
                            hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200
                            ${isHovered ? 'flex-1 py-1.5' : 'w-8 h-8'}`}
                    >
                        {lang === 'en' ? 'AR' : 'EN'}
                    </button>

                    <button
                        onClick={logout}
                        title={t('sign_out')}
                        className={`flex items-center justify-center gap-1.5 rounded-md transition-all text-xs font-semibold
                            text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 border border-transparent hover:border-red-200 dark:hover:border-red-500/20
                            ${isHovered ? 'flex-1 py-1.5' : 'w-8 h-8'}`}
                    >
                        <LogOut className="w-3.5 h-3.5" />
                        {isHovered && <span className="transition-opacity duration-300">{t('sign_out')}</span>}
                    </button>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
