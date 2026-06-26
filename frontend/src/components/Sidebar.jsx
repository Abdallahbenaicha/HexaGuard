import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Users, ScanLine, ScrollText, LayoutDashboard,
    LogOut, Settings, Clock, HelpCircle,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';

const Sidebar = () => {
    const { user, logout } = useAuth();
    const { pathname } = useLocation();
    const { lang, toggleLang, t } = useLang();
    const [isHovered, setIsHovered] = useState(false);

    if (!user) return null;

    const ADMIN_NAV = [
        { labelKey: 'user_management', descKey: 'user_mgmt_desc',   to: '/admin/users', icon: Users,          adminOnly: true  },
        { labelKey: 'scan_records',    descKey: 'scan_records_desc', to: '/admin/scans', icon: ScanLine,       adminOnly: true  },
        { labelKey: 'audit_log',       descKey: 'audit_log_desc',    to: '/audit',       icon: ScrollText,     adminOnly: true  },
        { labelKey: 'my_dashboard',    descKey: 'dashboard_desc',    to: '/dashboard',   icon: LayoutDashboard,adminOnly: false },
        { labelKey: 'scheduled_scans', descKey: 'scheduled_desc',    to: '/scheduled',   icon: Clock,          adminOnly: false },
        { labelKey: 'help',            descKey: 'help_desc',         to: '/help',        icon: HelpCircle,     adminOnly: false },
        { labelKey: 'profile_settings',descKey: 'profile_desc',      to: '/profile',     icon: Settings,       adminOnly: false },
    ];

    const ROLE_BADGE = {
        admin:   'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400',
        analyst: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400',
    };

    const visibleItems = ADMIN_NAV.filter(item => !item.adminOnly || user.role === 'admin');

    return (
        <aside
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            className={`
                relative flex flex-col flex-shrink-0 h-full
                bg-white dark:bg-slate-900
                border-r border-slate-200 dark:border-slate-800
                transition-all duration-300 ease-in-out z-30
                ${isHovered ? 'w-60 shadow-xl' : 'w-16'}
            `}
        >
            {/* Nav Items */}
            <nav className="flex-1 py-6 px-2.5 space-y-1.5 overflow-y-auto">
                <p
                    className={`
                        px-3 mb-3 text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest
                        transition-all duration-300 whitespace-nowrap
                        ${isHovered ? 'opacity-100 max-h-5' : 'opacity-0 max-h-0 overflow-hidden mb-0'}
                    `}
                >
                    {user.role === 'admin' ? t('admin_panel') : t('navigation')}
                </p>

                {visibleItems.map(item => {
                    const Icon = item.icon;
                    const active = pathname === item.to || (item.to !== '/dashboard' && pathname.startsWith(item.to));

                    return (
                        <Link
                            key={item.to}
                            to={item.to}
                            title={!isHovered ? t(item.labelKey) : undefined}
                            className={`
                                group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-150
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
                                <div className="text-xs text-slate-400 dark:text-slate-500 mt-0.5 leading-tight truncate">{t(item.descKey)}</div>
                            </div>
                        </Link>
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
