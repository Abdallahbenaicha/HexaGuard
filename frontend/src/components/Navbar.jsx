import { useState, useEffect, useRef } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Moon, Sun, User, LogOut, Menu, X,
    ChevronDown, Network, Globe, Server, Package,
    Shield, FileSearch, Layers, Zap, Lock,
    Command, Container, Mail,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';
import securaxLogo from '../assets/securax_logo.png';

function DropdownMenu({ group, pathname }) {
    const Icon = group.icon;
    const { t } = useLang();
    const isActive = group.items.some(i => pathname.startsWith(i.to));
    const [open, setOpen] = useState(false);
    const ref = useRef(null);

    useEffect(() => {
        const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, []);

    return (
        <div ref={ref} className="relative">
            <button
                onClick={() => setOpen(o => !o)}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                    isActive
                        ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                }`}
            >
                <Icon className="w-3.5 h-3.5" />
                {t(group.labelKey)}
                <ChevronDown className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
            </button>

            {open && (
                <>
                    <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
                    <div className="absolute left-0 mt-2 w-64 bg-white dark:bg-slate-900 rounded-xl shadow-xl border border-slate-200 dark:border-slate-800 py-1.5 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                        {group.items.map(item => {
                            const ItemIcon = item.icon;
                            const active = pathname === item.to;
                            return (
                                <Link
                                    key={item.to}
                                    to={item.to}
                                    onClick={() => setOpen(false)}
                                    className={`flex items-start gap-3 px-4 py-3 mx-1.5 rounded-lg transition-colors ${
                                        active
                                            ? 'bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-300'
                                            : 'hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300'
                                    }`}
                                >
                                    <div className={`mt-0.5 p-1.5 rounded-md flex-shrink-0 ${active ? 'bg-primary-100 dark:bg-primary-500/20 text-primary-600 dark:text-primary-400' : 'bg-slate-100 dark:bg-slate-800 text-slate-500'}`}>
                                        <ItemIcon className="w-3.5 h-3.5" />
                                    </div>
                                    <div>
                                        <div className="text-sm font-semibold leading-tight">{t(item.labelKey)}</div>
                                        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-tight">{t(item.descKey)}</div>
                                    </div>
                                </Link>
                            );
                        })}
                    </div>
                </>
            )}
        </div>
    );
}

const NAV_GROUPS = [
    {
        labelKey: 'nav_scan_web',
        icon: Globe,
        items: [
            { labelKey: 'nav_web_app_scan', descKey: 'nav_web_app_desc', to: '/scan/web',       icon: Globe  },
            { labelKey: 'nav_dast',         descKey: 'nav_dast_desc',    to: '/scan/dast',       icon: Zap    },
            { labelKey: 'nav_code_sast',    descKey: 'nav_code_desc',    to: '/scan/code',       icon: Layers },
            { labelKey: 'nav_ssl_audit',    descKey: 'nav_ssl_desc',     to: '/scan/ssl',        icon: Lock   },
            { labelKey: 'nav_wordpress',    descKey: 'nav_wordpress_desc', to: '/scan/wordpress', icon: Globe  },
        ],
    },
    {
        labelKey: 'nav_scan_server',
        icon: Server,
        items: [
            { labelKey: 'nav_config_int',  descKey: 'nav_config_int_desc', to: '/scan/apache',     icon: FileSearch },
            { labelKey: 'nav_server_ext',  descKey: 'nav_server_ext_desc', to: '/scan/server-ext', icon: Shield     },
            { labelKey: 'nav_docker',      descKey: 'nav_docker_desc',     to: '/scan/docker',     icon: Container  },
            { labelKey: 'nav_dns',         descKey: 'nav_dns_desc',        to: '/scan/dns',         icon: Mail       },
        ],
    },
];

const Navbar = () => {
    const { user, logout } = useAuth();
    const { pathname } = useLocation();
    const { lang, toggleLang, t } = useLang();
    const [darkMode, setDarkMode] = useState(false);
    const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

    useEffect(() => {
        if (localStorage.theme === 'light') {
            setDarkMode(false);
            document.documentElement.classList.remove('dark');
        } else {
            setDarkMode(true);
            document.documentElement.classList.add('dark');
        }
    }, []);

    const toggleTheme = () => {
        const newTheme = !darkMode;
        setDarkMode(newTheme);
        if (newTheme) {
            document.documentElement.classList.add('dark');
            localStorage.theme = 'dark';
        } else {
            document.documentElement.classList.remove('dark');
            localStorage.theme = 'light';
        }
    };

    if (!user) return null;

    return (
        <nav className="sticky top-0 z-50 bg-white/80 dark:bg-slate-950/80 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 transition-colors duration-300">
            <div className="px-4 sm:px-6">
                <div className="flex items-center h-16">

                    {/* Left Brand Area */}
                    <div className="flex-1 flex items-center gap-2">
                        <Link to="/dashboard" className="flex items-center gap-2">
                            <img
                                src={securaxLogo}
                                alt="securAX Logo"
                                className="w-8 h-8 object-contain rounded-md"
                            />
                            <span className="font-bold text-lg tracking-tight text-slate-900 dark:text-white">securAX</span>
                        </Link>
                    </div>

                    {/* Center: nav items */}
                    <div className="hidden lg:flex items-center gap-2">
                        <Link
                            to="/scan/network"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                                pathname.startsWith('/scan/network')
                                    ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Network className="w-3.5 h-3.5" />
                            {t('nav_scan_network')}
                        </Link>

                        {NAV_GROUPS.map(group => (
                            <DropdownMenu key={group.labelKey} group={group} pathname={pathname} />
                        ))}

                        <Link
                            to="/scan/dependencies"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                                pathname === '/scan/dependencies'
                                    ? 'bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-white'
                                    : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 dark:text-slate-300 dark:hover:text-white dark:hover:bg-slate-800/50'
                            }`}
                        >
                            <Package className="w-3.5 h-3.5" />
                            {t('nav_dependencies')}
                        </Link>

                        <Link
                            to="/chat"
                            className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-md transition-all ${
                                pathname === '/chat'
                                    ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                                    : 'text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10 border border-transparent hover:border-cyan-500/20'
                            }`}
                        >
                            {t('nav_aria_ai')}
                        </Link>
                    </div>

                    {/* Right: actions */}
                    <div className="flex-1 flex items-center justify-end gap-1.5">
                        {/* Command Palette trigger */}
                        <button
                            onClick={() => window.dispatchEvent(new CustomEvent('securax-cmd-palette'))}
                            title="Command Palette (Ctrl+K)"
                            className="hidden md:flex items-center gap-2 px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-800"
                        >
                            <Command className="w-3 h-3" />
                            <span className="hidden xl:inline">{t('nav_search')}</span>
                            <kbd className="hidden xl:inline text-[10px] bg-slate-100 dark:bg-slate-800 px-1 rounded">K</kbd>
                        </button>

                        <button
                            onClick={toggleTheme}
                            className="hidden md:flex p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors rounded-full hover:bg-slate-100 dark:hover:bg-slate-800"
                        >
                            {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                        </button>

                        {/* Profile link */}
                        <Link
                            to="/profile"
                            title={t('profile_settings')}
                            className={`hidden md:flex p-2 rounded-full transition-colors hover:bg-slate-100 dark:hover:bg-slate-800 ${
                                pathname === '/profile'
                                    ? 'text-primary-600 dark:text-primary-400 bg-primary-50 dark:bg-primary-500/10'
                                    : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-200'
                            }`}
                        >
                            <User className="w-4 h-4" />
                        </Link>

                        {/* Mobile menu button */}
                        <button
                            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                            className="lg:hidden p-2 text-slate-500 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800 rounded-md"
                        >
                            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                        </button>
                    </div>

                </div>
            </div>

            {/* Mobile Menu */}
            {mobileMenuOpen && (
                <div className="md:hidden border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 px-4 pt-2 pb-4 space-y-1">
                    <Link to="/scan/network" onClick={() => setMobileMenuOpen(false)} className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium ${pathname.startsWith('/scan/network') ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-white' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'}`}>
                        <Network className="w-4 h-4" /> {t('nav_scan_network')}
                    </Link>

                    <p className="px-3 pt-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{t('nav_scan_web')}</p>
                    <Link to="/scan/web"       onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_web_app_scan')}</Link>
                    <Link to="/scan/dast"      onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_dast')}</Link>
                    <Link to="/scan/code"      onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_code_sast')}</Link>
                    <Link to="/scan/ssl"       onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_ssl_audit')}</Link>
                    <Link to="/scan/wordpress" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_wordpress')}</Link>

                    <p className="px-3 pt-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{t('nav_scan_server')}</p>
                    <Link to="/scan/apache"     onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_config_int')}</Link>
                    <Link to="/scan/server-ext" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_server_ext')}</Link>
                    <Link to="/scan/docker"     onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_docker')}</Link>
                    <Link to="/scan/dns"        onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 pl-5">{t('nav_dns')}</Link>

                    <Link to="/scan/dependencies" onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm font-medium text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-800">{t('nav_dependencies')}</Link>
                    <Link to="/chat"              onClick={() => setMobileMenuOpen(false)} className="block px-3 py-2 rounded-md text-sm font-medium text-cyan-600 dark:text-cyan-400 hover:bg-cyan-500/10">{t('nav_aria_ai')}</Link>

                    <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 flex justify-between items-center">
                        <div className="flex items-center gap-3 px-3">
                            <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600">
                                <User className="w-4 h-4" />
                            </div>
                            <div>
                                <div className="text-sm font-medium text-slate-900 dark:text-white">{user.username}</div>
                                <div className="text-xs text-slate-500 dark:text-slate-400 capitalize">{user.role}</div>
                            </div>
                        </div>
                        <div className="flex gap-2">
                            <button onClick={toggleLang} className="px-2 py-1 text-xs font-semibold text-slate-500 border border-slate-200 dark:border-slate-700 rounded-md hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                                {lang === 'en' ? 'AR' : 'EN'}
                            </button>
                            <button onClick={toggleTheme} className="p-2 text-slate-500 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800">
                                {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                            </button>
                            <button onClick={() => { setMobileMenuOpen(false); logout(); }} className="p-2 text-red-500 rounded-full hover:bg-red-50 dark:hover:bg-red-500/10">
                                <LogOut className="w-5 h-5" />
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </nav>
    );
};

export default Navbar;
