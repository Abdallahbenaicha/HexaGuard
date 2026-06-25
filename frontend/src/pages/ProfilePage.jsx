import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import {
    User, Lock, Key, Shield, Eye, EyeOff,
    Copy, RefreshCw, CheckCircle, AlertTriangle,
    Trash2, QrCode, Smartphone, Info,
    Calendar, Activity,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { showToast } from '../context/AuthContext';

const TABS = [
    { id: 'general',  label: 'General',   icon: User  },
    { id: 'security', label: 'Security',   icon: Lock  },
    { id: 'tokens',   label: 'API Tokens', icon: Key   },
    { id: 'totp',     label: '2FA Setup',  icon: Shield },
];

const InputField = ({ label, type = 'text', value, onChange, placeholder, right }) => (
    <div className="space-y-1.5">
        <label className="text-xs font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">{label}</label>
        <div className="relative">
            <input
                type={type}
                value={value}
                onChange={onChange}
                placeholder={placeholder}
                className="w-full bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-primary-500 dark:focus:border-primary-400 transition-colors"
            />
            {right && <div className="absolute right-3 top-1/2 -translate-y-1/2">{right}</div>}
        </div>
    </div>
);

const Section = ({ title, desc, children }) => (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-5">
        <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white">{title}</h3>
            {desc && <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{desc}</p>}
        </div>
        {children}
    </div>
);

const Alert = ({ type, message }) => {
    if (!message) return null;
    const styles = {
        success: 'bg-green-50 dark:bg-green-500/10 border-green-200 dark:border-green-500/30 text-green-700 dark:text-green-400',
        error:   'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/30 text-red-700 dark:text-red-400',
        info:    'bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/30 text-blue-700 dark:text-blue-400',
    };
    const Icon = type === 'success' ? CheckCircle : type === 'error' ? AlertTriangle : Info;
    return (
        <div className={`flex items-start gap-2.5 p-3 rounded-xl border text-sm ${styles[type] || styles.info}`}>
            <Icon className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <span>{message}</span>
        </div>
    );
};

// ── General Tab ───────────────────────────────────────────────────────────────
const GeneralTab = ({ user }) => (
    <div className="space-y-4">
        <Section title="Account Information" desc="Your account details and activity.">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {[
                    { label: 'Username',    value: user?.username,   icon: User },
                    { label: 'Role',        value: user?.role,       icon: Shield },
                    { label: 'Login Count', value: user?.login_count ?? '—', icon: Activity },
                    { label: 'Last Login',  value: user?.last_login ? new Date(user.last_login).toLocaleString() : '—', icon: Calendar },
                ].map(({ label, value, icon: Icon }) => (
                    <div key={label} className="flex items-center gap-3 p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                        <div className="p-2 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600">
                            <Icon className="w-3.5 h-3.5 text-slate-500 dark:text-slate-400" />
                        </div>
                        <div>
                            <div className="text-[10px] text-slate-400 uppercase tracking-widest">{label}</div>
                            <div className="text-sm font-semibold text-slate-800 dark:text-slate-200 capitalize">{String(value)}</div>
                        </div>
                    </div>
                ))}
            </div>
            <div className="pt-2 flex flex-wrap gap-2">
                {(user?.permissions || []).map(p => (
                    <span key={p} className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20 uppercase tracking-wide">
                        {p.replace(/_/g, ' ')}
                    </span>
                ))}
            </div>
        </Section>
    </div>
);

// ── Security Tab ──────────────────────────────────────────────────────────────
const SecurityTab = () => {
    const { logout } = useAuth();
    const [currentPw, setCurrentPw] = useState('');
    const [newPw,     setNewPw]     = useState('');
    const [confirmPw, setConfirmPw] = useState('');
    const [showCur,   setShowCur]   = useState(false);
    const [showNew,   setShowNew]   = useState(false);
    const [loading,   setLoading]   = useState(false);
    const [msg,       setMsg]       = useState({ type: '', text: '' });

    const strengthScore = (pw) => {
        let s = 0;
        if (pw.length >= 8)    s++;
        if (/[A-Z]/.test(pw))  s++;
        if (/[a-z]/.test(pw))  s++;
        if (/\d/.test(pw))     s++;
        if (/[^A-Za-z0-9]/.test(pw)) s++;
        return s;
    };

    const score   = strengthScore(newPw);
    const barColor = score <= 1 ? 'bg-red-500' : score <= 2 ? 'bg-orange-400' : score <= 3 ? 'bg-yellow-400' : score === 4 ? 'bg-blue-500' : 'bg-green-500';
    const barLabel = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][score - 1] || '';

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMsg({ type: '', text: '' });
        if (newPw !== confirmPw) { setMsg({ type: 'error', text: 'Passwords do not match.' }); return; }
        if (score < 3) { setMsg({ type: 'error', text: 'Password is too weak. Use uppercase, digits, and symbols.' }); return; }
        setLoading(true);
        try {
            const { data } = await axios.post('/api/auth/change-password',
                { current_password: currentPw, new_password: newPw },
                { withCredentials: true });
            if (data.ok) {
                setMsg({ type: 'success', text: 'Password changed. Logging you out…' });
                setTimeout(() => logout(), 1800);
            } else {
                setMsg({ type: 'error', text: data.error || 'Failed to change password.' });
            }
        } catch (err) {
            setMsg({ type: 'error', text: err.response?.data?.error || 'Request failed.' });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="space-y-4">
            <Section title="Change Password" desc="You will be logged out after a successful password change.">
                <form onSubmit={handleSubmit} className="space-y-4">
                    <InputField
                        label="Current Password"
                        type={showCur ? 'text' : 'password'}
                        value={currentPw}
                        onChange={e => setCurrentPw(e.target.value)}
                        placeholder="Enter current password"
                        right={
                            <button type="button" onClick={() => setShowCur(v => !v)} className="text-slate-400 hover:text-slate-600">
                                {showCur ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        }
                    />
                    <InputField
                        label="New Password"
                        type={showNew ? 'text' : 'password'}
                        value={newPw}
                        onChange={e => setNewPw(e.target.value)}
                        placeholder="Min 8 chars, uppercase, digit, symbol"
                        right={
                            <button type="button" onClick={() => setShowNew(v => !v)} className="text-slate-400 hover:text-slate-600">
                                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        }
                    />
                    {newPw && (
                        <div className="space-y-1">
                            <div className="flex gap-1">
                                {[1,2,3,4,5].map(i => (
                                    <div key={i} className={`h-1 flex-1 rounded-full transition-all ${i <= score ? barColor : 'bg-slate-200 dark:bg-slate-700'}`} />
                                ))}
                            </div>
                            <div className="text-[10px] text-slate-400">{barLabel}</div>
                        </div>
                    )}
                    <InputField
                        label="Confirm New Password"
                        type="password"
                        value={confirmPw}
                        onChange={e => setConfirmPw(e.target.value)}
                        placeholder="Repeat new password"
                    />
                    <Alert type={msg.type} message={msg.text} />
                    <button
                        type="submit"
                        disabled={loading || !currentPw || !newPw || !confirmPw}
                        className="px-5 py-2.5 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50 flex items-center gap-2"
                    >
                        {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
                        {loading ? 'Updating…' : 'Update Password'}
                    </button>
                </form>
            </Section>
        </div>
    );
};

// ── API Tokens Tab ────────────────────────────────────────────────────────────
const TokensTab = () => {
    const [info,        setInfo]        = useState(null);
    const [newToken,    setNewToken]    = useState('');
    const [copied,      setCopied]      = useState(false);
    const [generating,  setGenerating]  = useState(false);
    const [revoking,    setRevoking]    = useState(false);
    const [showToken,   setShowToken]   = useState(false);
    const [msg,         setMsg]         = useState({ type: '', text: '' });

    const fetchInfo = async () => {
        try {
            const { data } = await axios.get('/api/auth/token', { withCredentials: true });
            setInfo(data);
        } catch { /* ignore */ }
    };

    useEffect(() => { fetchInfo(); }, []);

    const generate = async () => {
        setGenerating(true);
        setMsg({ type: '', text: '' });
        setNewToken('');
        try {
            const { data } = await axios.post('/api/auth/token/generate', {}, { withCredentials: true });
            if (data.ok) {
                setNewToken(data.token);
                setShowToken(true);
                setMsg({ type: 'success', text: 'Token generated. Copy it now — it will not be shown again.' });
                fetchInfo();
            }
        } catch (err) {
            setMsg({ type: 'error', text: err.response?.data?.error || 'Failed to generate token.' });
        } finally {
            setGenerating(false);
        }
    };

    const revoke = async () => {
        if (!window.confirm('Revoke your API token? All integrations using it will stop working.')) return;
        setRevoking(true);
        try {
            await axios.post('/api/auth/token/revoke', {}, { withCredentials: true });
            setNewToken('');
            setMsg({ type: 'info', text: 'Token revoked successfully.' });
            fetchInfo();
        } catch {
            setMsg({ type: 'error', text: 'Failed to revoke token.' });
        } finally {
            setRevoking(false);
        }
    };

    const copyToken = () => {
        navigator.clipboard.writeText(newToken);
        setCopied(true);
        showToast('Token copied to clipboard', 'success');
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="space-y-4">
            <Section title="API Token" desc="Use a token to authenticate API calls from scripts, CI/CD pipelines, or tools.">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center gap-3">
                    <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${info?.has_token ? 'bg-green-500' : 'bg-slate-400'}`} />
                    <div>
                        <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                            {info?.has_token ? 'Token active' : 'No token'}
                        </div>
                        {info?.created_at && (
                            <div className="text-xs text-slate-400">Created {new Date(info.created_at).toLocaleDateString()}</div>
                        )}
                    </div>
                </div>

                {newToken && (
                    <div className="space-y-2">
                        <div className="flex items-center gap-2">
                            <div className="flex-1 font-mono text-xs bg-slate-900 dark:bg-black text-green-400 p-3 rounded-xl border border-slate-700 overflow-x-auto whitespace-nowrap">
                                {showToken ? newToken : '•'.repeat(48)}
                            </div>
                            <button onClick={() => setShowToken(v => !v)} className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200">
                                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                            <button onClick={copyToken} className="p-2 text-slate-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors">
                                {copied ? <CheckCircle className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>
                )}

                <Alert type={msg.type} message={msg.text} />

                <div className="flex flex-wrap gap-3">
                    <button
                        onClick={generate}
                        disabled={generating}
                        className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                    >
                        {generating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                        {info?.has_token ? 'Regenerate Token' : 'Generate Token'}
                    </button>
                    {info?.has_token && (
                        <button
                            onClick={revoke}
                            disabled={revoking}
                            className="flex items-center gap-2 px-4 py-2 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/30 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                        >
                            {revoking ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                            Revoke
                        </button>
                    )}
                </div>
            </Section>

            <Section title="Usage Example" desc="How to authenticate API calls using your token.">
                <div className="rounded-xl bg-slate-900 dark:bg-black p-4 font-mono text-xs text-slate-300 overflow-x-auto space-y-1">
                    <div><span className="text-slate-500"># Add to request headers</span></div>
                    <div><span className="text-yellow-400">Authorization</span>: Bearer <span className="text-green-400">sx_your_token_here</span></div>
                    <div className="mt-3"><span className="text-slate-500"># Example curl</span></div>
                    <div><span className="text-blue-400">curl</span> -H <span className="text-green-400">"Authorization: Bearer sx_…"</span> \</div>
                    <div className="pl-4">https://abdallahbenaicha.pythonanywhere.com/api/version</div>
                </div>
            </Section>
        </div>
    );
};

// ── 2FA Tab ───────────────────────────────────────────────────────────────────
const TotpTab = ({ user, refetch }) => {
    const [step,     setStep]     = useState('idle'); // idle | setup | verify
    const [qrData,   setQrData]   = useState(null);
    const [code,     setCode]     = useState('');
    const [loading,  setLoading]  = useState(false);
    const [msg,      setMsg]      = useState({ type: '', text: '' });

    const startSetup = async () => {
        setLoading(true);
        setMsg({ type: '', text: '' });
        try {
            const { data } = await axios.post('/api/auth/totp/setup', {}, { withCredentials: true });
            setQrData(data);
            setStep('setup');
        } catch {
            setMsg({ type: 'error', text: 'Failed to start 2FA setup.' });
        } finally {
            setLoading(false);
        }
    };

    const enableTotp = async () => {
        if (!code.trim()) return;
        setLoading(true);
        setMsg({ type: '', text: '' });
        try {
            const { data } = await axios.post('/api/auth/totp/enable', { token: code }, { withCredentials: true });
            if (data.ok) {
                setMsg({ type: 'success', text: '2FA enabled successfully. Your account is now protected.' });
                setStep('idle');
                setCode('');
                refetch?.();
            } else {
                setMsg({ type: 'error', text: data.error || 'Invalid code. Try again.' });
            }
        } catch (err) {
            setMsg({ type: 'error', text: err.response?.data?.error || 'Failed to verify code.' });
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="space-y-4">
            <Section
                title="Two-Factor Authentication (TOTP)"
                desc="Add a second layer of protection using an authenticator app."
            >
                <div className="flex items-center gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700">
                    <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${user?.totp_enabled ? 'bg-green-500' : 'bg-slate-400'}`} />
                    <div>
                        <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                            {user?.totp_enabled ? '2FA is enabled' : '2FA is disabled'}
                        </div>
                        <div className="text-xs text-slate-400">
                            {user?.totp_enabled ? 'Login requires your authenticator app code.' : 'Enable for extra account security.'}
                        </div>
                    </div>
                </div>

                <Alert type={msg.type} message={msg.text} />

                {step === 'idle' && !user?.totp_enabled && (
                    <button
                        onClick={startSetup}
                        disabled={loading}
                        className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                    >
                        {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <QrCode className="w-4 h-4" />}
                        Set Up 2FA
                    </button>
                )}

                {step === 'setup' && qrData && (
                    <div className="space-y-5">
                        <div className="text-sm text-slate-600 dark:text-slate-400 space-y-1">
                            <p><span className="font-semibold text-slate-800 dark:text-slate-200">Step 1:</span> Install an authenticator app (Google Authenticator, Authy, or Aegis).</p>
                            <p><span className="font-semibold text-slate-800 dark:text-slate-200">Step 2:</span> Scan the QR code below.</p>
                            <p><span className="font-semibold text-slate-800 dark:text-slate-200">Step 3:</span> Enter the 6-digit code from the app.</p>
                        </div>

                        <div className="flex flex-col sm:flex-row gap-6 items-start">
                            <div className="bg-white p-3 rounded-xl border border-slate-200">
                                <img src={`data:image/png;base64,${qrData.qr_b64}`} alt="QR Code" className="w-40 h-40" />
                            </div>
                            <div className="space-y-3 flex-1">
                                <div>
                                    <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Manual entry key</div>
                                    <div className="font-mono text-xs bg-slate-100 dark:bg-slate-800 px-3 py-2 rounded-lg break-all border border-slate-200 dark:border-slate-700">
                                        {qrData.secret}
                                    </div>
                                </div>
                                <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
                                    <Smartphone className="w-4 h-4 flex-shrink-0" />
                                    Works with Google Authenticator, Authy, Aegis, Bitwarden, and any TOTP app.
                                </div>
                            </div>
                        </div>

                        <div className="space-y-3">
                            <InputField
                                label="Verification Code"
                                value={code}
                                onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="6-digit code from app"
                            />
                            <div className="flex gap-3">
                                <button
                                    onClick={enableTotp}
                                    disabled={loading || code.length < 6}
                                    className="flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-500 text-white rounded-xl text-sm font-semibold transition-colors disabled:opacity-50"
                                >
                                    {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
                                    Enable 2FA
                                </button>
                                <button
                                    onClick={() => { setStep('idle'); setCode(''); setMsg({ type: '', text: '' }); }}
                                    className="px-4 py-2 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 rounded-xl text-sm font-semibold transition-colors"
                                >
                                    Cancel
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {user?.totp_enabled && (
                    <div className="p-4 rounded-xl bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 flex items-start gap-3">
                        <CheckCircle className="w-5 h-5 text-green-500 mt-0.5 flex-shrink-0" />
                        <div className="text-sm text-green-700 dark:text-green-400">
                            <span className="font-semibold">2FA is active.</span> Your login is protected with a second factor. To disable, contact your administrator.
                        </div>
                    </div>
                )}
            </Section>
        </div>
    );
};

// ── Main ProfilePage ──────────────────────────────────────────────────────────
const ProfilePage = () => {
    const { user, refetch } = useAuth();
    const [activeTab, setActiveTab] = useState('general');

    return (
        <div className="max-w-2xl mx-auto animate-in fade-in duration-500 space-y-6">
            {/* Header */}
            <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-2xl bg-primary-100 dark:bg-primary-500/10 border border-primary-200 dark:border-primary-500/20 flex items-center justify-center flex-shrink-0">
                    <span className="text-2xl font-bold text-primary-600 dark:text-primary-400 uppercase">
                        {user?.username?.[0] || '?'}
                    </span>
                </div>
                <div>
                    <h1 className="text-xl font-bold text-slate-900 dark:text-white">{user?.username}</h1>
                    <p className="text-sm text-slate-500 dark:text-slate-400 capitalize">{user?.role} · Profile & Settings</p>
                </div>
            </div>

            {/* Tabs */}
            <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800/60 p-1 rounded-xl w-fit">
                {TABS.map(tab => {
                    const Icon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                                activeTab === tab.id
                                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm'
                                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                            }`}
                        >
                            <Icon className="w-3.5 h-3.5" />
                            <span className="hidden sm:inline">{tab.label}</span>
                        </button>
                    );
                })}
            </div>

            {/* Content */}
            <AnimatePresence mode="wait">
                <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.15 }}
                >
                    {activeTab === 'general'  && <GeneralTab user={user} />}
                    {activeTab === 'security' && <SecurityTab />}
                    {activeTab === 'tokens'   && <TokensTab />}
                    {activeTab === 'totp'     && <TotpTab user={user} refetch={refetch} />}
                </motion.div>
            </AnimatePresence>
        </div>
    );
};

export default ProfilePage;
