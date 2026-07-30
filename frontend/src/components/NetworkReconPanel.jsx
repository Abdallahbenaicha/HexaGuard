import React, { useState, useCallback } from 'react';
import {
    Server, Globe, Shield, Activity, Cpu, ChevronDown, ChevronRight,
    Wifi, Download, GitCompare, Lock, AlertCircle, CheckCircle,
    Network, HardDrive,
} from 'lucide-react';

const SEV_COLOR = {
    critical: 'text-red-600 dark:text-red-400',
    high:     'text-orange-600 dark:text-orange-400',
    medium:   'text-yellow-600 dark:text-yellow-400',
    low:      'text-green-600 dark:text-green-400',
    info:     'text-blue-600 dark:text-blue-400',
};

// ── Device risk score (0-10) computed from CVE count + ports + abuse score ──
const deviceRiskScore = (device, devicePorts) => {
    let s = 0;
    s += Math.min((device.shodan_cves?.length || 0) * 2, 6);
    if ((device.abuseipdb_score || 0) >= 75) s += 3;
    else if ((device.abuseipdb_score || 0) >= 25) s += 1;
    s += devicePorts.filter(p => p.severity === 'critical').length * 2;
    s += devicePorts.filter(p => p.severity === 'high').length;
    return Math.min(10, s);
};

const RiskBadge = ({ score }) => {
    const color = score >= 7 ? 'bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-400 border-red-200 dark:border-red-500/30'
                : score >= 4 ? 'bg-orange-100 text-orange-700 dark:bg-orange-500/20 dark:text-orange-400 border-orange-200 dark:border-orange-500/30'
                : score >= 1 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/20 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/30'
                             : 'bg-green-100 text-green-700 dark:bg-green-500/20 dark:text-green-400 border-green-200 dark:border-green-500/30';
    return (
        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${color}`}>
            Risk {score}/10
        </span>
    );
};

// ── SSL Cert display ──────────────────────────────────────────────────────────
const SslCertBadge = ({ cert }) => {
    const expired = cert.expires ? new Date(cert.expires) < new Date() : false;
    return (
        <div className={`flex items-start gap-1.5 text-xs p-2 rounded border ${
            cert.self_signed || expired
                ? 'bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20'
                : 'bg-green-50 dark:bg-green-500/10 border-green-200 dark:border-green-500/20'
        }`}>
            <Lock className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${cert.self_signed || expired ? 'text-red-500' : 'text-green-500'}`} />
            <div className="min-w-0">
                <div className="font-semibold text-slate-700 dark:text-slate-300 truncate">
                    :{cert.port} — {cert.cn || 'Unknown CN'}
                </div>
                <div className="text-slate-500 dark:text-slate-400 truncate">
                    {cert.issuer || 'Unknown issuer'}
                </div>
                <div className="text-slate-400 dark:text-slate-500">
                    Exp: {cert.expires || '?'}
                    {cert.self_signed && <span className="ml-1 text-red-500 font-semibold">· Self-signed</span>}
                    {expired         && <span className="ml-1 text-red-500 font-semibold">· EXPIRED</span>}
                </div>
            </div>
        </div>
    );
};

// ── Individual device card ────────────────────────────────────────────────────
const DeviceCard = ({ device, portList }) => {
    const [open, setOpen] = useState(false);
    const devicePorts = portList.filter(p => p.host === device.host);
    const risk = deviceRiskScore(device, devicePorts);

    return (
        <div className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
            <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center gap-3 px-4 py-3 bg-slate-50 dark:bg-slate-800/60 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors text-left"
            >
                <div className="w-8 h-8 rounded-lg bg-primary-100 dark:bg-primary-500/20 flex items-center justify-center flex-shrink-0">
                    <Cpu className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                </div>
                <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-slate-900 dark:text-white font-mono truncate">
                        {device.host}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 truncate">
                        {device.hostname && <span className="mr-2">{device.hostname}</span>}
                        {device.mac_vendor && <span className="text-primary-600 dark:text-primary-400">{device.mac_vendor}</span>}
                        {device.os && !device.hostname && !device.mac_vendor && (
                            <span>{device.os}{device.os_accuracy ? ` (${device.os_accuracy}%)` : ''}</span>
                        )}
                    </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                    {risk > 0 && <RiskBadge score={risk} />}
                    {devicePorts.length > 0 && (
                        <span className="text-xs px-2 py-0.5 bg-primary-100 dark:bg-primary-500/20 text-primary-700 dark:text-primary-300 rounded-full font-medium">
                            {devicePorts.length}p
                        </span>
                    )}
                    {device.shodan_cves?.length > 0 && (
                        <span className="text-xs px-2 py-0.5 bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400 rounded-full font-medium">
                            {device.shodan_cves.length} CVE
                        </span>
                    )}
                    {device.ssl_certs?.length > 0 && (
                        <Lock className="w-3.5 h-3.5 text-green-500" title="SSL cert detected" />
                    )}
                    {open ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                </div>
            </button>

            {open && (
                <div className="px-4 py-3 space-y-3 bg-white dark:bg-slate-900">
                    {/* Identity grid */}
                    <div className="grid grid-cols-2 gap-2 text-xs">
                        {device.hostname && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">Hostname</span>
                                <div className="mt-0.5 font-mono text-slate-700 dark:text-slate-300 truncate">{device.hostname}</div>
                            </div>
                        )}
                        {device.os && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">OS</span>
                                <div className="mt-0.5 text-slate-700 dark:text-slate-300 truncate">
                                    {device.os}{device.os_accuracy ? ` (${device.os_accuracy}%)` : ''}
                                </div>
                            </div>
                        )}
                        {device.mac && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">MAC</span>
                                <div className="mt-0.5 font-mono text-slate-700 dark:text-slate-300">{device.mac}</div>
                            </div>
                        )}
                        {device.mac_vendor && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">Vendor</span>
                                <div className="mt-0.5 text-slate-700 dark:text-slate-300">{device.mac_vendor}</div>
                            </div>
                        )}
                        <div>
                            <span className="text-slate-400 uppercase tracking-wider font-semibold">State</span>
                            <div className="mt-0.5 font-medium text-slate-700 dark:text-slate-300">{device.state || 'up'}</div>
                        </div>
                        {device.abuseipdb_score != null && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">Abuse Score</span>
                                <div className={`mt-0.5 font-medium ${device.abuseipdb_score >= 75 ? 'text-red-600' : device.abuseipdb_score >= 25 ? 'text-yellow-600' : 'text-green-600'}`}>
                                    {device.abuseipdb_score}/100
                                </div>
                            </div>
                        )}
                        {device.greynoise?.noise && (
                            <div>
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">GreyNoise</span>
                                <div className="mt-0.5 font-medium text-orange-600 dark:text-orange-400">
                                    {device.greynoise.classification || 'Scanner'}
                                </div>
                            </div>
                        )}
                        {device.shodan_tags?.length > 0 && (
                            <div className="col-span-2">
                                <span className="text-slate-400 uppercase tracking-wider font-semibold">Tags</span>
                                <div className="mt-0.5 flex flex-wrap gap-1">
                                    {device.shodan_tags.map(t => (
                                        <span key={t} className="text-[10px] px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 rounded border border-slate-200 dark:border-slate-700">
                                            {t}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* SSL Certs */}
                    {device.ssl_certs?.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                                <Lock className="w-3 h-3" /> SSL Certificates
                            </div>
                            <div className="space-y-1">
                                {device.ssl_certs.map((cert, i) => (
                                    <SslCertBadge key={i} cert={cert} />
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Known CVEs */}
                    {device.shodan_cves?.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-red-600 dark:text-red-400 uppercase tracking-wider mb-1">Known CVEs (Shodan)</div>
                            <div className="flex flex-wrap gap-1">
                                {device.shodan_cves.slice(0, 10).map(cve => (
                                    <span key={cve} className="text-[10px] font-mono px-1.5 py-0.5 bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 rounded border border-red-200 dark:border-red-500/20">
                                        {cve}
                                    </span>
                                ))}
                                {device.shodan_cves.length > 10 && (
                                    <span className="text-[10px] text-slate-400">+{device.shodan_cves.length - 10} more</span>
                                )}
                            </div>
                        </div>
                    )}

                    {/* Open Ports */}
                    {devicePorts.length > 0 && (
                        <div>
                            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1">Open Ports</div>
                            <div className="space-y-1">
                                {devicePorts.map((p, i) => (
                                    <div key={i} className="flex items-center gap-2 text-xs">
                                        <span className="font-mono text-slate-700 dark:text-slate-300 w-24 flex-shrink-0">
                                            {p.port}/{p.protocol}
                                        </span>
                                        <span className="text-slate-500">{p.service || '—'}</span>
                                        {p.version && <span className="text-slate-400 truncate">{p.version}</span>}
                                        <span className={`ml-auto font-semibold uppercase flex-shrink-0 ${SEV_COLOR[p.severity] || SEV_COLOR.info}`}>
                                            {p.severity}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

// ── Simple topology SVG (hub-and-spoke) ───────────────────────────────────────
const TopologyView = ({ recon }) => {
    const devices = recon.hosts || [];
    const portList = recon.open_port_list || [];
    if (devices.length === 0) return null;

    const cx = 260, cy = 140, r = 100;
    const nodeR = 22;

    const positions = devices.slice(0, 12).map((_, i) => {
        const angle = (2 * Math.PI * i) / Math.min(devices.length, 12) - Math.PI / 2;
        return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });

    const getNodeColor = (device) => {
        const devPorts = portList.filter(p => p.host === device.host);
        const risk = deviceRiskScore(device, devPorts);
        if (risk >= 7) return '#ef4444';
        if (risk >= 4) return '#f97316';
        if (risk >= 1) return '#eab308';
        return '#22c55e';
    };

    return (
        <svg viewBox="0 0 520 280" className="w-full max-h-64 select-none">
            {/* Lines from center to nodes */}
            {positions.map((pos, i) => (
                <line key={i} x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                    stroke="#94a3b8" strokeWidth="1" strokeDasharray="4,3" opacity="0.5" />
            ))}
            {/* Center node (router/target) */}
            <circle cx={cx} cy={cy} r={nodeR} fill="#1e293b" stroke="#6366f1" strokeWidth="2" />
            <text x={cx} y={cy + 4} textAnchor="middle" fontSize="8" fill="#c7d2fe" fontFamily="monospace">
                TARGET
            </text>
            {/* Device nodes */}
            {devices.slice(0, 12).map((device, i) => {
                const pos = positions[i];
                const color = getNodeColor(device);
                const label = device.mac_vendor || device.hostname ||
                              device.host.split('.').slice(-2).join('.');
                return (
                    <g key={i}>
                        <circle cx={pos.x} cy={pos.y} r={nodeR - 4} fill={color} opacity="0.15"
                            stroke={color} strokeWidth="1.5" />
                        <text x={pos.x} y={pos.y + 3} textAnchor="middle" fontSize="7"
                            fill="currentColor" className="text-slate-700 dark:text-slate-300"
                            fontFamily="monospace">
                            {device.host.split('.').pop()}
                        </text>
                        <text x={pos.x} y={pos.y + nodeR + 8} textAnchor="middle" fontSize="6.5"
                            fill="#64748b" fontFamily="sans-serif">
                            {label.length > 14 ? label.slice(0, 14) + '…' : label}
                        </text>
                    </g>
                );
            })}
            {devices.length > 12 && (
                <text x={cx} y={cy + r + 30} textAnchor="middle" fontSize="9" fill="#94a3b8">
                    +{devices.length - 12} more devices
                </text>
            )}
        </svg>
    );
};

// ── History / diff panel ──────────────────────────────────────────────────────
const HistoryPanel = ({ history }) => {
    if (!history) return null;
    const { new_devices = [], removed_devices = [], port_changes = [], has_changes } = history;
    if (!has_changes) {
        return (
            <div className="flex items-center gap-2 text-xs text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 rounded-xl px-4 py-3">
                <CheckCircle className="w-4 h-4 flex-shrink-0" />
                No changes detected since last scan — network topology is stable.
            </div>
        );
    }
    return (
        <div className="space-y-3">
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                <GitCompare className="w-3.5 h-3.5" /> Changes Since Last Scan
            </h4>
            {new_devices.length > 0 && (
                <div className="bg-green-50 dark:bg-green-500/10 border border-green-200 dark:border-green-500/20 rounded-xl p-3">
                    <div className="text-xs font-semibold text-green-700 dark:text-green-400 mb-1.5">
                        {new_devices.length} New Device{new_devices.length !== 1 ? 's' : ''} Detected
                    </div>
                    <div className="space-y-0.5">
                        {new_devices.map((d, i) => (
                            <div key={i} className="text-xs font-mono text-green-700 dark:text-green-400">
                                + {d.host}{d.hostname ? ` (${d.hostname})` : ''}
                            </div>
                        ))}
                    </div>
                </div>
            )}
            {removed_devices.length > 0 && (
                <div className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl p-3">
                    <div className="text-xs font-semibold text-slate-500 mb-1.5">
                        {removed_devices.length} Device{removed_devices.length !== 1 ? 's' : ''} No Longer Visible
                    </div>
                    <div className="space-y-0.5">
                        {removed_devices.map((d, i) => (
                            <div key={i} className="text-xs font-mono text-slate-500">
                                − {d.host}{d.hostname ? ` (${d.hostname})` : ''}
                            </div>
                        ))}
                    </div>
                </div>
            )}
            {port_changes.length > 0 && (
                <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 rounded-xl p-3">
                    <div className="text-xs font-semibold text-amber-700 dark:text-amber-400 mb-1.5">
                        Port Changes on {port_changes.length} Host{port_changes.length !== 1 ? 's' : ''}
                    </div>
                    {port_changes.map((pc, i) => (
                        <div key={i} className="mb-1.5">
                            <div className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">{pc.host}</div>
                            {pc.new_ports.map((p, j) => (
                                <div key={j} className="text-xs font-mono text-green-600 dark:text-green-400 pl-2">
                                    + {p.port}/{p.protocol} {p.service}
                                </div>
                            ))}
                            {pc.closed_ports.map((p, j) => (
                                <div key={j} className="text-xs font-mono text-slate-500 pl-2">
                                    − {p.port}/{p.protocol} {p.service}
                                </div>
                            ))}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

// ── CSV export helper ─────────────────────────────────────────────────────────
const exportCsv = (recon) => {
    const devices = recon.hosts || [];
    const portList = recon.open_port_list || [];
    const rows = [['IP', 'Hostname', 'MAC', 'Vendor', 'OS', 'Open Ports', 'CVE Count', 'Abuse Score']];
    for (const d of devices) {
        const devPorts = portList.filter(p => p.host === d.host);
        rows.push([
            d.host,
            d.hostname || '',
            d.mac || '',
            d.mac_vendor || '',
            d.os || '',
            devPorts.map(p => `${p.port}/${p.protocol}(${p.service})`).join(' | '),
            d.shodan_cves?.length || 0,
            d.abuseipdb_score ?? '',
        ]);
    }
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `securax-network-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
};

// ── Main component ────────────────────────────────────────────────────────────
const NetworkReconPanel = ({ recon, history }) => {
    const [view, setView] = useState('devices'); // 'devices' | 'topology' | 'history'
    const handleExport = useCallback(() => exportCsv(recon), [recon]);

    if (!recon) return null;

    const devices = recon.hosts || [];
    const portList = recon.open_port_list || [];

    const stats = [
        { label: 'Target',      value: recon.ip || '—',                              icon: Globe },
        { label: 'OS Detected', value: recon.os || 'Unknown',                        icon: Server },
        { label: 'Hosts Up',    value: `${recon.hosts_up ?? 0} / ${recon.total_hosts ?? 0}`, icon: Wifi },
        { label: 'Open Ports',  value: recon.open_ports ?? 0,                        icon: Activity },
        { label: 'Subdomains',  value: recon.subdomain_count ?? 0,                   icon: Shield },
        { label: 'Shodan CVEs', value: recon.shodan_cve_count ?? 0,                  icon: AlertCircle },
    ];

    const hasHistory = history && (history.has_changes || history.new_devices?.length >= 0);

    return (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
                <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                        Network Reconnaissance Summary
                    </h3>
                    {recon.tools_used?.length > 0 && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            Tools: {recon.tools_used.join(' · ')}
                        </p>
                    )}
                </div>
                {devices.length > 0 && (
                    <button
                        onClick={handleExport}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 rounded-lg transition-colors"
                        title="Export devices to CSV"
                    >
                        <Download className="w-3.5 h-3.5" /> Export CSV
                    </button>
                )}
            </div>

            {/* Stats grid */}
            <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
                {stats.map(({ label, value, icon: Icon }) => (
                    <div key={label} className="rounded-xl border border-slate-200 dark:border-slate-800 p-3 bg-slate-50 dark:bg-slate-950">
                        <div className="flex items-center gap-1.5 text-slate-500 dark:text-slate-400 mb-1.5">
                            <Icon className="w-3.5 h-3.5" />
                            <span className="text-[9px] font-semibold uppercase tracking-wider leading-tight">{label}</span>
                        </div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white font-mono truncate" title={String(value)}>
                            {value}
                        </div>
                    </div>
                ))}
            </div>

            {/* View tabs */}
            {devices.length > 0 && (
                <div className="flex gap-1 border-b border-slate-200 dark:border-slate-800 pb-0">
                    {[
                        { id: 'devices',  label: `Devices (${devices.length})`, icon: HardDrive },
                        { id: 'topology', label: 'Topology',                    icon: Network },
                        ...(hasHistory ? [{ id: 'history', label: 'Changes', icon: GitCompare }] : []),
                    ].map(({ id, label, icon: Icon }) => (
                        <button
                            key={id}
                            onClick={() => setView(id)}
                            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-t-lg transition-colors border-b-2 -mb-px ${
                                view === id
                                    ? 'border-primary-500 text-primary-600 dark:text-primary-400 bg-primary-50 dark:bg-primary-500/10'
                                    : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                            }`}
                        >
                            <Icon className="w-3.5 h-3.5" />
                            {label}
                            {id === 'history' && history?.has_changes && (
                                <span className="w-1.5 h-1.5 bg-amber-500 rounded-full" />
                            )}
                        </button>
                    ))}
                </div>
            )}

            {/* Devices list */}
            {view === 'devices' && devices.length > 0 && (
                <div>
                    <div className="space-y-2">
                        {devices.map((d, i) => (
                            <DeviceCard key={i} device={d} portList={portList} />
                        ))}
                    </div>
                </div>
            )}

            {/* Topology view */}
            {view === 'topology' && (
                <div className="bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 p-4">
                    <p className="text-[10px] text-slate-400 mb-2 text-center uppercase tracking-wider">
                        Hub-and-spoke topology · color = risk level
                    </p>
                    <TopologyView recon={recon} />
                    <div className="flex items-center justify-center gap-4 mt-2">
                        {[['#ef4444','High (7+)'],['#f97316','Medium (4-6)'],['#eab308','Low (1-3)'],['#22c55e','Clean']].map(([c,l]) => (
                            <div key={l} className="flex items-center gap-1 text-[10px] text-slate-500">
                                <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{background:c}} />
                                {l}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* History / diff */}
            {view === 'history' && hasHistory && (
                <HistoryPanel history={history} />
            )}

            {/* Legacy port table (no per-device data) */}
            {devices.length === 0 && portList.length > 0 && (
                <div>
                    <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Open Ports</h4>
                    <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-slate-800">
                        <table className="w-full text-xs">
                            <thead className="bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                                <tr>
                                    <th className="text-left px-3 py-2 font-semibold">Endpoint</th>
                                    <th className="text-left px-3 py-2 font-semibold">Service</th>
                                    <th className="text-left px-3 py-2 font-semibold">Version</th>
                                    <th className="text-left px-3 py-2 font-semibold">Severity</th>
                                </tr>
                            </thead>
                            <tbody>
                                {portList.slice(0, 20).map((p, i) => (
                                    <tr key={i} className="border-t border-slate-200 dark:border-slate-800">
                                        <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">
                                            {p.host}:{p.port}/{p.protocol}
                                        </td>
                                        <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{p.service || '—'}</td>
                                        <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{p.version || '—'}</td>
                                        <td className={`px-3 py-2 uppercase font-semibold ${SEV_COLOR[p.severity] || SEV_COLOR.info}`}>
                                            {p.severity}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Subdomains */}
            {recon.subdomains?.length > 0 && (
                <div>
                    <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                        Discovered Subdomains ({recon.subdomain_count})
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                        {recon.subdomains.slice(0, 30).map((s, i) => (
                            <span key={i} className="text-[10px] font-mono px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 rounded border border-slate-200 dark:border-slate-700">
                                {s}
                            </span>
                        ))}
                        {recon.subdomain_count > 30 && (
                            <span className="text-[10px] text-slate-400 py-0.5">+{recon.subdomain_count - 30} more</span>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default NetworkReconPanel;
