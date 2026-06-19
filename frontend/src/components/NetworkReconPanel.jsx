import React from 'react';
import { Server, Globe, Shield, Activity } from 'lucide-react';

const NetworkReconPanel = ({ recon }) => {
    if (!recon) return null;

    const stats = [
        { label: 'Target',       value: recon.ip || '—',              icon: Globe },
        { label: 'OS Detected',  value: recon.os || 'Unknown',       icon: Server },
        { label: 'Open Ports',   value: recon.open_ports ?? 0,        icon: Activity },
        { label: 'Subdomains',   value: recon.subdomain_count ?? 0,   icon: Shield },
    ];

    return (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-5">
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

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {stats.map(({ label, value, icon: Icon }) => (
                    <div key={label} className="rounded-xl border border-slate-200 dark:border-slate-800 p-4 bg-slate-50 dark:bg-slate-950">
                        <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400 mb-2">
                            <Icon className="w-4 h-4" />
                            <span className="text-[10px] font-semibold uppercase tracking-wider">{label}</span>
                        </div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white font-mono truncate" title={String(value)}>
                            {value}
                        </div>
                    </div>
                ))}
            </div>

            {recon.open_port_list?.length > 0 && (
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
                                {recon.open_port_list.slice(0, 20).map((p, i) => (
                                    <tr key={i} className="border-t border-slate-200 dark:border-slate-800">
                                        <td className="px-3 py-2 font-mono text-slate-800 dark:text-slate-200">
                                            {p.host}:{p.port}/{p.protocol}
                                        </td>
                                        <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{p.service || '—'}</td>
                                        <td className="px-3 py-2 text-slate-600 dark:text-slate-400">{p.version || '—'}</td>
                                        <td className="px-3 py-2 uppercase font-semibold text-slate-700 dark:text-slate-300">
                                            {p.severity}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
};

export default NetworkReconPanel;
