import React, { useState, useEffect } from 'react';
import Card from '../ui/Card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { TrendingDown, AlertTriangle, RefreshCw, CheckCircle } from 'lucide-react';
import { api } from '../../services/api';

const FEATURES = [
    { name: 'request_rate', psi: 0.04, kl: 0.12, status: 'stable', detects: 'DoS / Flood' },
    { name: 'error_rate', psi: 0.07, kl: 0.21, status: 'stable', detects: 'Brute Force' },
    { name: 'unique_ips', psi: 0.12, kl: 0.33, status: 'watch', detects: 'Scanning' },
    { name: 'unique_endpoints', psi: 0.09, kl: 0.18, status: 'stable', detects: 'Enumeration' },
    { name: 'payload_entropy', psi: 0.23, kl: 0.49, status: 'drift', detects: 'SQL Injection' },
    { name: 'session_velocity', psi: 0.06, kl: 0.15, status: 'stable', detects: 'Slow-and-Low' },
    { name: 'byte_ratio', psi: 0.11, kl: 0.28, status: 'watch', detects: 'Data Exfil' },
    { name: 'baseline_deviation', psi: 0.18, kl: 0.41, status: 'watch', detects: 'Behavioral Drift' },
    { name: 'connection_burst', psi: 0.03, kl: 0.09, status: 'stable', detects: 'DoS / Burst' },
];

const STATUS_COLORS = { stable: '#00FF41', watch: '#FFF01F', drift: '#FF003C' };
const STATUS_LABELS = { stable: 'STABLE', watch: 'WATCH', drift: '⚠ DRIFT' };

const DriftMonitor = () => {
    const [timeline] = useState(() =>
        Array.from({ length: 20 }, (_, i) => ({
            t: `T-${20 - i}m`,
            psi: parseFloat((0.03 + Math.random() * 0.05 + (i > 15 ? 0.12 : 0)).toFixed(3)),
            threshold: 0.2,
        }))
    );

    const driftCount = FEATURES.filter(f => f.status === 'drift').length;
    const watchCount = FEATURES.filter(f => f.status === 'watch').length;

    return (
        <div className="space-y-6">
            {/* Status Banner */}
            <div className="grid grid-cols-3 gap-4">
                <Card className="p-4 border-neon-red/30 bg-neon-red/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Drift Detected</p>
                    <p className="text-3xl font-display text-neon-red">{driftCount}</p>
                    <p className="text-[10px] text-gray-600 mt-1">features with PSI &gt; 0.2</p>
                </Card>
                <Card className="p-4 border-yellow-400/30 bg-yellow-400/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Under Watch</p>
                    <p className="text-3xl font-display text-yellow-400">{watchCount}</p>
                    <p className="text-[10px] text-gray-600 mt-1">PSI 0.1 – 0.2</p>
                </Card>
                <Card className="p-4 border-neon-green/30 bg-neon-green/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Last Retrain</p>
                    <p className="text-lg font-display text-neon-green">7m 22s</p>
                    <p className="text-[10px] text-gray-600 mt-1">after PSI threshold breach on payload_entropy</p>
                </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* PSI Bar Chart */}
                <Card title="Population Stability Index (PSI) per Feature">
                    <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={FEATURES} layout="vertical" margin={{ left: 20 }}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
                            <XAxis type="number" domain={[0, 0.35]} stroke="#666" fontSize={9} tickLine={false} axisLine={false} />
                            <YAxis dataKey="name" type="category" stroke="#888" fontSize={9} width={130} tickLine={false} axisLine={false} />
                            <Tooltip contentStyle={{ background: '#050505', border: '1px solid #333', fontSize: 10, fontFamily: 'monospace' }} />
                            <Bar dataKey="psi" name="PSI" radius={[0, 3, 3, 0]}>
                                {FEATURES.map((f, i) => (
                                    <rect key={i} fill={STATUS_COLORS[f.status]} />
                                ))}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                    <div className="flex gap-4 px-4 pb-2">
                        {Object.entries(STATUS_COLORS).map(([k, v]) => (
                            <div key={k} className="flex items-center gap-1 text-[10px]" style={{ color: v }}>
                                <span className="w-2 h-2 rounded-sm inline-block" style={{ background: v }} /> {k.toUpperCase()}
                            </div>
                        ))}
                        <span className="text-[10px] text-gray-600 ml-auto">Threshold: 0.20</span>
                    </div>
                </Card>

                {/* PSI Timeline */}
                <Card title="Max PSI Over Time (Last 20 Minutes)">
                    <ResponsiveContainer width="100%" height={280}>
                        <LineChart data={timeline}>
                            <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                            <XAxis dataKey="t" stroke="#666" fontSize={9} tickLine={false} axisLine={false} interval={3} />
                            <YAxis stroke="#666" fontSize={9} tickLine={false} axisLine={false} domain={[0, 0.35]} />
                            <Tooltip contentStyle={{ background: '#050505', border: '1px solid #333', fontSize: 10 }} />
                            <Line type="monotone" dataKey="psi" stroke="#00F3FF" strokeWidth={2} dot={false} name="Max PSI" />
                            <Line type="monotone" dataKey="threshold" stroke="#FF003C" strokeDasharray="4 4" strokeWidth={1} dot={false} name="Threshold (0.2)" />
                        </LineChart>
                    </ResponsiveContainer>
                </Card>
            </div>

            {/* Feature Table */}
            <Card title="Feature Drift Status — 9 Engineered Features">
                <table className="w-full text-xs font-mono">
                    <thead>
                        <tr className="border-b border-white/10">
                            {['Feature', 'PSI', 'KL Divergence', 'Status', 'Detects'].map(h => (
                                <th key={h} className="text-left py-3 px-4 text-gray-500 uppercase tracking-widest">{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {FEATURES.map(f => (
                            <tr key={f.name} className="border-b border-white/5 hover:bg-white/5">
                                <td className="py-2 px-4 text-white font-mono">{f.name}</td>
                                <td className="py-2 px-4" style={{ color: STATUS_COLORS[f.status] }}>{f.psi.toFixed(2)}</td>
                                <td className="py-2 px-4 text-neon-cyan">{f.kl.toFixed(2)}</td>
                                <td className="py-2 px-4">
                                    <span className="px-2 py-0.5 rounded text-[9px] font-bold border"
                                        style={{ color: STATUS_COLORS[f.status], borderColor: STATUS_COLORS[f.status], background: STATUS_COLORS[f.status] + '22' }}>
                                        {STATUS_LABELS[f.status]}
                                    </span>
                                </td>
                                <td className="py-2 px-4 text-gray-400">{f.detects}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </Card>

            {/* Drift Response Pipeline */}
            <Card title="Drift Response Pipeline">
                <div className="flex items-center gap-2 px-4 py-3 overflow-x-auto">
                    {['Drift Detected', 'Alert → ES Index', 'MLflow Retrain', 'Eval on Holdout', 'Promote to Prod', 'Hot-Reload Model'].map((step, i) => (
                        <React.Fragment key={step}>
                            <div className="text-center flex-shrink-0">
                                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border ${i < 2 ? 'border-neon-red text-neon-red bg-neon-red/10' : 'border-neon-green text-neon-green bg-neon-green/10'}`}>{i + 1}</div>
                                <p className="text-[9px] text-gray-500 mt-1 w-16 mx-auto leading-tight">{step}</p>
                            </div>
                            {i < 5 && <div className="w-6 h-px bg-white/20 flex-shrink-0" />}
                        </React.Fragment>
                    ))}
                </div>
            </Card>
        </div>
    );
};

export default DriftMonitor;
