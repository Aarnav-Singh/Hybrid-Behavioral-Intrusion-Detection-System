import React, { useState, useEffect } from 'react';
import Card from '../ui/Card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { Globe, ShieldAlert, TrendingUp } from 'lucide-react';
import { api } from '../../services/api';

const MITRE_TECHNIQUES = [
    { id: 'T1046', name: 'Network Service Scan', tactic: 'Discovery', covered: true },
    { id: 'T1110', name: 'Brute Force', tactic: 'Credential', covered: true },
    { id: 'T1190', name: 'Exploit Public App', tactic: 'Initial Access', covered: true },
    { id: 'T1499', name: 'DoS / Endpoint Denial', tactic: 'Impact', covered: true },
    { id: 'T1071', name: 'App Layer Protocol', tactic: 'C2', covered: false },
    { id: 'T1059', name: 'Command Interpreter', tactic: 'Execution', covered: false },
];

const ATTACK_TYPES_24H = [
    { time: '00:00', sqlinjection: 3, bruteforce: 5, dos: 12, traversal: 2, portscan: 8 },
    { time: '02:00', sqlinjection: 1, bruteforce: 2, dos: 5, traversal: 1, portscan: 3 },
    { time: '04:00', sqlinjection: 0, bruteforce: 1, dos: 3, traversal: 0, portscan: 2 },
    { time: '06:00', sqlinjection: 2, bruteforce: 4, dos: 8, traversal: 1, portscan: 6 },
    { time: '08:00', sqlinjection: 8, bruteforce: 12, dos: 25, traversal: 4, portscan: 18 },
    { time: '10:00', sqlinjection: 15, bruteforce: 18, dos: 38, traversal: 7, portscan: 22 },
    { time: '12:00', sqlinjection: 12, bruteforce: 14, dos: 30, traversal: 5, portscan: 20 },
    { time: '14:00', sqlinjection: 18, bruteforce: 22, dos: 42, traversal: 9, portscan: 28 },
    { time: '16:00', sqlinjection: 22, bruteforce: 25, dos: 55, traversal: 11, portscan: 35 },
    { time: '18:00', sqlinjection: 14, bruteforce: 16, dos: 33, traversal: 6, portscan: 22 },
    { time: '20:00', sqlinjection: 9, bruteforce: 11, dos: 20, traversal: 4, portscan: 15 },
    { time: '22:00', sqlinjection: 5, bruteforce: 7, dos: 15, traversal: 3, portscan: 10 },
];

const ForensicsPanel = ({ topIPs }) => {
    const [ips, setIps] = useState(topIPs || [
        { ip: '192.168.1.105', count: 42, risk: 0.94, type: 'SQL Injection', last: '2 min ago' },
        { ip: '10.0.0.47', count: 35, risk: 0.88, type: 'Brute Force', last: '5 min ago' },
        { ip: '172.16.0.22', count: 28, risk: 0.82, type: 'Port Scan', last: '8 min ago' },
        { ip: '203.0.113.5', count: 18, risk: 0.76, type: 'DoS Flood', last: '12 min ago' },
        { ip: '198.51.100.3', count: 12, risk: 0.65, type: 'Path Traversal', last: '22 min ago' },
        { ip: '10.10.5.200', count: 9, risk: 0.58, type: 'Slow-and-Low', last: '31 min ago' },
        { ip: '192.0.2.44', count: 6, risk: 0.45, type: 'Mimicry', last: '55 min ago' },
    ]);

    const covered = MITRE_TECHNIQUES.filter(t => t.covered).length;

    useEffect(() => {
        api.getTopIPs().then(data => { if (data?.length) setIps(data); }).catch(() => { });
    }, []);

    return (
        <div className="space-y-6">
            {/* KPIs */}
            <div className="grid grid-cols-3 gap-4">
                <Card className="p-4 border-neon-red/30 bg-neon-red/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest">Unique Threat IPs</p>
                    <p className="text-3xl font-display text-neon-red">{ips.length}</p>
                    <p className="text-[10px] text-gray-600 mt-1">last 24 hours</p>
                </Card>
                <Card className="p-4 border-neon-green/30 bg-neon-green/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest">MITRE Coverage</p>
                    <p className="text-3xl font-display text-neon-green">{covered}/{MITRE_TECHNIQUES.length}</p>
                    <p className="text-[10px] text-gray-600 mt-1">ATT&amp;CK techniques</p>
                </Card>
                <Card className="p-4 border-neon-purple/30 bg-neon-purple/5">
                    <p className="text-[10px] text-gray-500 uppercase tracking-widest">Highest Risk Score</p>
                    <p className="text-3xl font-display text-neon-purple">{ips[0]?.risk?.toFixed(2) || '0.00'}</p>
                    <p className="text-[10px] text-gray-600 mt-1">{ips[0]?.ip || '—'}</p>
                </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Top Threat Sources */}
                <Card title="Top Threat Sources">
                    <div className="space-y-2 p-2">
                        {ips.map((ip, i) => (
                            <div key={ip.ip} className="flex items-center gap-3 p-2.5 bg-black/30 rounded hover:bg-white/5 transition-colors">
                                <span className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold bg-neon-red/20 text-neon-red border border-neon-red/40">
                                    {i + 1}
                                </span>
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs font-mono text-white font-bold">{ip.ip}</span>
                                        <span className="text-[10px] font-bold font-mono" style={{ color: ip.risk > 0.8 ? '#FF003C' : ip.risk > 0.6 ? '#FFF01F' : '#00FF41' }}>
                                            {(ip.risk * 100).toFixed(0)}%
                                        </span>
                                    </div>
                                    <div className="flex items-center justify-between mt-0.5">
                                        <span className="text-[10px] text-gray-500">{ip.type || ip.attack_type}</span>
                                        <span className="text-[9px] text-gray-600">{ip.last || 'recently'}</span>
                                    </div>
                                    {/* Risk Bar */}
                                    <div className="w-full h-1 bg-white/10 rounded mt-1.5">
                                        <div className="h-1 rounded transition-all"
                                            style={{ width: `${(ip.risk || ip?.count / ips[0]?.count) * 100}%`, background: ip.risk > 0.8 ? '#FF003C' : ip.risk > 0.6 ? '#FFF01F' : '#00FF41' }} />
                                    </div>
                                </div>
                                <span className="text-[10px] text-gray-600 font-mono flex-shrink-0">{ip.count}x</span>
                            </div>
                        ))}
                    </div>
                </Card>

                {/* MITRE ATT&CK Coverage */}
                <Card title="MITRE ATT&CK Coverage">
                    <div className="space-y-3 p-2">
                        {MITRE_TECHNIQUES.map(t => (
                            <div key={t.id} className="flex items-center gap-3 p-2.5 bg-black/30 rounded">
                                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${t.covered ? 'bg-neon-green shadow-[0_0_6px_#00FF41]' : 'bg-gray-700'}`} />
                                <div className="flex-1">
                                    <div className="flex items-center gap-2">
                                        <span className="text-[10px] font-mono text-gray-400">{t.id}</span>
                                        <span className="text-xs text-white">{t.name}</span>
                                    </div>
                                    <span className="text-[9px] text-gray-600">{t.tactic}</span>
                                </div>
                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded border ${t.covered ? 'text-neon-green border-neon-green/40 bg-neon-green/10' : 'text-gray-600 border-gray-700'}`}>
                                    {t.covered ? 'COVERED' : 'PLANNED'}
                                </span>
                            </div>
                        ))}
                        <div className="text-[9px] text-gray-600 pt-1 font-mono">
                            Compliance: NIST CSF DE.AE · RS.MI · SOC 2 Monitoring
                        </div>
                    </div>
                </Card>
            </div>

            {/* Attack Timeline */}
            <Card title="Attack Type Timeline (24 Hours)">
                <ResponsiveContainer width="100%" height={240}>
                    <AreaChart data={ATTACK_TYPES_24H}>
                        <defs>
                            {[['sql', '#FF003C'], ['bf', '#FFF01F'], ['dos', '#00F3FF'], ['trav', '#BC13FE'], ['scan', '#00FF41']].map(([id, color]) => (
                                <linearGradient key={id} id={`grad-${id}`} x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                                    <stop offset="95%" stopColor={color} stopOpacity={0} />
                                </linearGradient>
                            ))}
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                        <XAxis dataKey="time" stroke="#666" fontSize={9} tickLine={false} axisLine={false} />
                        <YAxis stroke="#666" fontSize={9} tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={{ background: '#050505', border: '1px solid #333', fontSize: 10, fontFamily: 'monospace' }} />
                        <Area type="monotone" dataKey="sqlinjection" name="SQL Injection" stroke="#FF003C" fill="url(#grad-sql)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="bruteforce" name="Brute Force" stroke="#FFF01F" fill="url(#grad-bf)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="dos" name="DoS Flood" stroke="#00F3FF" fill="url(#grad-dos)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="traversal" name="Path Traversal" stroke="#BC13FE" fill="url(#grad-trav)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="portscan" name="Port Scan" stroke="#00FF41" fill="url(#grad-scan)" strokeWidth={1.5} />
                    </AreaChart>
                </ResponsiveContainer>
            </Card>
        </div>
    );
};

export default ForensicsPanel;
