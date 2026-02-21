import React from 'react';
import Card from '../ui/Card';
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Swords, Shield, Eye, Zap } from 'lucide-react';

const TECHNIQUES = [
    { id: 1, name: 'Feature Dilution', desc: 'Mix malicious requests with benign traffic at high ratio', impact: 'PARTIAL', layer: 'ML', detect: 'Anomaly score degrades ~20%; behavioral detects residual signal' },
    { id: 2, name: 'Slow-and-Low', desc: 'Reduce request rate below rule threshold for extended period', impact: 'PARTIAL', layer: 'Behavioral', detect: 'Baseline deviation fires at 2.5σ after 7-min window' },
    { id: 3, name: 'Mimicry Attack', desc: 'Copy benign URI patterns inside attack request payloads', impact: 'PARTIAL', layer: 'Rules', detect: 'Entropy analysis partial; ML still detects structural anomaly' },
    { id: 4, name: 'IP Rotation', desc: 'Rotate source IPs every N requests to avoid per-IP thresholds', impact: 'EVADES', layer: 'Rules', detect: 'Aggregate flow analysis detects distributed pattern' },
    { id: 5, name: 'Timing Jitter', desc: 'Randomize inter-request intervals to evade rate detection', impact: 'PARTIAL', layer: 'Rules', detect: 'Increases detection latency by ~30s; behavioral baseline catches' },
    { id: 6, name: 'URL Encoding', desc: 'Percent-encode SQL/traversal chars to bypass regex signatures', impact: 'EVADES', layer: 'Rules', detect: 'Deep payload entropy analysis catches encoded anomalies' },
    { id: 7, name: 'Credential Stuffing', desc: 'Distributed login attempts using credential-breach dumps', impact: 'DETECTS', layer: 'Hybrid', detect: '401 error rate + session velocity spike triggers within 60s' },
];

const IMPACT_COLORS = { DETECTS: '#00FF41', PARTIAL: '#FFF01F', EVADES: '#FF003C' };
const LAYER_COLORS = { Rules: '#f59e0b', ML: '#3b82f6', Behavioral: '#a855f7', Hybrid: '#00FF41' };

const RADAR_DATA = [
    { attack: 'SQL Injection', rule: 90, ml: 95, behavioral: 70 },
    { attack: 'Brute Force', rule: 85, ml: 80, behavioral: 90 },
    { attack: 'DoS Flood', rule: 95, ml: 85, behavioral: 75 },
    { attack: 'Slow-and-Low', rule: 30, ml: 65, behavioral: 85 },
    { attack: 'IP Rotation', rule: 20, ml: 70, behavioral: 80 },
    { attack: 'Mimicry', rule: 45, ml: 75, behavioral: 65 },
    { attack: 'Credential Stuff', rule: 70, ml: 80, behavioral: 95 },
];

const AdversarialLab = () => (
    <div className="space-y-6">
        {/* Summary Stats */}
        <div className="grid grid-cols-3 gap-4">
            <Card className="p-4 border-neon-green/30 bg-neon-green/5">
                <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Fully Detected</p>
                <p className="text-3xl font-display text-neon-green">{TECHNIQUES.filter(t => t.impact === 'DETECTS').length}</p>
                <p className="text-[10px] text-gray-600 mt-1">techniques neutralized</p>
            </Card>
            <Card className="p-4 border-yellow-400/30 bg-yellow-400/5">
                <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Partially Evaded</p>
                <p className="text-3xl font-display text-yellow-400">{TECHNIQUES.filter(t => t.impact === 'PARTIAL').length}</p>
                <p className="text-[10px] text-gray-600 mt-1">require multi-signal</p>
            </Card>
            <Card className="p-4 border-neon-red/30 bg-neon-red/5">
                <p className="text-[10px] text-gray-500 uppercase tracking-widest mb-1">Evasion Risk</p>
                <p className="text-3xl font-display text-neon-red">{TECHNIQUES.filter(t => t.impact === 'EVADES').length}</p>
                <p className="text-[10px] text-gray-600 mt-1">rule-bypass techniques</p>
            </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Radar Chart */}
            <Card title="Detection Layer Coverage per Attack">
                <ResponsiveContainer width="100%" height={320}>
                    <RadarChart data={RADAR_DATA}>
                        <PolarGrid stroke="#222" />
                        <PolarAngleAxis dataKey="attack" stroke="#888" fontSize={9} />
                        <PolarRadiusAxis domain={[0, 100]} tick={false} />
                        <Radar name="Rule Engine" dataKey="rule" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.1} />
                        <Radar name="ML Anomaly" dataKey="ml" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
                        <Radar name="Behavioral" dataKey="behavioral" stroke="#a855f7" fill="#a855f7" fillOpacity={0.1} />
                        <Tooltip contentStyle={{ background: '#050505', border: '1px solid #333', fontSize: 10 }} />
                    </RadarChart>
                </ResponsiveContainer>
                <div className="flex gap-4 px-4 pb-2">
                    {[['Rule Engine', '#f59e0b'], ['ML Anomaly', '#3b82f6'], ['Behavioral', '#a855f7']].map(([name, color]) => (
                        <div key={name} className="flex items-center gap-1 text-[10px]" style={{ color }}>
                            <span className="w-2 h-2 rounded-sm inline-block" style={{ background: color }} /> {name}
                        </div>
                    ))}
                </div>
            </Card>

            {/* MITRE Technique Cards */}
            <Card title="Evasion Technique Registry">
                <div className="space-y-2 p-2 max-h-80 overflow-y-auto">
                    {TECHNIQUES.map(t => (
                        <div key={t.id} className="flex items-start gap-3 p-3 bg-white/5 rounded border border-white/5 hover:border-white/10 transition-colors">
                            <div className="flex-shrink-0 w-6 h-6 rounded flex items-center justify-center text-[9px] font-bold border"
                                style={{ color: IMPACT_COLORS[t.impact], borderColor: IMPACT_COLORS[t.impact], background: IMPACT_COLORS[t.impact] + '22' }}>
                                {t.id}
                            </div>
                            <div>
                                <div className="flex items-center gap-2">
                                    <span className="text-xs text-white font-bold">{t.name}</span>
                                    <span className="text-[9px] px-1.5 rounded border font-bold"
                                        style={{ color: IMPACT_COLORS[t.impact], borderColor: IMPACT_COLORS[t.impact] + '66' }}>
                                        {t.impact}
                                    </span>
                                    <span className="text-[9px] px-1.5 rounded border font-bold"
                                        style={{ color: LAYER_COLORS[t.layer], borderColor: LAYER_COLORS[t.layer] + '66' }}>
                                        {t.layer}
                                    </span>
                                </div>
                                <p className="text-[10px] text-gray-500 mt-0.5 leading-tight">{t.detect}</p>
                            </div>
                        </div>
                    ))}
                </div>
            </Card>
        </div>

        {/* Full Technique Table */}
        <Card title="Full Adversarial Technique Matrix">
            <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                    <thead>
                        <tr className="border-b border-white/10">
                            {['Technique', 'Description', 'Primary Layer', 'Impact', 'Detection Response'].map(h => (
                                <th key={h} className="text-left py-3 px-3 text-gray-500 uppercase tracking-widest text-[9px]">{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {TECHNIQUES.map(t => (
                            <tr key={t.id} className="border-b border-white/5 hover:bg-white/5">
                                <td className="py-2 px-3 text-white font-bold">{t.name}</td>
                                <td className="py-2 px-3 text-gray-400 max-w-xs">{t.desc}</td>
                                <td className="py-2 px-3"><span style={{ color: LAYER_COLORS[t.layer] }}>{t.layer}</span></td>
                                <td className="py-2 px-3">
                                    <span className="px-2 py-0.5 rounded text-[9px] font-bold border"
                                        style={{ color: IMPACT_COLORS[t.impact], borderColor: IMPACT_COLORS[t.impact], background: IMPACT_COLORS[t.impact] + '22' }}>
                                        {t.impact}
                                    </span>
                                </td>
                                <td className="py-2 px-3 text-gray-500 text-[10px] max-w-xs">{t.detect}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </Card>
    </div>
);

export default AdversarialLab;
