import React from 'react';
import { AlertTriangle, PlayCircle, Fingerprint } from 'lucide-react';

const mockAlerts = [
    {
        id: 'ALRT-001',
        entity: '192.168.1.12',
        score: 0.94,
        type: 'GraphSAGE Lateral Movement',
        time: '2024-03-24 10:25:31',
        shap: [
            { feature: 'delta_conn_count', value: '+0.45' },
            { feature: 'node2vec_embedding[12]', value: '+0.31' },
            { feature: 'dst_port_nunique', value: '+0.12' }
        ]
    },
    {
        id: 'ALRT-002',
        entity: 'admin.local',
        score: 0.88,
        type: 'TCN Temporal Anomaly (DNS Tunnel)',
        time: '2024-03-24 09:12:05',
        shap: [
            { feature: 'domain_entropy', value: '+0.55' },
            { feature: 'domain_nunique', value: '+0.25' }
        ]
    }
];

export function Alerts() {
    return (
        <div className="space-y-6">
            <h1 className="text-3xl font-bold tracking-tight text-white mb-6">Security Alerts</h1>

            <div className="space-y-6">
                {mockAlerts.map((alert) => (
                    <div key={alert.id} className="bg-[#0f172a] border border-red-500/20 rounded-xl p-6 shadow-xl relative overflow-hidden group">
                        <div className="absolute top-0 left-0 w-1 h-full bg-red-500 group-hover:bg-red-400 transition-colors"></div>

                        <div className="flex justify-between items-start">
                            <div>
                                <div className="flex items-center space-x-3 mb-2">
                                    <AlertTriangle className="h-6 w-6 text-red-500" />
                                    <h2 className="text-xl font-bold text-gray-100">{alert.type}</h2>
                                    <span className="px-2 py-1 bg-gray-800 text-gray-400 text-xs rounded border border-gray-700">{alert.id}</span>
                                </div>
                                <p className="text-gray-400 font-mono text-sm mb-4">Entity: <span className="text-blue-400">{alert.entity}</span> | Time: {alert.time}</p>
                            </div>

                            <div className="text-right">
                                <div className="text-3xl font-black text-red-500">{alert.score.toFixed(2)}</div>
                                <div className="text-xs tracking-widest text-gray-500 uppercase mt-1">Anomaly Score</div>
                            </div>
                        </div>

                        <div className="mt-4 pt-4 border-t border-gray-800 grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3 flex items-center">
                                    <Fingerprint className="h-4 w-4 mr-2 text-indigo-400" />
                                    SHAP Feature Contributions
                                </h3>
                                <div className="space-y-2">
                                    {alert.shap.map((s, i) => (
                                        <div key={i} className="flex justify-between items-center text-sm">
                                            <span className="font-mono text-gray-400">{s.feature}</span>
                                            <span className="text-red-400 font-bold bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">{s.value}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="flex flex-col justify-end items-end space-y-3">
                                <button className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg shadow transition-colors">
                                    <PlayCircle className="h-4 w-4 mr-2" />
                                    Replay in Attack Lab
                                </button>
                            </div>
                        </div>

                    </div>
                ))}
            </div>
        </div>
    );
}
