import React from 'react';
import { Beaker, Download } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const mockExperiments = [
    { name: 'Baseline (LightGBM)', prAUC: 0.65, asr: 0.45 },
    { name: 'TCN Only', prAUC: 0.76, asr: 0.32 },
    { name: 'Node2Vec + TCN', prAUC: 0.85, asr: 0.21 },
    { name: 'GraphSAGE + TCN (Hybrid)', prAUC: 0.94, asr: 0.08 },
];

export function Experiments() {
    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold tracking-tight text-white flex items-center">
                    <Beaker className="h-8 w-8 text-indigo-500 mr-3" />
                    Ablation Experiments
                </h1>
                <button className="flex items-center px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white text-sm font-medium rounded-lg border border-gray-700 transition-colors">
                    <Download className="h-4 w-4 mr-2" />
                    Export JSON Report
                </button>
            </div>
            <p className="text-gray-400 max-w-3xl">
                Review the performance of various model architectures under adversarial stress.
                Higher PR-AUC indicates better detection, while lower Attack Success Rate (ASR) indicates better robustness.
            </p>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">

                {/* Chart 1: PR-AUC */}
                <div className="bg-[#0f172a] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-medium text-gray-200 mb-6 flex items-center">
                        Precision-Recall AUC (Higher is Better)
                    </h3>
                    <div className="h-80 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={mockExperiments} layout="vertical" margin={{ left: 80 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
                                <XAxis type="number" domain={[0, 1]} stroke="#64748b" />
                                <YAxis dataKey="name" type="category" stroke="#64748b" tick={{ fill: '#cbd5e1', fontSize: 12 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                                    itemStyle={{ color: '#818cf8' }}
                                />
                                <Bar dataKey="prAUC" fill="#6366f1" radius={[0, 4, 4, 0]} barSize={30} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Chart 2: ASR */}
                <div className="bg-[#0f172a] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-medium text-gray-200 mb-6 flex items-center">
                        Attack Success Rate (Lower is Better)
                    </h3>
                    <div className="h-80 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={mockExperiments} layout="vertical" margin={{ left: 80 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
                                <XAxis type="number" domain={[0, 1]} stroke="#64748b" />
                                <YAxis dataKey="name" type="category" stroke="#64748b" tick={{ fill: '#cbd5e1', fontSize: 12 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                                    itemStyle={{ color: '#f87171' }}
                                />
                                <Bar dataKey="asr" fill="#ef4444" radius={[0, 4, 4, 0]} barSize={30} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

            </div>
        </div>
    );
}
