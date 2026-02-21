import React from 'react';
import { Shield, Activity, TrendingUp, AlertTriangle } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const dummyData = [
    { time: '10:00', score: 0.1 },
    { time: '10:05', score: 0.15 },
    { time: '10:10', score: 0.12 },
    { time: '10:15', score: 0.85 },
    { time: '10:20', score: 0.92 },
    { time: '10:25', score: 0.2 },
];

export function Overview() {
    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold tracking-tight text-white">System Overview</h1>
                <div className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-sm font-medium border border-blue-500/30">
                    Hybrid Mode Active
                </div>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                {[
                    { name: 'Active Threats', stat: '3', icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
                    { name: 'Events/sec', stat: '4,200', icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
                    { name: 'Precision @ 1%', stat: '94.2%', icon: TrendingUp, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
                    { name: 'Graph Drift', stat: '0.12', icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
                ].map((item) => (
                    <div key={item.name} className={`relative overflow-hidden rounded-xl bg-[#0f172a] p-5 shadow-lg border ${item.border}`}>
                        <dt>
                            <div className={`absolute rounded-md p-3 ${item.bg}`}>
                                <item.icon className={`h-6 w-6 ${item.color}`} aria-hidden="true" />
                            </div>
                            <p className="ml-16 truncate text-sm font-medium text-gray-400">{item.name}</p>
                        </dt>
                        <dd className="ml-16 flex items-baseline pb-1 sm:pb-2">
                            <p className="text-2xl font-semibold text-white">{item.stat}</p>
                        </dd>
                    </div>
                ))}
            </div>

            {/* Charts section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-8">
                <div className="bg-[#0f172a] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-medium leading-6 text-gray-200 mb-4">Anomaly Score Timeline</h3>
                    <div className="h-72 w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={dummyData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                                <XAxis dataKey="time" stroke="#64748b" />
                                <YAxis stroke="#64748b" />
                                <Tooltip
                                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                                    itemStyle={{ color: '#60a5fa' }}
                                />
                                <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={3} dot={{ r: 4, fill: '#3b82f6' }} activeDot={{ r: 6 }} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="bg-[#0f172a] p-6 rounded-xl border border-gray-800 shadow-lg">
                    <h3 className="text-lg font-medium leading-6 text-gray-200 mb-4">Recent Alerts</h3>
                    <div className="divide-y divide-gray-800">
                        {['10.0.0.45 - Potential Beaconing', '192.168.1.12 - Lateral Movement (GraphSAGE)', 'admin.local - DNS Tunneling'].map((alert, i) => (
                            <div key={i} className="py-4 flex justify-between items-center group cursor-pointer">
                                <div className="flex items-center">
                                    <div className="h-2 w-2 rounded-full bg-red-500 mr-3"></div>
                                    <p className="text-sm font-medium text-gray-300 group-hover:text-blue-400 transition-colors">{alert}</p>
                                </div>
                                <span className="text-xs text-gray-500">Just now</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}
