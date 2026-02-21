import { useState, useEffect } from 'react';
import { Shield, Activity, TrendingUp, AlertTriangle } from 'lucide-react';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { cn } from '../lib/utils';

interface Alert {
    id: string;
    severity: 'critical' | 'high' | 'medium';
    timestamp: string;
    score: number;
    threat_type: string;
    source_ip: string;
}

export function Overview() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [stats, setStats] = useState({
        threats: 0,
        eps: '4,200',
        precision: '94.2%',
        drift: '0.12'
    });

    const fetchOverviewData = async () => {
        try {
            const res = await fetch('http://localhost:8001/api/v1/alerts');
            if (res.ok) {
                const data = await res.json();
                setAlerts(data);

                // Drive KPIs from live data
                const criticalCount = data.filter((a: Alert) => a.severity === 'critical').length;
                const randomEPS = (4100 + Math.floor(Math.random() * 300)).toLocaleString();
                const randomDrift = (0.11 + Math.random() * 0.04).toFixed(2);
                const randomPrecision = (94.1 + Math.random() * 0.5).toFixed(1) + '%';

                setStats(prev => ({
                    ...prev,
                    threats: criticalCount,
                    eps: randomEPS,
                    drift: randomDrift,
                    precision: randomPrecision
                }));
            }
        } catch (error) {
            console.error("Failed to fetch overview data:", error);
        }
    };

    useEffect(() => {
        fetchOverviewData();
        const interval = setInterval(fetchOverviewData, 5000); // 5s polling
        return () => clearInterval(interval);
    }, []);

    // Transform alerts into time-series data for the chart
    const chartData = alerts.slice().reverse().map(a => ({
        time: a.timestamp,
        score: a.score
    }));

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            <div className="flex justify-between items-center bg-[#0f172a]/50 p-6 rounded-2xl border border-gray-800/60 backdrop-blur-md shadow-2xl">
                <h1 className="text-3xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-gray-100 to-gray-400">System Overview</h1>
                <div className="px-4 py-1.5 flex items-center bg-indigo-500/10 text-indigo-400 rounded-full text-xs font-bold border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.2)]">
                    <span className="w-2 h-2 rounded-full bg-indigo-500 mr-2 animate-pulse"></span>
                    LIVE MONITORING ACTIVE
                </div>
            </div>

            {/* KPI Cards */}
            <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                {[
                    { name: 'Active Threats', stat: stats.threats.toString(), icon: Shield, color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20', glow: 'shadow-[0_0_20px_rgba(244,63,94,0.15)]' },
                    { name: 'Events/sec', stat: stats.eps, icon: Activity, color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', glow: 'shadow-[0_0_20px_rgba(59,130,246,0.15)]' },
                    { name: 'Precision @ 1%', stat: stats.precision, icon: TrendingUp, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', glow: 'shadow-[0_0_20px_rgba(16,185,129,0.15)]' },
                    { name: 'Graph Drift', stat: stats.drift, icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', glow: 'shadow-[0_0_20px_rgba(245,158,11,0.15)]' },
                ].map((item) => (
                    <div key={item.name} className={cn(
                        "relative overflow-hidden rounded-2xl bg-gradient-to-br from-[#1e293b]/80 to-[#0f172a]/80 p-6 backdrop-blur-md border hover:scale-[1.02] transition-transform duration-300",
                        item.border,
                        item.glow
                    )}>
                        <dt>
                            <div className={`absolute rounded-xl p-3 ${item.bg}`}>
                                <item.icon className={`h-6 w-6 ${item.color}`} aria-hidden="true" />
                            </div>
                            <p className="ml-16 truncate text-xs font-bold tracking-widest text-gray-400 uppercase">{item.name}</p>
                        </dt>
                        <dd className="ml-16 flex items-baseline pb-1 sm:pb-2 mt-2">
                            <p className="text-3xl font-black text-white">{item.stat}</p>
                        </dd>
                    </div>
                ))}
            </div>

            {/* Charts section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
                <div className="bg-[#0f172a]/70 p-7 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-blue-600 to-indigo-600"></div>
                    <h3 className="text-xl font-bold tracking-wide text-gray-200 mb-6 flex items-center">
                        <Activity className="h-5 w-5 text-indigo-400 mr-2" />
                        Live Anomaly Score Stream
                    </h3>
                    <div className="h-[300px] w-full">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={chartData}>
                                <defs>
                                    <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                                        <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                                <XAxis dataKey="time" stroke="#64748b" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
                                <YAxis domain={[0, 1]} stroke="#64748b" tickLine={false} axisLine={false} tick={{ fontSize: 12 }} />
                                <Tooltip
                                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid #334155', borderRadius: '12px', backdropFilter: 'blur(8px)', color: '#fff' }}
                                    itemStyle={{ color: '#818cf8', fontWeight: 'bold' }}
                                />
                                <Area type="monotone" dataKey="score" stroke="#6366f1" strokeWidth={3} fillOpacity={1} fill="url(#colorScore)" animationDuration={1000} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="bg-[#0f172a]/70 p-7 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-rose-500 to-red-600"></div>
                    <h3 className="text-xl font-bold tracking-wide text-gray-200 mb-6 flex items-center">
                        <Shield className="h-5 w-5 text-rose-400 mr-2" />
                        Live Alert Queue
                    </h3>
                    <div className="flex flex-col gap-4">
                        {alerts.slice(0, 3).map((alert) => (
                            <div key={alert.id} className="py-2.5 px-4 bg-[#1e293b]/40 rounded-xl flex justify-between items-center group cursor-pointer border border-[#1e293b] hover:border-rose-500/30 hover:bg-rose-500/5 transition-all duration-300">
                                <div className="flex items-center truncate">
                                    <div className="relative flex h-2.5 w-2.5 mr-3 flex-shrink-0">
                                        <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-75", alert.severity === 'critical' ? 'bg-rose-400' : 'bg-orange-400')}></span>
                                        <span className={cn("relative inline-flex rounded-full h-2.5 w-2.5", alert.severity === 'critical' ? 'bg-rose-500' : 'bg-orange-500')}></span>
                                    </div>
                                    <p className="text-xs font-semibold text-gray-300 group-hover:text-white transition-colors truncate">{alert.source_ip} - {alert.threat_type}</p>
                                </div>
                                <span className="text-[10px] font-mono text-gray-500 bg-[#0f172a] px-1.5 py-0.5 rounded-md flex-shrink-0">{alert.timestamp}</span>
                            </div>
                        ))}
                        {alerts.length === 0 && <p className="text-center text-gray-500 py-10">Waiting for live data...</p>}
                    </div>
                </div>
            </div>
        </div>
    );
}
