import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity, Shield, Cpu, Target, Octagon, CheckCircle, HardDrive, Network, Zap, Server } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { cn } from '../../lib/utils';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';

// -- Animation Variants --
const containerVariants = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.1 } }
};

const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 300, damping: 24 } }
};

const ProgressBar = ({ value, color = "bg-neon-green" }) => (
    <div className="w-full h-1 bg-white/10 mt-2 overflow-hidden">
        <motion.div
            className={`h-full ${color}`}
            initial={{ width: 0 }}
            animate={{ width: `${Math.min(value || 0, 100)}%` }}
            transition={{ duration: 0.8, ease: 'easeOut' }}
        />
    </div>
);

const Gauge = ({ value, label, icon: Icon, color }) => (
    <div className="flex flex-col items-center justify-center p-4 bg-black/40 border border-white/5 rounded">
        <Icon size={24} className={`mb-3 ${color}`} />
        <div className="text-2xl font-display font-bold text-white mb-1">{value}%</div>
        <div className="text-[9px] uppercase tracking-widest text-gray-500">{label}</div>
        <ProgressBar value={value} color={color.replace('text-', 'bg-')} />
    </div>
);

const Overview = ({ alerts, trafficData, systemStats, distribution, modelMetrics, topIps, onUpdateAlert }) => {
    const [severityFilter, setSeverityFilter] = useState('ALL');

    // Metrics
    const metrics = [
        { label: 'Active Threats', value: systemStats?.threats_detected || 0, icon: Shield, color: 'text-neon-red' },
        { label: 'Network Load', value: `${systemStats?.network_in || 0} Mb/s`, icon: Activity, color: 'text-neon-cyan' },
        { label: 'Detection Rate', value: `${((modelMetrics?.recall || 0.9) * 100).toFixed(1)}%`, icon: Target, color: 'text-neon-purple' },
        { label: 'Events Analyzed', value: systemStats?.alerts_today || 0, icon: Cpu, color: 'text-neon-green' },
    ];

    const BAR_COLORS = ['#00FF41', '#00F3FF', '#BC13FE', '#FF003C', '#FFF01F', '#FF00A0'];

    // Alerts filtering
    const filteredAlerts = useMemo(() => {
        let result = alerts;
        if (severityFilter !== 'ALL') {
            result = alerts.filter(a => a.severity === severityFilter);
        }
        return result.slice(0, 15); // Show only recent 15 in the feed
    }, [alerts, severityFilter]);

    return (
        <motion.div
            className="space-y-6"
            variants={containerVariants}
            initial="hidden"
            animate="show"
        >
            {/* --- ROW 1: KPI Grid --- */}
            <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {metrics.map((m) => (
                    <Card key={m.label} className="p-4 flex items-center justify-between">
                        <div>
                            <p className="text-[10px] text-gray-500 uppercase tracking-widest">{m.label}</p>
                            <p className={`text-3xl font-display font-bold ${m.color} text-glow mt-1`}>{m.value}</p>
                        </div>
                        <m.icon size={28} className={`${m.color} opacity-80`} />
                    </Card>
                ))}
            </motion.div>

            {/* --- ROW 2: Charts and Live Feed --- */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Left Column (2/3 width) - Charts */}
                <div className="lg:col-span-2 space-y-6">
                    <motion.div variants={itemVariants}>
                        <Card title="Traffic Volatility & Alert Volume" className="h-[300px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={trafficData}>
                                    <defs>
                                        <linearGradient id="colorIn" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#00F3FF" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#00F3FF" stopOpacity={0} />
                                        </linearGradient>
                                        <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="5%" stopColor="#FF003C" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#FF003C" stopOpacity={0} />
                                        </linearGradient>
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                                    <XAxis dataKey="time" stroke="#666" fontSize={10} tickLine={false} axisLine={false} />
                                    <YAxis stroke="#666" fontSize={10} tickLine={false} axisLine={false} />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#050505', borderColor: '#333', fontSize: '10px', fontFamily: 'monospace' }}
                                        itemStyle={{ color: '#fff' }}
                                    />
                                    <Area type="monotone" dataKey="inbound" stroke="#00F3FF" strokeWidth={2} fillOpacity={1} fill="url(#colorIn)" />
                                    <Area type="monotone" dataKey="threats" stroke="#FF003C" strokeWidth={2} fillOpacity={1} fill="url(#colorOut)" />
                                </AreaChart>
                            </ResponsiveContainer>
                        </Card>
                    </motion.div>

                    <motion.div variants={itemVariants}>
                        <Card title="Threat Classification Distribution" className="h-[250px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={distribution} layout="vertical">
                                    <CartesianGrid strokeDasharray="3 3" stroke="#222" horizontal={false} />
                                    <XAxis type="number" stroke="#666" fontSize={10} tickLine={false} axisLine={false} />
                                    <YAxis dataKey="name" type="category" stroke="#888" fontSize={10} width={120} tickLine={false} axisLine={false} />
                                    <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: '#050505', borderColor: '#333', fontSize: '10px' }} />
                                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                        {distribution.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={BAR_COLORS[index % BAR_COLORS.length]} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </Card>
                    </motion.div>
                </div>

                {/* Right Column (1/3 width) - Live Feed */}
                <motion.div variants={itemVariants} className="lg:col-span-1">
                    <Card title="Live Alert Feed" className="h-[574px] flex flex-col">
                        <div className="flex gap-2 mb-3">
                            {['ALL', 'CRITICAL', 'HIGH'].map(sev => (
                                <Button
                                    key={sev}
                                    variant={severityFilter === sev ? 'default' : 'ghost'}
                                    size="sm"
                                    onClick={() => setSeverityFilter(sev)}
                                    className="text-[9px] h-6 px-2"
                                >
                                    {sev}
                                </Button>
                            ))}
                        </div>
                        <div className="overflow-y-auto flex-1 custom-scrollbar space-y-2 pr-1">
                            <AnimatePresence initial={false}>
                                {filteredAlerts.length === 0 ? (
                                    <div className="text-center py-8 text-gray-500 font-mono text-xs">No active threats detected.</div>
                                ) : (
                                    filteredAlerts.map((alert) => (
                                        <motion.div
                                            key={alert.id || alert._id}
                                            initial={{ opacity: 0, x: 20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            exit={{ opacity: 0, scale: 0.9 }}
                                            transition={{ type: "spring", stiffness: 300, damping: 25 }}
                                            className={cn(
                                                "p-3 rounded border bg-black/50 transition-colors cursor-default",
                                                alert.severity === 'CRITICAL' ? 'border-neon-red/50 hover:border-neon-red' :
                                                    alert.severity === 'HIGH' ? 'border-orange-500/50 hover:border-orange-500' :
                                                        'border-white/10 hover:border-white/30'
                                            )}
                                        >
                                            <div className="flex justify-between items-start mb-1">
                                                <Badge variant={alert.severity} className="text-[9px] px-1 py-0 h-4">{alert.severity}</Badge>
                                                <span className="font-mono text-[10px] text-gray-400">{alert.timestamp.split(' ')[1] || alert.timestamp}</span>
                                            </div>
                                            <div className="font-bold text-white text-xs mb-1 truncate">{alert.attack_type}</div>
                                            <div className="flex justify-between items-center text-[10px] font-mono text-gray-400 mb-2">
                                                <span className="text-neon-cyan truncate">{alert.source_ip}</span>
                                                <span>{alert.protocol}</span>
                                            </div>

                                            {alert.status === 'ACTIVE' && (
                                                <div className="flex gap-2 mt-2 pt-2 border-t border-white/5">
                                                    <button onClick={() => onUpdateAlert(alert._id, 'BLOCKED')} className="flex-1 flex items-center justify-center text-[9px] border border-neon-red/30 text-neon-red hover:bg-neon-red/10 py-1 transition-colors">
                                                        <Octagon size={10} className="mr-1" /> BLOCK
                                                    </button>
                                                    <button onClick={() => onUpdateAlert(alert._id, 'RESOLVED')} className="flex-1 flex items-center justify-center text-[9px] border border-white/20 text-gray-300 hover:bg-white/10 py-1 transition-colors">
                                                        <CheckCircle size={10} className="mr-1" /> OK
                                                    </button>
                                                </div>
                                            )}
                                            {alert.status !== 'ACTIVE' && (
                                                <div className={cn(
                                                    "text-[9px] text-right font-bold mt-1 tracking-wider uppercase",
                                                    alert.status === 'BLOCKED' ? 'text-neon-red' : 'text-neon-green'
                                                )}>
                                                    [{alert.status}]
                                                </div>
                                            )}
                                        </motion.div>
                                    ))
                                )}
                            </AnimatePresence>
                        </div>
                    </Card>
                </motion.div>

            </div>

            {/* --- ROW 3: System Health & Top IPs & Neural Engine --- */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* System Diagnostics */}
                <motion.div variants={itemVariants}>
                    <Card title="Node Diagnostics" className="h-[250px]">
                        <div className="grid grid-cols-2 gap-4 mb-4">
                            <Gauge value={systemStats?.cpu || 0} label="CPU Load" icon={Cpu} color="text-neon-cyan" />
                            <Gauge value={systemStats?.memory || 0} label="Memory" icon={Zap} color="text-neon-purple" />
                        </div>
                        <div className="flex justify-between items-end mb-1 px-1">
                            <span className="text-[10px] text-gray-400 uppercase tracking-widest">Inbound Throughput</span>
                            <span className="font-mono text-neon-cyan text-xs">{systemStats?.network_in || 0} MB/s</span>
                        </div>
                        <ProgressBar value={(systemStats?.network_in || 0) / 2} color="bg-neon-cyan" />
                    </Card>
                </motion.div>

                {/* Neural Engine */}
                <motion.div variants={itemVariants}>
                    <Card title="Neural Engine Core" className="h-[250px]">
                        <div className="space-y-4 p-2">
                            <div className="flex justify-between items-center bg-white/5 p-3 rounded">
                                <span className="text-xs text-gray-400">Algorithm</span>
                                <span className="text-xs font-mono text-white">Isolation Forest (v1.4)</span>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <div className="text-[10px] text-gray-500 mb-1 uppercase">Precision</div>
                                    <div className="text-2xl font-display text-neon-purple">{(modelMetrics?.precision || 0.95).toFixed(3)}</div>
                                </div>
                                <div>
                                    <div className="text-[10px] text-gray-500 mb-1 uppercase">Recall (TPR)</div>
                                    <div className="text-2xl font-display text-neon-green">{(modelMetrics?.recall || 0.92).toFixed(3)}</div>
                                </div>
                            </div>
                            <div className="pt-2">
                                <div className="flex justify-between text-[10px] uppercase tracking-widest text-gray-500 mb-2">
                                    <span>Inference Latency</span>
                                    <span className="text-neon-cyan">{(modelMetrics?.latency_ms || 1.2)}ms</span>
                                </div>
                                <ProgressBar value={(modelMetrics?.latency_ms || 1.2) * 20} color="bg-neon-cyan" />
                            </div>
                        </div>
                    </Card>
                </motion.div>

                {/* Top IPs */}
                <motion.div variants={itemVariants}>
                    <Card title="Top Threat Sources" className="h-[250px]">
                        <div className="space-y-3 mt-2 pr-2 overflow-y-auto h-[170px] custom-scrollbar">
                            {topIps?.length > 0 ? topIps.map((target, idx) => (
                                <div key={idx} className="flex justify-between items-center bg-black/40 p-2 border border-white/5 rounded">
                                    <div className="flex items-center gap-2">
                                        <span className="text-[10px] font-mono text-gray-500">#{idx + 1}</span>
                                        <span className="text-xs font-mono text-neon-red">{target.ip}</span>
                                    </div>
                                    <Badge variant="destructive" className="text-[9px] rounded px-1.5 h-4">{target.count} Hits</Badge>
                                </div>
                            )) : (
                                <div className="text-[10px] text-gray-500 font-mono text-center mt-8">NO SIGNIFICANT THREAT SOURCES</div>
                            )}
                        </div>
                    </Card>
                </motion.div>
            </div>

        </motion.div>
    );
};

export default Overview;
