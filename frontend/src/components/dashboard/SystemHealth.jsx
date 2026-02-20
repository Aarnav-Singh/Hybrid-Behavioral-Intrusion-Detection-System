import React from 'react';
import Card from '../ui/Card';
import { Cpu, HardDrive, Network, Server, Zap } from 'lucide-react';

const ProgressBar = ({ value, color = "bg-neon-green" }) => (
    <div className="w-full h-1 bg-white/10 mt-2">
        <div className={`h-full ${color} transition-all duration-500`} style={{ width: `${Math.min(value, 100)}%` }} />
    </div>
);

const Gauge = ({ value, label, icon: Icon, color }) => (
    <Card className="flex flex-col items-center justify-center p-6 border-white/5">
        <Icon size={32} className={`mb-4 ${color}`} />
        <div className="text-3xl font-display font-bold text-white mb-1">{value}%</div>
        <div className="text-[10px] uppercase tracking-widest text-gray-500">{label}</div>
        <ProgressBar value={value} color={color.replace('text-', 'bg-')} />
    </Card>
);

const SystemHealth = ({ stats }) => {
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <Gauge value={stats?.cpu || 0} label="CPU Load" icon={Cpu} color="text-neon-cyan" />
            <Gauge value={stats?.memory || 0} label="Memory Usage" icon={Zap} color="text-neon-purple" />
            <Gauge value={stats?.disk || 0} label="Disk Usage" icon={HardDrive} color="text-neon-yellow" />
            <Gauge value={Math.min((stats?.network_in || 0) / 2, 100)} label="Bandwidth Saturation" icon={Network} color="text-neon-green" />

            {/* Detailed Stats */}
            <div className="col-span-full grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
                <Card title="Node Diagnostics">
                    <div className="space-y-6 p-2">
                        <div>
                            <div className="text-xs font-mono text-gray-500 mb-2">SYSTEM UPTIME</div>
                            <div className="text-3xl font-display text-white">{stats?.uptime || '0d 0h 0m'}</div>
                        </div>
                        <div>
                            <div className="text-xs font-mono text-gray-500 mb-4">THROUGHPUT</div>
                            <div className="flex justify-between items-end mb-2">
                                <span className="text-[10px] text-gray-400">INBOUND</span>
                                <span className="font-mono text-neon-cyan text-xs">{stats?.network_in || 0} MB/s</span>
                            </div>
                            <ProgressBar value={(stats?.network_in || 0) / 2} color="bg-neon-cyan" />
                        </div>
                        <div className="grid grid-cols-2 gap-4 pt-2">
                            <div className="bg-black/40 p-4 border border-neon-red/20 rounded">
                                <div className="text-xl font-bold text-neon-red">{stats?.threats_detected || 0}</div>
                                <div className="text-[10px] text-gray-500">DETECTED</div>
                            </div>
                            <div className="bg-black/40 p-4 border border-neon-green/20 rounded">
                                <div className="text-xl font-bold text-neon-green">{stats?.blocked_today || 0}</div>
                                <div className="text-[10px] text-gray-500">NEUTRALIZED</div>
                            </div>
                        </div>
                    </div>
                </Card>

                <Card title="Neural Engine Diagnostics">
                    <div className="space-y-4 p-2">
                        <div className="flex justify-between items-center bg-white/5 p-3 rounded">
                            <span className="text-xs text-gray-400">Algorithm</span>
                            <span className="text-xs font-mono text-white">Isolation Forest (v1.4)</span>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <div className="text-[10px] text-gray-500 mb-1 uppercase">Precision</div>
                                <div className="text-2xl font-display text-neon-purple">{(stats?.modelMetrics?.precision || 0.95).toFixed(3)}</div>
                            </div>
                            <div>
                                <div className="text-[10px] text-gray-500 mb-1 uppercase">Recall (TPR)</div>
                                <div className="text-2xl font-display text-neon-green">{(stats?.modelMetrics?.recall || 0.92).toFixed(3)}</div>
                            </div>
                        </div>
                        <div className="pt-2">
                            <div className="flex justify-between text-[10px] uppercase tracking-widest text-gray-500 mb-2">
                                <span>Inference Latency</span>
                                <span className="text-neon-cyan">{(stats?.modelMetrics?.latency_ms || 1.2)}ms / Packet</span>
                            </div>
                            <ProgressBar value={(stats?.modelMetrics?.latency_ms || 1.2) * 20} color="bg-neon-cyan" />
                        </div>
                        <div className="mt-2 text-[8px] font-mono text-gray-600">
                            LAST TRAINING: 2026-02-19 14:22:10 UTC | CONTAMINATION: 0.10
                        </div>
                    </div>
                </Card>
            </div>
        </div>
    );
};

export default SystemHealth;
