import { useState } from 'react';
import { Crosshair, PlayCircle, ShieldAlert, Cpu, Activity, Zap } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { cn } from '../lib/utils'; // Assuming 'cn' is a utility function like clsx or class-variance-authority

const generateDriftData = (intensity: number, hasAttack: boolean) => {
    return Array.from({ length: 20 }).map((_, i) => ({
        time: `${19}:${(10 + i).toString().padStart(2, '0')}`,
        baseline: 0.1 + Math.random() * 0.05,
        attack: hasAttack && i > 10
            ? 0.1 + (Math.random() * 0.1) + (intensity * 0.05)
            : 0.1 + Math.random() * 0.05
    }));
};

export function AttackLab() {
    const [attackType, setAttackType] = useState('feature_perturbation');
    const [targetIp, setTargetIp] = useState('10.0.0.45');
    const [intensity, setIntensity] = useState(2.0);
    const [isRunning, setIsRunning] = useState(false);
    const [data, setData] = useState(generateDriftData(2.0, true));
    const [metrics, setMetrics] = useState({
        asr: '87.2%',
        drift: '0.78',
        performance: '12.8%'
    });

    const handleLaunch = () => {
        setIsRunning(true);
        // Simulate a "calculation" period
        setTimeout(() => {
            const newAsr = (70 + (intensity * 3) + Math.random() * 5).toFixed(1) + '%';
            const newDrift = (0.5 + (intensity * 0.1) + Math.random() * 0.1).toFixed(2);
            const newPerf = (5 + (intensity * 2) + Math.random() * 5).toFixed(1) + '%';

            setMetrics({ asr: newAsr, drift: newDrift, performance: newPerf });
            setData(generateDriftData(intensity, true));
            setIsRunning(false);
        }, 1500);
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500 pb-10">
            <div className="flex justify-between items-center bg-[#0f172a]/50 p-6 rounded-2xl border border-rose-500/20 backdrop-blur-md shadow-2xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-2 h-full bg-rose-500"></div>
                <div>
                    <h1 className="text-3xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-rose-400 to-red-600 flex items-center">
                        <Crosshair className="h-8 w-8 text-rose-500 mr-3" />
                        Adversarial Attack Lab
                    </h1>
                    <p className="text-gray-400 mt-2 font-medium">Inject synthetic red-team telemetry into the data stream to evaluate model robustness.</p>
                </div>
                <div className="px-4 py-1.5 flex items-center bg-rose-500/10 text-rose-400 rounded-full text-xs font-bold border border-rose-500/30 shadow-[0_0_15px_rgba(244,63,94,0.2)]">
                    <span className="w-2 h-2 rounded-full bg-rose-500 mr-2 animate-pulse"></span>
                    RED TEAM MODE
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Configuration Panel */}
                <div className="lg:col-span-1 bg-[#0f172a]/70 p-7 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-600 to-purple-600"></div>
                    <h2 className="text-xl font-bold text-gray-200 mb-6 flex items-center">
                        <Cpu className="h-5 w-5 mr-3 text-indigo-400" />
                        Attack Configuration
                    </h2>

                    <div className="space-y-6">
                        <div>
                            <label className="block text-sm font-bold tracking-wide text-gray-400 mb-2 uppercase">Scenario Type</label>
                            <select
                                value={attackType}
                                onChange={(e) => setAttackType(e.target.value)}
                                className="w-full bg-[#1e293b]/50 border border-gray-700 rounded-xl px-4 py-3 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500/50 appearance-none font-medium transition-shadow hover:bg-[#1e293b]/80"
                            >
                                <option value="feature_perturbation">Feature Perturbation (Evasion)</option>
                                <option value="dns_tunneling">DNS Tunneling Simulation</option>
                                <option value="graph_poisoning">Graph Node Poisoning</option>
                                <option value="beacon_evasion">Low-and-Slow Beaconing</option>
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-bold tracking-wide text-gray-400 mb-2 uppercase">Target IP Segment</label>
                            <input
                                type="text"
                                value={targetIp}
                                onChange={(e) => setTargetIp(e.target.value)}
                                className="w-full bg-[#1e293b]/50 border border-gray-700 rounded-xl px-4 py-3 text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-shadow hover:bg-[#1e293b]/80"
                            />
                        </div>

                        <div>
                            <div className="flex justify-between items-center mb-2">
                                <label className="block text-sm font-bold tracking-wide text-gray-400 uppercase">Multiplier Intensity</label>
                                <span className="text-indigo-400 font-bold bg-indigo-500/10 px-2 py-0.5 rounded">{intensity}x</span>
                            </div>
                            <input
                                type="range"
                                min="1" max="10" step="0.5"
                                value={intensity}
                                onChange={(e) => setIntensity(parseFloat(e.target.value))}
                                className="w-full accent-indigo-500"
                            />
                            <div className="flex justify-between text-xs text-gray-500 mt-2 font-mono">
                                <span>Stealth (1x)</span>
                                <span>Aggressive (10x)</span>
                            </div>
                        </div>

                        <div className="pt-6 border-t border-gray-800">
                            <button
                                onClick={handleLaunch}
                                disabled={isRunning}
                                className={cn(
                                    "w-full py-4 rounded-xl flex items-center justify-center font-black tracking-widest uppercase transition-all shadow-xl",
                                    isRunning
                                        ? "bg-gray-800 text-gray-500 cursor-not-allowed"
                                        : "bg-gradient-to-r from-rose-600 to-red-500 hover:from-rose-500 hover:to-red-400 text-white shadow-rose-500/20 hover:shadow-rose-500/40 transform hover:-translate-y-0.5"
                                )}
                            >
                                {isRunning ? (
                                    <>
                                        <Activity className="animate-spin h-5 w-5 mr-3" />
                                        Injecting...
                                    </>
                                ) : (
                                    <>
                                        <Zap className="h-5 w-5 mr-3" />
                                        Launch Simulation
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Attack Metrics & Drift Chart */}
                <div className="lg:col-span-2 space-y-8">
                    {/* Metrics */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="bg-[#0f172a]/70 p-6 rounded-3xl border border-rose-500/20 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-rose-600 to-red-600"></div>
                            <div className="flex items-center justify-between mb-3">
                                <h3 className="text-sm font-bold tracking-wide text-gray-400 uppercase">Attack Success Rate</h3>
                                <ShieldAlert className="h-5 w-5 text-rose-400" />
                            </div>
                            <p className="text-4xl font-black text-rose-400 tracking-tighter">
                                {isRunning ? (
                                    <span className="animate-pulse">--%</span>
                                ) : (
                                    metrics.asr
                                )}
                            </p>
                            <p className="text-xs text-gray-500 mt-1">Target model evasion</p>
                        </div>

                        <div className="bg-[#0f172a]/70 p-6 rounded-3xl border border-indigo-500/20 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-indigo-600 to-purple-600"></div>
                            <div className="flex items-center justify-between mb-3">
                                <h3 className="text-sm font-bold tracking-wide text-gray-400 uppercase">Data Drift Score</h3>
                                <Activity className="h-5 w-5 text-indigo-400" />
                            </div>
                            <p className="text-4xl font-black text-indigo-400 tracking-tighter">
                                {isRunning ? (
                                    <span className="animate-pulse">--</span>
                                ) : (
                                    metrics.drift
                                )}
                            </p>
                            <p className="text-xs text-gray-500 mt-1">Shift from baseline</p>
                        </div>

                        <div className="bg-[#0f172a]/70 p-6 rounded-3xl border border-emerald-500/20 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-600 to-teal-600"></div>
                            <div className="flex items-center justify-between mb-3">
                                <h3 className="text-sm font-bold tracking-wide text-gray-400 uppercase">Model Performance</h3>
                                <PlayCircle className="h-5 w-5 text-emerald-400" />
                            </div>
                            <p className="text-4xl font-black text-emerald-400 tracking-tighter">
                                {isRunning ? (
                                    <span className="animate-pulse">--%</span>
                                ) : (
                                    metrics.performance
                                )}
                            </p>
                            <p className="text-xs text-gray-500 mt-1">Accuracy drop</p>
                        </div>
                    </div>

                    {/* Drift Chart */}
                    <div className="bg-[#0f172a]/70 p-6 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-600 to-blue-600"></div>
                        <h3 className="text-xl font-bold text-gray-200 mb-4 flex items-center">
                            <Activity className="h-5 w-5 mr-3 text-cyan-400" />
                            Real-time Data Drift
                        </h3>
                        <div className="h-64">
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart
                                    data={data}
                                    margin={{ top: 5, right: 20, left: -20, bottom: 5 }}
                                >
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                                    <XAxis dataKey="time" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                                    <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid #334155', borderRadius: '12px', backdropFilter: 'blur(8px)' }}
                                        labelStyle={{ color: '#cbd5e1', fontWeight: 'bold', marginBottom: '4px' }}
                                        itemStyle={{ padding: '2px 0' }}
                                    />
                                    <Line type="monotone" dataKey="baseline" stroke="#06b6d4" strokeWidth={3} dot={false} name="Baseline Drift" strokeDasharray="5 5" />
                                    <Line type="monotone" dataKey="attack" stroke="#ef4444" strokeWidth={3} dot={false} name="Attack Drift" animationDuration={2000} />
                                </LineChart>
                            </ResponsiveContainer>
                        </div>
                        <div className="mt-4 text-xs font-medium text-gray-400 text-center flex items-center justify-center gap-6 border-t border-gray-800/50 pt-4">
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-0.5 bg-cyan-400 border-t border-dashed border-cyan-400"></div>
                                <span>Baseline (Benign)</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <div className="w-3 h-0.5 bg-rose-500"></div>
                                <span>Attack Telemetry</span>
                            </div>
                        </div>
                    </div>

                    {/* Additional Info / Model Details */}
                    <div className="bg-[#0f172a]/70 p-6 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-purple-600 to-pink-600"></div>
                        <h3 className="text-xl font-bold text-gray-200 mb-4 flex items-center">
                            <Cpu className="h-5 w-5 mr-3 text-purple-400" />
                            Model Robustness Enhancements
                        </h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div className="bg-[#0b0f19] p-4 rounded-2xl border border-emerald-500/20 shadow-[0_0_15px_rgba(16,185,129,0.05)]">
                                <div className="text-emerald-400 text-xs font-bold uppercase tracking-wider mb-1">Contrastive Pretraining</div>
                                <div className="text-2xl font-black text-white">Active</div>
                            </div>
                            <div className="bg-[#0b0f19] p-4 rounded-2xl border border-indigo-500/20 shadow-[0_0_15px_rgba(99,102,241,0.05)]">
                                <div className="text-indigo-400 text-xs font-bold uppercase tracking-wider mb-1">DropEdge Sampling</div>
                                <div className="text-2xl font-black text-white">10% drop rate</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
