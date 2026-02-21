import { useState, useEffect } from 'react';
import { ShieldAlert, Shield, Activity } from 'lucide-react';
import { cn } from '../lib/utils'; // Assuming 'cn' utility is available, e.g., from shadcn/ui or similar

// Define the Alert type based on the new component's expectations
interface Alert {
    id: string;
    severity: 'critical' | 'high' | 'medium';
    timestamp: string;
    score: number;
    threat_type: string;
    target_ip: string;
    datetime: string;
    source_ip: string;
    shap_values: { [key: string]: number };
    threat_intel?: {
        source: string;
        malicious: boolean;
        confidence: number;
        tags: string[];
    };
}

export function Alerts() {
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const res = await fetch('http://localhost:8001/api/v1/alerts');
                if (res.ok) {
                    const data = await res.json();
                    setAlerts(data);
                }
            } catch (error) {
                console.error("Failed to fetch alerts:", error);
            } finally {
                setLoading(false);
            }
        };
        fetchAlerts();
        // Setup polling every 5 seconds for real-time feel
        const interval = setInterval(fetchAlerts, 5000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="flex h-[calc(100vh-4rem)] md:h-full overflow-hidden animate-in fade-in duration-500">
            {/* Alert List */}
            <div className={`${selectedAlert ? 'hidden md:flex' : 'flex'} w-full md:w-1/3 flex-col bg-[#0f172a]/60 backdrop-blur-xl border-r border-gray-800/60`}>
                <div className="p-6 border-b border-gray-800/60 bg-gradient-to-r from-gray-900/50 to-transparent">
                    <h2 className="text-xl font-black tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-rose-400 to-red-600 flex items-center">
                        <ShieldAlert className="h-6 w-6 mr-2 text-rose-500" />
                        Detection Queue
                    </h2>
                    <div className="mt-4 flex gap-2">
                        <span className="px-3 py-1 bg-rose-500/10 text-rose-400 rounded-full text-xs font-bold border border-rose-500/20 shadow-[0_0_10px_rgba(244,63,94,0.1)]">
                            {alerts.filter(a => a.severity === 'critical').length} Critical
                        </span>
                        <span className="px-3 py-1 bg-amber-500/10 text-amber-400 rounded-full text-xs font-bold border border-amber-500/20">
                            {alerts.filter(a => a.severity === 'high' || a.severity === 'medium').length} Warning
                        </span>
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 space-y-3 relative">
                    {loading && (
                        <div className="absolute inset-0 flex items-center justify-center bg-[#0f172a]/80 backdrop-blur-sm z-10">
                            <Activity className="h-8 w-8 text-indigo-500 animate-spin" />
                        </div>
                    )}
                    {alerts.map((alert: Alert) => (
                        <div
                            key={alert.id}
                            onClick={() => setSelectedAlert(alert)}
                            className={cn(
                                "p-4 rounded-xl cursor-pointer transition-all duration-300 border backdrop-blur-md group",
                                selectedAlert?.id === alert.id
                                    ? "bg-indigo-500/10 border-indigo-500/40 shadow-[0_0_20px_rgba(99,102,241,0.15)]"
                                    : "bg-[#1e293b]/40 border-gray-800 hover:border-gray-600 hover:bg-[#1e293b]/80"
                            )}
                        >
                            <div className="flex justify-between items-start mb-2">
                                <div className="flex items-center">
                                    <div className={cn(
                                        "w-2 h-2 rounded-full mr-3 shadow-lg",
                                        alert.severity === 'critical' ? 'bg-rose-500 shadow-rose-500/50 animate-pulse' :
                                            alert.severity === 'high' ? 'bg-orange-500 shadow-orange-500/50' : 'bg-amber-500'
                                    )}></div>
                                    <span className="text-xs font-mono text-gray-400">{alert.timestamp}</span>
                                </div>
                                <span className="text-sm font-bold text-gray-300 group-hover:text-white transition-colors">{alert.score.toFixed(2)}</span>
                            </div>
                            <h3 className="font-semibold text-gray-200 text-sm mb-1 line-clamp-1">{alert.threat_type}</h3>
                            <p className="text-xs font-mono text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded inline-block">Source: {alert.source_ip}</p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Alert Details */}
            <div className={`${!selectedAlert ? 'hidden md:flex flex-col items-center justify-center text-gray-500' : 'flex'} flex-1 flex-col bg-[#0b0f19] relative`}>
                {!selectedAlert ? (
                    <div className="text-center animate-pulse">
                        <Shield className="h-20 w-20 mx-auto text-gray-800 mb-6" />
                        <p className="text-xl font-medium tracking-wide">Select an anomaly to investigate</p>
                    </div>
                ) : (
                    <div className="flex-1 overflow-y-auto p-8 relative">
                        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/5 rounded-full blur-[100px] pointer-events-none"></div>

                        <button
                            onClick={() => setSelectedAlert(null)}
                            className="md:hidden flex items-center text-indigo-400 hover:text-indigo-300 mb-6 font-medium transition-colors"
                        >
                            ← Back to queue
                        </button>

                        <div className="flex justify-between items-start mb-8 border-b border-gray-800 pb-6 relative z-10">
                            <div>
                                <div className="flex items-center gap-3 mb-2">
                                    <h1 className="text-3xl font-black text-white tracking-wide">{selectedAlert.threat_type}</h1>
                                    <span className={cn(
                                        "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border",
                                        selectedAlert.severity === 'critical' ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' :
                                            selectedAlert.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                                    )}>
                                        {selectedAlert.severity}
                                    </span>
                                </div>
                                <p className="text-gray-400 font-mono text-sm">{selectedAlert.datetime} • Source: {selectedAlert.source_ip} → Dest: {selectedAlert.target_ip}</p>
                            </div>
                            <div className="text-right">
                                <div className="text-sm text-gray-400 uppercase tracking-widest font-bold mb-1">Anomaly Score</div>
                                <div className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-b from-white to-gray-500">{selectedAlert.score.toFixed(3)}</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8 relative z-10">
                            {/* SHAP Explanation */}
                            <div className="bg-[#0f172a]/60 backdrop-blur-xl border border-gray-800/60 rounded-2xl p-6 shadow-2xl">
                                <h3 className="text-lg font-bold text-gray-200 mb-6 flex items-center border-b border-gray-800/50 pb-3">
                                    <Activity className="h-5 w-5 text-indigo-400 mr-3" />
                                    SHAP Feature Contributions
                                </h3>
                                <div className="space-y-5">
                                    {Object.entries(selectedAlert.shap_values)
                                        .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
                                        .map(([feature, value]) => (
                                            <div key={feature}>
                                                <div className="flex justify-between text-sm mb-2">
                                                    <span className="text-gray-300 font-mono truncate mr-4">{feature}</span>
                                                    <span className={value > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                                                        {value > 0 ? '+' : ''}{value.toFixed(4)}
                                                    </span>
                                                </div>
                                                <div className="w-full bg-gray-900 rounded-full h-2 overflow-hidden border border-gray-800">
                                                    <div
                                                        className={cn("h-2 rounded-full transition-all duration-1000", value > 0 ? 'bg-gradient-to-r from-rose-600 to-rose-400' : 'bg-gradient-to-r from-emerald-600 to-emerald-400')}
                                                        style={{
                                                            width: `${Math.min(Math.abs(value) * 100, 100)}%`,
                                                            marginLeft: value < 0 ? 'auto' : '0'
                                                        }}
                                                    ></div>
                                                </div>
                                            </div>
                                        ))}
                                </div>
                            </div>

                            {/* Context & Actions */}
                            <div className="space-y-6">
                                <div className="bg-[#0f172a]/60 backdrop-blur-xl border border-gray-800/60 rounded-2xl p-6 shadow-2xl">
                                    <h3 className="text-lg font-bold text-gray-200 mb-4 border-b border-gray-800/50 pb-3">Metadata</h3>
                                    <div className="space-y-3 text-sm">
                                        <div className="flex justify-between py-2 border-b border-gray-800/30">
                                            <span className="text-gray-500 font-medium">Model Context</span>
                                            <span className="text-indigo-300 font-mono bg-indigo-500/10 px-2 py-0.5 rounded">
                                                {selectedAlert.threat_type.split('(')[1]?.replace(')', '') || 'Active Engine'}
                                            </span>
                                        </div>
                                        <div className="flex justify-between py-2 border-b border-gray-800/30">
                                            <span className="text-gray-500 font-medium">Protocol Activity</span>
                                            <span className="text-gray-300 font-mono">DNS (53), HTTPS (443)</span>
                                        </div>
                                        <div className="flex justify-between py-2">
                                            <span className="text-gray-500 font-medium">Bytes Transferred</span>
                                            <span className="text-gray-300 font-mono">4.2 MB (Out) / 12 KB (In)</span>
                                        </div>
                                        {selectedAlert.threat_intel && (
                                            <div className="mt-4 pt-4 border-t border-indigo-500/30">
                                                <h4 className="text-indigo-400 font-bold mb-2 uppercase tracking-widest text-xs flex items-center"><ShieldAlert className="w-3 h-3 mr-1" /> Global Threat Intel</h4>
                                                <div className="flex justify-between py-1">
                                                    <span className="text-gray-500">Source</span>
                                                    <span className="text-gray-300 font-mono">{selectedAlert.threat_intel.source}</span>
                                                </div>
                                                <div className="flex justify-between py-1">
                                                    <span className="text-gray-500">Known Malicious</span>
                                                    <span className={selectedAlert.threat_intel.malicious ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                                                        {selectedAlert.threat_intel.malicious ? "YES" : "NO"}
                                                    </span>
                                                </div>
                                                <div className="flex justify-between py-1">
                                                    <span className="text-gray-500">Confidence Score</span>
                                                    <span className="text-gray-300 font-mono">{selectedAlert.threat_intel.confidence}</span>
                                                </div>
                                                <div className="mt-2 text-xs text-indigo-300 bg-indigo-500/10 p-2 rounded">
                                                    Tags: {selectedAlert.threat_intel.tags.join(', ') || 'None'}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>

                                <div className="bg-gradient-to-br from-indigo-900/20 to-blue-900/10 border border-indigo-500/20 rounded-2xl p-6 shadow-[0_0_30px_rgba(79,70,229,0.1)]">
                                    <h3 className="text-lg font-bold text-indigo-100 mb-4">Response Actions</h3>
                                    <div className="space-y-3">
                                        <button className="w-full py-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-bold tracking-wide transition-all shadow-lg hover:shadow-indigo-500/25 flex justify-center items-center group">
                                            Isolate Host {selectedAlert.source_ip}
                                            <Shield className="w-4 h-4 ml-2 opacity-50 group-hover:opacity-100 transition-opacity" />
                                        </button>
                                        <button className="w-full py-3 bg-[#1e293b] hover:bg-gray-700 text-gray-200 rounded-xl text-sm font-bold tracking-wide border border-gray-600 transition-colors">
                                            Mark as False Positive
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
