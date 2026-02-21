import { useState, useEffect } from 'react';
import { Save, Settings2, ShieldCheck, Database, Zap } from 'lucide-react';

interface ModelInfo {
    id: string;
    name: string;
    description: string;
    type: string;
}

export function Settings() {
    const [models, setModels] = useState<ModelInfo[]>([]);
    const [activeModelId, setActiveModelId] = useState('');
    const [loadingModels, setLoadingModels] = useState(true);

    const [isSaving, setIsSaving] = useState(false);
    const [saveSuccess, setSaveSuccess] = useState(false);

    useEffect(() => {
        const fetchModels = async () => {
            try {
                const [modelsRes, activeRes] = await Promise.all([
                    fetch('http://localhost:8001/api/v1/models'),
                    fetch('http://localhost:8001/api/v1/models/active')
                ]);

                if (modelsRes.ok && activeRes.ok) {
                    const modelsData = await modelsRes.json();
                    const activeData = await activeRes.json();
                    setModels(modelsData);
                    setActiveModelId(activeData.id);
                }
            } catch (error) {
                console.error("Failed to fetch models:", error);
            } finally {
                setLoadingModels(false);
            }
        };
        fetchModels();
    }, []);

    const handleSave = async () => {
        setIsSaving(true);
        try {
            const res = await fetch('http://localhost:8001/api/v1/models/active', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ model_id: activeModelId })
            });

            if (res.ok) {
                setSaveSuccess(true);
                setTimeout(() => setSaveSuccess(false), 3000);
            }
        } catch (error) {
            console.error("Failed to save changes:", error);
        } finally {
            setIsSaving(false);
        }
    };

    return (
        <div className="space-y-6 max-w-4xl">
            <div className="flex justify-between items-center mb-8 relative">
                <h1 className="text-3xl font-bold tracking-tight text-white flex items-center">
                    <Settings2 className="h-8 w-8 text-gray-400 mr-3" />
                    System Settings
                </h1>

                <div className="flex items-center space-x-4">
                    {saveSuccess && (
                        <span className="text-emerald-400 text-sm font-medium animate-in slide-in-from-right fade-in px-3 py-1 bg-emerald-500/10 rounded-full border border-emerald-500/20 shadow-[0_0_10px_rgba(16,185,129,0.15)] flex items-center">
                            <ShieldCheck className="w-4 h-4 mr-1" />
                            Active Model Switched
                        </span>
                    )}
                    <button
                        onClick={handleSave}
                        disabled={isSaving || loadingModels}
                        className={`flex items-center px-5 py-2.5 text-sm font-bold rounded-xl shadow-lg transition-all duration-300 ${isSaving
                            ? 'bg-indigo-600/50 text-white/50 cursor-wait'
                            : saveSuccess
                                ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-500/20'
                                : 'bg-indigo-600 hover:bg-indigo-500 hover:shadow-indigo-500/25 text-white border border-indigo-500/50'
                            }`}
                    >
                        {isSaving ? (
                            <div className="flex items-center">
                                <div className="w-4 h-4 rounded-full border-2 border-white/20 border-t-white animate-spin mr-2"></div>
                                Updating Model...
                            </div>
                        ) : saveSuccess ? (
                            <>
                                <ShieldCheck className="h-4 w-4 mr-2" />
                                Updated
                            </>
                        ) : (
                            <>
                                <Save className="h-4 w-4 mr-2" />
                                Apply Configuration
                            </>
                        )}
                    </button>
                </div>
            </div>

            <div className="space-y-8">

                {/* ML Configuration */}
                <section className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl">
                    <h2 className="text-xl font-bold text-gray-200 mb-6 flex items-center border-b border-gray-800 pb-4">
                        <Zap className="h-5 w-5 text-indigo-400 mr-2" />
                        Dynamic Detection Engine
                    </h2>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Active Inference Model</label>
                            <select
                                value={activeModelId}
                                onChange={(e) => setActiveModelId(e.target.value)}
                                disabled={loadingModels}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-indigo-500"
                            >
                                {models.map(m => (
                                    <option key={m.id} value={m.id}>{m.name}</option>
                                ))}
                            </select>
                            {activeModelId && (
                                <p className="mt-2 text-xs text-gray-500 italic">
                                    {models.find(m => m.id === activeModelId)?.description}
                                </p>
                            )}
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Alert Threshold (Local)</label>
                            <input
                                type="number"
                                defaultValue={0.85}
                                step={0.05}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-indigo-500"
                            />
                            <p className="mt-2 text-xs text-gray-500">Anomaly scores above this threshold trigger Critical alerts.</p>
                        </div>

                        <div className="md:col-span-2">
                            <label className="block text-sm font-medium text-gray-400 mb-2">AbuseIPDB Integration Status</label>
                            <div className="flex items-center gap-4 bg-[#1e293b]/50 p-4 rounded-xl border border-gray-800">
                                <div className="p-3 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                                    <ShieldCheck className="h-5 w-5 text-emerald-400" />
                                </div>
                                <div className="flex-1">
                                    <h4 className="text-sm font-bold text-gray-200">API Key Verified</h4>
                                    <p className="text-xs text-gray-500">Fusion logic is actively enriching local scores with global threat intelligence.</p>
                                </div>
                                <button className="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded-md text-xs font-medium text-gray-300">View Logs</button>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Data Management */}
                <section className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl">
                    <h2 className="text-xl font-bold text-gray-200 mb-6 flex items-center border-b border-gray-800 pb-4">
                        <Database className="h-5 w-5 text-emerald-400 mr-2" />
                        Live Observation Window
                    </h2>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Polling Interval (Seconds)</label>
                            <input
                                type="number"
                                defaultValue={5}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-indigo-500"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Dashboard Refresh Rate</label>
                            <select className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-indigo-500">
                                <option value="realtime">Real-time (WebSocket Fallback)</option>
                                <option value="fast">Aggressive (1s)</option>
                                <option value="normal">Normal (5s)</option>
                            </select>
                        </div>
                    </div>
                </section>

            </div>
        </div>
    );
}
