import React, { useState } from 'react';
import { Save, Settings2, ShieldCheck, Database } from 'lucide-react';

export function Settings() {
    const [retention, setRetention] = useState('30');
    const [mode, setMode] = useState('hybrid');

    return (
        <div className="space-y-6 max-w-4xl">
            <div className="flex justify-between items-center mb-8">
                <h1 className="text-3xl font-bold tracking-tight text-white flex items-center">
                    <Settings2 className="h-8 w-8 text-gray-400 mr-3" />
                    System Settings
                </h1>
                <button className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-semibold rounded-lg shadow transition-colors">
                    <Save className="h-4 w-4 mr-2" />
                    Save Changes
                </button>
            </div>

            <div className="space-y-8">

                {/* ML Configuration */}
                <section className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl">
                    <h2 className="text-xl font-bold text-gray-200 mb-6 flex items-center border-b border-gray-800 pb-4">
                        <ShieldCheck className="h-5 w-5 text-indigo-400 mr-2" />
                        Detection Engine Configuration
                    </h2>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Operating Mode</label>
                            <select
                                value={mode}
                                onChange={(e) => setMode(e.target.value)}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-blue-500"
                            >
                                <option value="fast">Fast (Node2Vec + Base TCN)</option>
                                <option value="hybrid">Hybrid (GraphSAGE + Ensemble TCN)</option>
                            </select>
                            <p className="mt-2 text-xs text-gray-500">Fast mode is optimized for CPUs. Hybrid utilizes PyTorch/PyG for advanced relational tracking.</p>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Alert Threshold</label>
                            <input
                                type="number"
                                defaultValue={0.85}
                                step={0.05}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-blue-500"
                            />
                            <p className="mt-2 text-xs text-gray-500">Anomaly scores above this threshold trigger Critical alerts.</p>
                        </div>

                        <div className="md:col-span-2">
                            <label className="block text-sm font-medium text-gray-400 mb-2">FortiGuard API Key</label>
                            <div className="flex">
                                <input
                                    type="password"
                                    defaultValue="sk-mock-fortiguard-key-92837"
                                    className="flex-1 bg-[#1e293b] border border-t-gray-700 border-b-gray-700 border-l-gray-700 text-gray-200 rounded-l-lg p-3 focus:outline-none focus:border-blue-500"
                                />
                                <button className="bg-gray-700 hover:bg-gray-600 px-4 rounded-r-lg text-sm font-medium text-white transition-colors">Verify</button>
                            </div>
                        </div>
                    </div>
                </section>

                {/* Data Management */}
                <section className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl">
                    <h2 className="text-xl font-bold text-gray-200 mb-6 flex items-center border-b border-gray-800 pb-4">
                        <Database className="h-5 w-5 text-emerald-400 mr-2" />
                        Data Retention & Storage
                    </h2>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Event Retention (Days)</label>
                            <input
                                type="number"
                                value={retention}
                                onChange={(e) => setRetention(e.target.value)}
                                className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-blue-500"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-2">Graph Snapshot Interval</label>
                            <select className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:outline-none focus:border-blue-500">
                                <option value="15">15 Minutes</option>
                                <option value="60">1 Hour</option>
                                <option value="1440">24 Hours</option>
                            </select>
                        </div>
                    </div>
                </section>

            </div>
        </div>
    );
}
