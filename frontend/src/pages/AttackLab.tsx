import React, { useState } from 'react';
import { Target, Zap, Play, CheckCircle } from 'lucide-react';

export function AttackLab() {
    const [attackType, setAttackType] = useState('dns_tunneling');
    const [intensity, setIntensity] = useState(1.0);
    const [target, setTarget] = useState('10.0.0.45');
    const [isRunning, setIsRunning] = useState(false);

    const handleLaunch = () => {
        setIsRunning(true);
        setTimeout(() => setIsRunning(false), 2000);
    };

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold tracking-tight text-white flex items-center">
                    <Target className="h-8 w-8 text-rose-500 mr-3" />
                    Adversarial Attack Lab
                </h1>
            </div>
            <p className="text-gray-400 max-w-3xl">
                Configure and inject synthetic attacks directly into the streaming telemetry. This triggers
                the evaluation pipeline, measuring the model's robustness and updating the PR-AUC metrics.
            </p>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mt-8">
                <div className="lg:col-span-2 space-y-6">
                    <div className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl">
                        <h3 className="text-xl font-bold text-gray-200 mb-6">Configuration</h3>

                        <div className="space-y-5">
                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">Scenario Type</label>
                                <select
                                    value={attackType}
                                    onChange={(e) => setAttackType(e.target.value)}
                                    className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                                >
                                    <option value="dns_tunneling">DNS Tunneling (Temporal)</option>
                                    <option value="graph_poisoning">Graph Poisoning (Spatial)</option>
                                    <option value="beacon_evasion">Beacon Evasion (Rate Limiting)</option>
                                    <option value="feature_perturbation">Feature Perturbation (White-box)</option>
                                </select>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">Target IP Entity</label>
                                <input
                                    type="text"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    className="w-full bg-[#1e293b] border border-gray-700 text-gray-200 rounded-lg p-3 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none"
                                />
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">
                                    Intensity Multiplier: <span className="text-blue-400 font-bold">{intensity}x</span>
                                </label>
                                <input
                                    type="range"
                                    min="0.1" max="5.0" step="0.1"
                                    value={intensity}
                                    onChange={(e) => setIntensity(parseFloat(e.target.value))}
                                    className="w-full appearance-none bg-gray-700 h-2 rounded-lg cursor-pointer accent-blue-500"
                                />
                                <div className="flex justify-between text-xs text-gray-500 mt-2">
                                    <span>Stealthy</span>
                                    <span>Noisy</span>
                                </div>
                            </div>
                        </div>

                        <div className="mt-8">
                            <button
                                onClick={handleLaunch}
                                disabled={isRunning}
                                className={`w-full flex items-center justify-center p-3 rounded-lg font-bold transition-all shadow-lg
                  ${isRunning ? 'bg-gray-700 text-gray-400 cursor-not-allowed' : 'bg-rose-600 hover:bg-rose-500 text-white'}`}
                            >
                                {isRunning ? (
                                    <><Zap className="h-5 w-5 mr-2 animate-pulse" /> Injecting Telemetry...</>
                                ) : (
                                    <><Play className="h-5 w-5 mr-2" /> Launch Red-Team Scenario</>
                                )}
                            </button>
                        </div>
                    </div>
                </div>

                <div className="bg-[#0f172a] border border-gray-800 rounded-xl p-6 shadow-xl h-fit">
                    <h3 className="text-lg font-bold text-gray-200 mb-4">Live Status</h3>
                    <div className="space-y-4">
                        <div className="flex items-center text-sm">
                            <CheckCircle className="h-4 w-4 text-emerald-500 mr-2" />
                            <span className="text-gray-300">FastAPI Pipeline Connected</span>
                        </div>
                        <div className="flex items-center text-sm">
                            <CheckCircle className="h-4 w-4 text-emerald-500 mr-2" />
                            <span className="text-gray-300">Redis Data Generation Ready</span>
                        </div>
                        <div className="flex items-center text-sm">
                            <CheckCircle className="h-4 w-4 text-emerald-500 mr-2" />
                            <span className="text-gray-300">Evaluation Job Queue Active</span>
                        </div>

                        <div className="mt-6 p-4 bg-gray-800/50 rounded border border-gray-700">
                            <h4 className="text-xs uppercase tracking-wider text-gray-500 mb-2">Last Run Result</h4>
                            {isRunning ? (
                                <div className="animate-pulse h-4 bg-gray-700 rounded w-3/4"></div>
                            ) : (
                                <div className="text-sm text-gray-300 font-mono">
                                    <span className="text-emerald-400">SUCCESS</span>: metric.json saved.
                                    <br />ASR: <span className="text-red-400">12.5%</span> (Evaded)
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
