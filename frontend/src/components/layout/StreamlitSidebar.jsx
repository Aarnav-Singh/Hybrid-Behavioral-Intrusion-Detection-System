import React, { useState } from 'react';
import { Settings, Search, Shield, ChevronDown, X, Brain, BarChart2, Loader2, Play } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api } from '../../services/api';

// Helper components for the sidebar
const CustomSlider = ({ label, value, min, max, onChange }) => (
    <div className="mb-6">
        <div className="flex justify-between items-center mb-2">
            <label className="text-xs text-gray-500 font-mono">{label}</label>
            <span className="text-xs font-mono text-neon-red">{value}</span>
        </div>
        <div className="relative w-full h-1 bg-white/10 rounded-full">
            <div
                className="absolute top-0 left-0 h-full bg-neon-red rounded-full"
                style={{ width: `${((value - min) / (max - min)) * 100}%` }}
            />
            <input
                type="range"
                min={min}
                max={max}
                value={value}
                onChange={onChange}
                className="absolute top-[-5px] left-0 w-full h-3 opacity-0 cursor-pointer"
            />
            <div
                className="absolute top-1/2 -mt-1.5 w-3 h-3 bg-neon-red rounded-full shadow-[0_0_8px_#FF003C] pointer-events-none"
                style={{ left: `calc(${((value - min) / (max - min)) * 100}% - 6px)` }}
            />
        </div>
    </div>
);

const MultiSelect = ({ label, options, selected, onChange }) => {
    return (
        <div className="mb-4">
            <label className="text-xs text-gray-500 mb-2 block">{label}</label>
            <div className="flex flex-wrap gap-2">
                {options.map(opt => {
                    const isSelected = selected.includes(opt.value);
                    const colorClass = opt.color || 'bg-white text-black'; // Default to white for info

                    if (isSelected) {
                        return (
                            <button
                                key={opt.value}
                                onClick={() => onChange(selected.filter(v => v !== opt.value))}
                                className={cn("flex items-center gap-1 px-2 py-1 rounded text-xs font-bold", colorClass)}
                            >
                                {opt.label} <X size={12} />
                            </button>
                        )
                    }
                    return null; // The screenshot only shows selected ones as tags
                })}
                {/* Mock dropdown button */}
                <button className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-white text-black bg-opacity-90">
                    <span className="opacity-0">Add</span> <ChevronDown size={12} className="text-gray-500" />
                </button>
            </div>
        </div>
    );
};

const StreamlitSidebar = ({ filters, setFilters }) => {
    const [isTraining, setIsTraining] = useState(false);
    const [isBenchmarking, setIsBenchmarking] = useState(false);
    const [actionResult, setActionResult] = useState(null);

    const handleTrain = async () => {
        setIsTraining(true);
        setActionResult(null);
        try {
            await api.triggerTrain();
            setActionResult({ type: 'success', msg: 'Model trained successfully' });
        } catch (err) {
            setActionResult({ type: 'error', msg: 'Training failed' });
        }
        setIsTraining(false);
    };

    const handleBenchmark = async () => {
        setIsBenchmarking(true);
        setActionResult(null);
        try {
            await api.triggerBenchmark();
            setActionResult({ type: 'success', msg: 'Benchmark complete' });
        } catch (err) {
            setActionResult({ type: 'error', msg: 'Benchmark failed' });
        }
        setIsBenchmarking(false);
    };

    return (
        <aside className="w-[300px] h-screen fixed left-0 top-0 bg-[#0e1117] border-r border-[#1e2329] flex flex-col z-40 overflow-y-auto pt-8">

            {/* Brand Logo matching Streamlit screenshot */}
            <div className="flex flex-col items-center mb-8 px-6">
                <div className="relative mb-3">
                    <Shield size={48} className="text-[#2e8fff] animate-pulse drop-shadow-[0_0_15px_rgba(46,143,255,0.6)]" fill="currentColor" />
                    <div className="absolute inset-0 bg-cyan-400 opacity-20 blur-xl rounded-full"></div>
                </div>
                <h1 className="font-display font-bold text-xl tracking-wider text-neon-cyan text-glow-cyan">
                    CYBERSENTINEL
                </h1>
                <h2 className="text-[10px] font-mono tracking-[0.2em] text-cyan-700 mt-1">COMMAND CENTER</h2>
            </div>

            <div className="px-6 flex-1">
                {/* Controls Section */}
                <div className="flex items-center gap-2 mb-6">
                    <Settings size={14} className="text-gray-400" />
                    <h3 className="text-xs font-bold text-gray-500 tracking-widest">CONTROLS</h3>
                </div>

                {/* Live Mode Toggle */}
                <div className="flex items-center gap-3 mb-8">
                    <button
                        onClick={() => setFilters({ ...filters, liveMode: !filters.liveMode })}
                        className={cn("w-10 h-5 rounded-full relative transition-colors", filters.liveMode ? "bg-neon-red" : "bg-gray-700")}
                    >
                        <div className={cn("w-3 h-3 bg-white rounded-full absolute top-1 transition-transform", filters.liveMode ? "translate-x-6" : "translate-x-1")} />
                    </button>
                    <span className="text-sm text-gray-500">Live Mode (Auto-Refresh)</span>
                </div>

                {/* Sliders */}
                <CustomSlider
                    label="Refresh Interval (s)"
                    value={filters.refreshInterval}
                    min={5} max={60}
                    onChange={(e) => setFilters({ ...filters, refreshInterval: parseInt(e.target.value) })}
                />
                <CustomSlider
                    label="Alerts to Show"
                    value={filters.alertsToShow}
                    min={5} max={100}
                    onChange={(e) => setFilters({ ...filters, alertsToShow: parseInt(e.target.value) })}
                />

                <div className="my-8 border-t border-[#1e2329]" />

                {/* Filter Section */}
                <div className="flex items-center gap-2 mb-6">
                    <Search size={14} className="text-gray-400" />
                    <h3 className="text-xs font-bold text-gray-500 tracking-widest uppercase">Filter</h3>
                </div>

                <MultiSelect
                    label="Severity"
                    selected={filters.severities}
                    onChange={(v) => setFilters({ ...filters, severities: v })}
                    options={[
                        { value: 'CRITICAL', label: 'CRITICAL', color: 'bg-neon-red text-white' },
                        { value: 'WARNING', label: 'WARNING', color: 'bg-neon-red text-white' }, // Screenshot shows WARNING in red too
                        { value: 'INFO', label: 'INFO', color: 'bg-neon-red text-white' }
                    ]}
                />

                <MultiSelect
                    label="Attack Type"
                    selected={filters.attackTypes}
                    onChange={(v) => setFilters({ ...filters, attackTypes: v })}
                    options={[
                        { value: 'SQL Injection', label: 'SQL Injection', color: 'bg-neon-red text-white' },
                        { value: 'Brute Force', label: 'Brute Force', color: 'bg-neon-red text-white' },
                        { value: 'DoS Flood', label: 'DoS Flood', color: 'bg-neon-red text-white' },
                        { value: 'Path Traversal', label: 'Path Traversal', color: 'bg-neon-red text-white' },
                        { value: 'Port Scan', label: 'Port Scan', color: 'bg-neon-red text-white' },
                        { value: 'Slow-and-Low', label: 'Slow-and-Low', color: 'bg-neon-red text-white' },
                        { value: 'Credential Stuffing', label: 'Credential Stuff', color: 'bg-neon-red text-white' },
                        { value: 'XSS', label: 'XSS', color: 'bg-neon-red text-white' },
                    ]}
                />
                {/* ML Operations Section (Matching Original Streamlit Sidebar) */}
                <div className="flex items-center gap-2 mb-4 mt-8">
                    <Brain size={14} className="text-gray-400" />
                    <h3 className="text-xs font-bold text-gray-500 tracking-widest uppercase">ML Operations</h3>
                </div>

                <div className="flex gap-2 mb-4">
                    <button
                        onClick={handleTrain}
                        disabled={isTraining || isBenchmarking}
                        className="flex-1 flex flex-col items-center justify-center gap-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded py-2 transition-colors disabled:opacity-50"
                    >
                        {isTraining ? <Loader2 size={16} className="text-neon-cyan animate-spin" /> : <Brain size={16} className="text-neon-cyan" />}
                        <span className="text-[10px] uppercase font-bold text-gray-300">Train Model</span>
                    </button>

                    <button
                        onClick={handleBenchmark}
                        disabled={isTraining || isBenchmarking}
                        className="flex-1 flex flex-col items-center justify-center gap-1 bg-white/5 hover:bg-white/10 border border-white/10 rounded py-2 transition-colors disabled:opacity-50"
                    >
                        {isBenchmarking ? <Loader2 size={16} className="text-neon-purple animate-spin" /> : <BarChart2 size={16} className="text-neon-purple" />}
                        <span className="text-[10px] uppercase font-bold text-gray-300">Benchmark</span>
                    </button>
                </div>

                {actionResult && (
                    <div className={cn(
                        "px-3 py-2 rounded text-[10px] font-mono border mb-8",
                        actionResult.type === 'success' ? 'bg-neon-green/10 border-neon-green/30 text-neon-green' : 'bg-neon-red/10 border-neon-red/30 text-neon-red'
                    )}>
                        {actionResult.type === 'success' ? '✅ ' : '❌ '}{actionResult.msg}
                    </div>
                )}

            </div>
        </aside>
    );
};

export default StreamlitSidebar;
