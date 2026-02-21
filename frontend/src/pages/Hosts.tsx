import { useState } from 'react';
import { Search, Server, Activity, ArrowUpRight, ArrowDownRight } from 'lucide-react';
import { cn } from '../lib/utils';

//... (keep mockHosts)
const mockHosts = [
    { id: '10.0.0.45', hostname: 'DESKTOP-DEV1', os: 'Windows 11', riskScore: 0.92, status: 'critical', bandwidthIn: '24 GB', bandwidthOut: '42 GB' },
    { id: '192.168.1.12', hostname: 'SRV-DB-01', os: 'Linux (Ubuntu)', riskScore: 0.85, status: 'high', bandwidthIn: '512 GB', bandwidthOut: '1.2 TB' },
    { id: 'admin.local', hostname: 'DC-PRIMARY', os: 'Windows Server', riskScore: 0.45, status: 'warning', bandwidthIn: '89 GB', bandwidthOut: '15 GB' },
    { id: '10.0.0.105', hostname: 'USER-LAPTOP-X', os: 'macOS Sonoma', riskScore: 0.12, status: 'clean', bandwidthIn: '12 GB', bandwidthOut: '4 GB' },
    { id: '10.0.0.210', hostname: 'IOT-THERMOSTAT', os: 'RTOS', riskScore: 0.05, status: 'clean', bandwidthIn: '45 MB', bandwidthOut: '12 MB' },
];

export function Hosts() {
    const [searchTerm, setSearchTerm] = useState('');

    const filteredHosts = mockHosts.filter(h =>
        h.id.includes(searchTerm) || h.hostname.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="space-y-8 animate-in fade-in duration-500 pb-10">
            <div className="flex justify-between items-center bg-[#0f172a]/50 p-6 rounded-2xl border border-gray-800/60 backdrop-blur-md shadow-2xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-2 h-full bg-blue-500"></div>
                <div>
                    <h1 className="text-3xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-indigo-600 flex items-center">
                        <Server className="h-8 w-8 text-blue-500 mr-3" />
                        Network Entities
                    </h1>
                    <p className="text-gray-400 mt-2 font-medium">Monitoring {mockHosts.length} active nodes across the segment.</p>
                </div>

                <div className="relative w-72">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Search className="h-5 w-5 text-gray-500" />
                    </div>
                    <input
                        type="text"
                        className="block w-full pl-10 pr-3 py-3 border border-gray-700 rounded-xl leading-5 bg-[#1e293b]/50 text-gray-300 placeholder-gray-500 focus:outline-none focus:bg-[#1e293b]/80 focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/50 transition-all font-mono"
                        placeholder="Search IP or Hostname..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
            </div>

            <div className="bg-[#0f172a]/70 rounded-3xl border border-gray-800/60 shadow-2xl backdrop-blur-xl relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-600 to-blue-600"></div>
                <div className="overflow-x-auto p-2">
                    <table className="min-w-full divide-y divide-gray-800/50">
                        <thead>
                            <tr>
                                <th className="px-6 py-4 text-left text-xs font-black tracking-widest text-gray-500 uppercase">Entity IP / Name</th>
                                <th className="px-6 py-4 text-left text-xs font-black tracking-widest text-gray-500 uppercase">OS Profile</th>
                                <th className="px-6 py-4 text-left text-xs font-black tracking-widest text-gray-500 uppercase">Bandwidth</th>
                                <th className="px-6 py-4 text-left text-xs font-black tracking-widest text-gray-500 uppercase flex items-center"><Activity className="w-4 h-4 mr-1" /> Threat Score</th>
                                <th className="px-6 py-4 text-right text-xs font-black tracking-widest text-gray-500 uppercase">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800/30">
                            {filteredHosts.map((host) => (
                                <tr key={host.id} className="hover:bg-[#1e293b]/40 transition-colors group cursor-pointer">
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="flex items-center">
                                            <div className={cn(
                                                "w-2.5 h-2.5 rounded-full mr-4 shadow-lg",
                                                host.status === 'critical' ? 'bg-rose-500 shadow-rose-500/50 animate-pulse' :
                                                    host.status === 'high' ? 'bg-orange-500 shadow-orange-500/50' :
                                                        host.status === 'warning' ? 'bg-amber-500 shadow-amber-500/50' : 'bg-emerald-500 shadow-emerald-500/50'
                                            )}></div>
                                            <div>
                                                <div className="text-sm font-bold text-gray-200 group-hover:text-white transition-colors">{host.id}</div>
                                                <div className="text-xs text-gray-500 font-mono mt-0.5">{host.hostname}</div>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <span className="px-3 py-1 bg-gray-800/50 text-gray-300 rounded text-xs font-medium border border-gray-700/50">
                                            {host.os}
                                        </span>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                                        <div className="flex flex-col space-y-1">
                                            <div className="flex items-center text-xs"><ArrowDownRight className="w-3 h-3 text-emerald-500 mr-1" /> {host.bandwidthIn}</div>
                                            <div className="flex items-center text-xs"><ArrowUpRight className="w-3 h-3 text-blue-500 mr-1" /> {host.bandwidthOut}</div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="flex items-center space-x-3">
                                            <span className="text-sm font-black text-white">{host.riskScore.toFixed(2)}</span>
                                            <div className="w-24 bg-gray-900 rounded-full h-1.5 overflow-hidden border border-gray-800">
                                                <div
                                                    className={cn(
                                                        "h-1.5 rounded-full",
                                                        host.status === 'critical' ? 'bg-gradient-to-r from-rose-600 to-rose-400' :
                                                            host.status === 'high' ? 'bg-gradient-to-r from-orange-600 to-orange-400' :
                                                                host.status === 'warning' ? 'bg-gradient-to-r from-amber-600 to-amber-400' : 'bg-gradient-to-r from-emerald-600 to-emerald-400'
                                                    )}
                                                    style={{ width: `${Math.min(host.riskScore * 100, 100)}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        <button className="text-indigo-400 hover:text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 px-4 py-2 rounded-lg transition-colors border border-indigo-500/20 flex items-center ml-auto">
                                            Inspect Flow
                                        </button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>

                    {filteredHosts.length === 0 && (
                        <div className="text-center py-12">
                            <Server className="mx-auto h-12 w-12 text-gray-600" />
                            <h3 className="mt-2 text-sm font-medium text-gray-300">No entities found</h3>
                            <p className="mt-1 text-sm text-gray-500">No network hosts match your search trace.</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
