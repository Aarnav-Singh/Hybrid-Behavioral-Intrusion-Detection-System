import React, { useState } from 'react';
import { Search, Server, Activity, ShieldAlert } from 'lucide-react';

const mockHosts = [
    { id: '10.0.0.45', type: 'Workstation', risk: 'High', cves: 3, lastSeen: '2 min ago' },
    { id: '192.168.1.12', type: 'Server', risk: 'Critical', cves: 8, lastSeen: 'Just now' },
    { id: '10.0.0.100', type: 'Mobile', risk: 'Low', cves: 0, lastSeen: '1 hr ago' },
    { id: 'admin.local', type: 'Domain Controller', risk: 'Medium', cves: 1, lastSeen: '5 min ago' },
];

export function Hosts() {
    const [searchTerm, setSearchTerm] = useState('');

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-3xl font-bold tracking-tight text-white">Network Hosts</h1>
            </div>

            <div className="flex bg-[#0f172a] p-2 rounded-lg border border-gray-800 w-full max-w-md shadow-sm">
                <Search className="h-5 w-5 text-gray-500 mx-2 self-center" />
                <input
                    type="text"
                    placeholder="Search by IP or hostname..."
                    className="bg-transparent border-none text-gray-200 outline-none w-full placeholder-gray-600"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            <div className="bg-[#0f172a] border border-gray-800 shadow-xl rounded-xl overflow-hidden mt-6">
                <table className="min-w-full divide-y divide-gray-800">
                    <thead className="bg-[#1e293b]">
                        <tr>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Host ID</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Type</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Risk Level</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Known CVEs</th>
                            <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Last Seen</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                        {mockHosts.filter(h => h.id.includes(searchTerm)).map((host) => (
                            <tr key={host.id} className="hover:bg-gray-800/50 transition-colors cursor-pointer group">
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="flex items-center">
                                        <Server className="h-5 w-5 text-blue-500 mr-3" />
                                        <div className="text-sm font-medium text-gray-200 group-hover:text-blue-400">{host.id}</div>
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="text-sm text-gray-400">{host.type}</div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                    ${host.risk === 'Critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                                            host.risk === 'High' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                                host.risk === 'Medium' ? 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20' :
                                                    'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'}`}>
                                        {host.risk}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                                    <div className="flex items-center">
                                        {host.cves > 0 ? <ShieldAlert className="h-4 w-4 text-red-400 mr-2" /> : <ShieldAlert className="h-4 w-4 text-gray-600 mr-2" />}
                                        {host.cves}
                                    </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                                    <div className="flex items-center">
                                        <Activity className="h-4 w-4 text-emerald-500 mr-2" />
                                        {host.lastSeen}
                                    </div>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
