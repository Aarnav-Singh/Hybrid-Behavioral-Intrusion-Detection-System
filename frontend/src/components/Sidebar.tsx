import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, Server, ShieldAlert, Network, Sword, Beaker, Settings, Activity } from 'lucide-react';
import { cn } from '../lib/utils';

const navigation = [
    { name: 'Overview', to: '/', icon: LayoutDashboard },
    { name: 'Hosts', to: '/hosts', icon: Server },
    { name: 'Alerts', to: '/alerts', icon: ShieldAlert },
    { name: 'Graph Explorer', to: '/graph', icon: Network },
    { name: 'Attack Lab', to: '/attack-lab', icon: Sword },
    { name: 'Experiments', to: '/experiments', icon: Beaker },
    { name: 'Settings', to: '/settings', icon: Settings },
];

export function Sidebar() {
    return (
        <div className="flex h-full w-64 flex-col bg-[#0b1120] text-gray-300 border-r border-gray-800">
            <div className="flex h-16 items-center flex-shrink-0 px-4 border-b border-gray-800 bg-[#0f172a]">
                <Activity className="h-8 w-8 text-blue-500 mr-2" />
                <span className="text-xl font-bold text-white tracking-wider">HB-IDS v2</span>
            </div>
            <div className="flex flex-1 flex-col overflow-y-auto pt-5 pb-4">
                <nav className="mt-2 flex-1 space-y-1 px-2">
                    {navigation.map((item) => (
                        <NavLink
                            key={item.name}
                            to={item.to}
                            className={({ isActive }) =>
                                cn(
                                    isActive
                                        ? 'bg-blue-900/40 text-blue-400 border-l-4 border-blue-500'
                                        : 'text-gray-400 hover:bg-gray-800 hover:text-white border-l-4 border-transparent',
                                    'group flex items-center px-3 py-2 text-sm font-medium transition-colors'
                                )
                            }
                        >
                            <item.icon
                                className="mr-3 flex-shrink-0 h-5 w-5"
                                aria-hidden="true"
                            />
                            {item.name}
                        </NavLink>
                    ))}
                </nav>
            </div>
        </div>
    );
}
