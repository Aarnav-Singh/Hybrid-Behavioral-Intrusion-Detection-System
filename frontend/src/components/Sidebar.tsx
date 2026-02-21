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
        <div className="flex z-10 h-full w-64 flex-col bg-[#0b0f19] text-gray-400 border-r border-[#1e293b] shadow-2xl relative overflow-hidden backdrop-blur-xl">
            <div className="flex h-16 items-center flex-shrink-0 px-6 border-b border-[#1e293b] bg-gradient-to-r from-[#0f172a] to-[#0b0f19]">
                <Activity className="h-7 w-7 text-indigo-500 mr-3 animate-pulse" />
                <span className="text-xl font-black text-white tracking-widest bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-500">Cyber Sentinel</span>
            </div>
            <div className="flex flex-1 flex-col overflow-y-auto pt-6 pb-4">
                <nav className="mt-2 flex-1 space-y-2 px-3">
                    {navigation.map((item) => (
                        <NavLink
                            key={item.name}
                            to={item.to}
                            className={({ isActive }) =>
                                cn(
                                    isActive
                                        ? 'bg-indigo-500/10 text-indigo-400 border-l-[3px] border-indigo-500 shadow-inner'
                                        : 'text-gray-400 hover:bg-[#1e293b]/50 hover:text-gray-200 border-l-[3px] border-transparent',
                                    'group flex items-center px-4 py-3 text-sm font-semibold rounded-r-lg transition-all duration-300 ease-in-out'
                                )
                            }
                        >
                            <item.icon
                                className="mr-3 flex-shrink-0 h-[18px] w-[18px] transition-transform group-hover:scale-110"
                                aria-hidden="true"
                            />
                            {item.name}
                        </NavLink>
                    ))}
                </nav>
            </div>
            <div className="absolute bottom-0 left-0 w-full h-32 bg-gradient-to-t from-indigo-900/10 to-transparent pointer-events-none"></div>
        </div>
    );
}
