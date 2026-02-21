import React from 'react';
import { LayoutDashboard, ShieldAlert, Activity, Lock, Server, Terminal, Cpu, FlaskConical, TrendingDown, Swords, Zap, Globe } from 'lucide-react';
import { cn } from '../../lib/utils';

const Sidebar = ({ activeTab, setActiveTab, alertCount = 0 }) => {
    const operationalItems = [
        { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: 'alerts', label: 'Threat Alerts', icon: ShieldAlert, badge: alertCount },
        { id: 'packets', label: 'Packet Log', icon: Terminal },
        { id: 'blocklist', label: 'IP Blocklist', icon: Lock },
        { id: 'system', label: 'System Health', icon: Activity },
        { id: 'ops', label: 'ML Operations', icon: Cpu },
    ];

    const researchItems = [
        { id: 'evaluation', label: 'Evaluation Lab', icon: FlaskConical },
        { id: 'drift', label: 'Drift Monitor', icon: TrendingDown },
        { id: 'adversarial', label: 'Adversarial Lab', icon: Swords },
        { id: 'chaos', label: 'Chaos Testing', icon: Zap },
        { id: 'forensics', label: 'Threat Intel', icon: Globe },
    ];

    const renderNavItem = (item) => {
        const isActive = activeTab === item.id;
        const Icon = item.icon;
        return (
            <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={cn(
                    "w-full flex items-center px-6 py-2.5 text-sm font-mono tracking-wider transition-all relative group",
                    isActive
                        ? "text-neon-green bg-neon-green/5 border-r-2 border-neon-green"
                        : "text-gray-400 hover:text-white hover:bg-white/5"
                )}
            >
                <Icon size={16} className={cn("mr-3 flex-shrink-0", isActive && "animate-pulse-glow")} />
                {item.label}
                {item.badge > 0 && (
                    <span className="ml-auto flex h-5 w-5 items-center justify-center rounded-full bg-neon-red/20 text-neon-red text-[10px] font-bold border border-neon-red animate-pulse">
                        {item.badge}
                    </span>
                )}
                {!isActive && (
                    <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-neon-green opacity-0 group-hover:opacity-100 transition-opacity" />
                )}
            </button>
        );
    };

    return (
        <aside className="w-64 h-screen fixed left-0 top-0 bg-black/90 border-r border-white/10 flex flex-col z-40 backdrop-blur-md overflow-y-auto">
            {/* Brand */}
            <div className="h-16 flex items-center px-6 border-b border-white/10 flex-shrink-0">
                <div className="w-3 h-3 bg-neon-green rounded-full animate-pulse mr-3 shadow-[0_0_10px_#00FF41]" />
                <h1 className="font-display font-bold text-xl tracking-wider text-white">
                    CYBER<span className="text-neon-green">SENTINEL</span>
                </h1>
            </div>

            <nav className="flex-1 py-4">
                {/* Operational Section */}
                <div className="px-6 py-2">
                    <p className="text-[9px] font-bold tracking-[0.2em] text-gray-600 uppercase">Operations</p>
                </div>
                <div className="space-y-0.5 mb-2">
                    {operationalItems.map(renderNavItem)}
                </div>

                {/* Divider */}
                <div className="mx-4 my-3 border-t border-white/10" />

                {/* Research & Analysis Section */}
                <div className="px-6 py-2">
                    <p className="text-[9px] font-bold tracking-[0.2em] text-gray-600 uppercase">Research & Analysis</p>
                </div>
                <div className="space-y-0.5">
                    {researchItems.map(renderNavItem)}
                </div>
            </nav>

            {/* Footer / Status */}
            <div className="p-4 border-t border-white/10 flex-shrink-0">
                <div className="text-[10px] font-mono text-gray-500 uppercase tracking-widest text-center">
                    System Secure
                    <div className="text-neon-green mt-1">v2.5.0-RC1</div>
                </div>
            </div>
        </aside>
    );
};

export default Sidebar;
