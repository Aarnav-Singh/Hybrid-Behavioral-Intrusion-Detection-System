import React, { useState, useEffect } from 'react';
import { Wifi, Cpu, Shield } from 'lucide-react';

const TopBar = ({ isConnected, systemStats }) => {
    const [time, setTime] = useState(new Date());

    useEffect(() => {
        const timer = setInterval(() => setTime(new Date()), 1000);
        return () => clearInterval(timer);
    }, []);

    const formatTime = (date) => {
        return date.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    return (
        <header className="fixed top-0 left-0 right-0 h-16 bg-black/80 backdrop-blur-md border-b border-white/10 flex items-center justify-between px-8 z-30">
            {/* Left: Breadcrumb / Status */}
            <div className="flex items-center gap-6">
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-neon-green shadow-[0_0_10px_#00FF41]' : 'bg-neon-red shadow-[0_0_10px_#FF003C]'}`} />
                    <span className="text-xs font-mono text-gray-400 uppercase tracking-widest">
                        {isConnected ? 'NETLINK ONLINE' : 'NETLINK OFFLINE'}
                    </span>
                </div>
            </div>

            {/* Right: Stats & Clock */}
            <div className="flex items-center gap-8">
                {/* CPULoad */}
                <div className="flex items-center gap-3">
                    <Cpu size={16} className="text-neon-cyan" />
                    <div className="flex flex-col items-end">
                        <span className="text-xs font-bold text-white font-mono">{systemStats?.cpu || 0}%</span>
                        <span className="text-[10px] text-gray-500 uppercase">CPU Load</span>
                    </div>
                </div>

                {/* Threats */}
                <div className="flex items-center gap-3">
                    <Shield size={16} className="text-neon-red" />
                    <div className="flex flex-col items-end">
                        <span className="text-xs font-bold text-white font-mono">{systemStats?.threats_detected || 0}</span>
                        <span className="text-[10px] text-gray-500 uppercase">Active Threats</span>
                    </div>
                </div>

                {/* Clock */}
                <div className="pl-8 border-l border-white/10">
                    <div className="text-xl font-display font-bold text-white tracking-widest text-glow">
                        {formatTime(time)}
                    </div>
                    <div className="text-[10px] text-right text-gray-400 font-mono">
                        UTC {time.toISOString().split('T')[0]}
                    </div>
                </div>
            </div>
        </header>
    );
};

export default TopBar;
