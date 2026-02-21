import React, { useState, useEffect, useRef } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import { Pause, Play, Download, Terminal } from 'lucide-react';

const PacketLog = ({ packets }) => {
    const [isPaused, setIsPaused] = useState(false);
    const [logs, setLogs] = useState([]);
    const bottomRef = useRef(null);

    useEffect(() => {
        if (!isPaused && packets.length > 0) {
            // Add new packets to logs
            setLogs(packets.slice(0, 100).reverse());
        }
    }, [packets, isPaused]);

    useEffect(() => {
        if (!isPaused && bottomRef.current) {
            bottomRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }, [logs, isPaused]);

    const handleExport = () => {
        const text = logs.map(p =>
            `[${p.timestamp}] ${p.protocol} ${p.src_ip}:${p.port} -> ${p.dst_ip} LEN=${p.length} ${p.flags}`
        ).join('\n');
        const blob = new Blob([text], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `packet_log_${Date.now()}.txt`;
        a.click();
    };

    return (
        <Card className="h-full flex flex-col font-mono text-xs" title="Live Traffic Sniffer">
            {/* Controls */}
            <div className="flex justify-between items-center mb-2 px-2">
                <div className="flex gap-2">
                    <Button size="sm" variant="ghost" onClick={() => setIsPaused(!isPaused)}>
                        {isPaused ? <Play size={14} className="text-neon-green" /> : <Pause size={14} className="text-neon-yellow" />}
                        <span className="ml-2">{isPaused ? 'RESUME' : 'PAUSE'}</span>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={handleExport}>
                        <Download size={14} className="text-neon-cyan" />
                        <span className="ml-2">EXPORT</span>
                    </Button>
                </div>
                <div className="text-neon-green/50 animate-pulse">● LIVE CAPTURE</div>
            </div>

            {/* Terminal Output */}
            <div className="flex-1 min-h-0 bg-black/80 border border-white/10 p-4 overflow-y-auto overflow-x-hidden font-mono text-[10px] leading-relaxed">
                {logs.map((packet, i) => (
                    <div key={i} className="whitespace-nowrap overflow-hidden hover:bg-white/5 px-1 py-0.5 border-l-2 border-transparent hover:border-neon-green">
                        <span className="text-gray-500 mr-2">[{packet.timestamp}]</span>
                        <span className={`mr-2 font-bold ${packet.protocol === 'TCP' ? 'text-blue-400' :
                            packet.protocol === 'UDP' ? 'text-orange-400' :
                                'text-purple-400'
                            }`}>{packet.protocol}</span>
                        <span className="text-neon-cyan">{packet.src_ip}</span>
                        <span className="text-gray-600 mx-1">→</span>
                        <span className="text-neon-green">{packet.dst_ip}</span>
                        <span className="ml-2 text-gray-500">Len:{packet.length}</span>
                        <span className="ml-2 text-gray-400">[{packet.flags}]</span>
                        <span className="ml-2 text-gray-600 truncate opacity-50">{packet.payload_preview}</span>
                    </div>
                ))}
                <div ref={bottomRef} />
            </div>
        </Card>
    );
};

export default PacketLog;
