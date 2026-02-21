import React, { useState, useMemo } from 'react';
import Card from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Input from '../ui/Input';
import { Search, Filter, Octagon, CheckCircle } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api } from '../../services/api';

const AlertsPanel = ({ alerts, onUpdateAlert }) => {
    const [filter, setFilter] = useState('');
    const [severityFilter, setSeverityFilter] = useState('ALL');

    const filteredAlerts = useMemo(() => {
        return alerts.filter(a => {
            const matchesSearch =
                a.source_ip.includes(filter) ||
                a.attack_type.toLowerCase().includes(filter.toLowerCase());
            const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
            return matchesSearch && matchesSeverity;
        });
    }, [alerts, filter, severityFilter]);

    const handleAction = async (id, action) => {
        try {
            // Optimistic update
            onUpdateAlert(id, action === 'BLOCK' ? 'BLOCKED' : 'RESOLVED');
            await api.updateAlertStatus(id, action === 'BLOCK' ? 'BLOCKED' : 'RESOLVED');
            if (action === 'BLOCK') {
                // Also add to blocklist? Logic can be extended.
            }
        } catch (e) {
            console.error("Action failed", e);
        }
    };

    return (
        <Card title="Threat Detection Log" className="h-full flex flex-col">
            {/* Toolbar */}
            <div className="flex gap-4 mb-4">
                <div className="relative flex-1">
                    <Input
                        placeholder="Search IP or Attack Type..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="pl-10"
                    />
                    <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
                </div>
                <div className="flex gap-2">
                    {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                        <Button
                            key={sev}
                            variant={severityFilter === sev ? 'default' : 'ghost'}
                            size="sm"
                            onClick={() => setSeverityFilter(sev)}
                        >
                            {sev}
                        </Button>
                    ))}
                </div>
            </div>

            {/* Table Header */}
            <div className="grid grid-cols-[90px_90px_130px_1fr_60px_130px_90px] gap-x-3 px-4 py-2 bg-white/5 text-[10px] font-mono uppercase tracking-wider text-gray-400 border-b border-white/10">
                <div>Time</div>
                <div>Severity</div>
                <div>Source IP</div>
                <div>Attack Type</div>
                <div>Proto</div>
                <div>Action</div>
                <div className="text-right">Status</div>
            </div>

            {/* Table Body */}
            <div className="overflow-y-auto flex-1 custom-scrollbar space-y-1">
                {filteredAlerts.length === 0 ? (
                    <div className="text-center py-8 text-gray-500 font-mono">No threats detected matching filters.</div>
                ) : (
                    filteredAlerts.map((alert) => (
                        <div key={alert.id || alert._id} className="grid grid-cols-[90px_90px_130px_1fr_60px_130px_90px] gap-x-3 px-4 py-3 border-b border-white/5 hover:bg-white/5 items-center transition-colors group">
                            <div className="font-mono text-xs text-gray-400 whitespace-nowrap">{alert.timestamp.split(' ')[1]}</div>
                            <div><Badge variant={alert.severity}>{alert.severity}</Badge></div>
                            <div className="font-mono text-xs text-neon-cyan truncate">{alert.source_ip}</div>
                            <div className="text-xs font-bold text-white whitespace-nowrap truncate">{alert.attack_type}</div>
                            <div className="text-xs text-gray-500 whitespace-nowrap">{alert.protocol}</div>
                            <div className="flex gap-1 items-center">
                                {alert.status === 'ACTIVE' && (
                                    <>
                                        <Button size="sm" variant="destructive" onClick={() => handleAction(alert._id, 'BLOCK')} className="h-6 text-[10px] px-2 whitespace-nowrap">
                                            <Octagon size={10} className="mr-1" /> BLOCK
                                        </Button>
                                        <Button size="sm" variant="outline" onClick={() => handleAction(alert._id, 'RESOLVED')} className="h-6 text-[10px] px-2 whitespace-nowrap">
                                            <CheckCircle size={10} className="mr-1" /> OK
                                        </Button>
                                    </>
                                )}
                            </div>
                            <div className="text-right">
                                <span className={cn(
                                    "text-xs font-bold tracking-wider",
                                    alert.status === 'BLOCKED' ? 'text-neon-red' :
                                        alert.status === 'RESOLVED' ? 'text-neon-green' : 'text-neon-yellow animate-pulse'
                                )}>
                                    {alert.status}
                                </span>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </Card>
    );
};

export default AlertsPanel;
