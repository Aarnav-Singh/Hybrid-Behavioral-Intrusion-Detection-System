import React, { useState } from 'react';
import Card from '../ui/Card';
import Button from '../ui/Button';
import Input from '../ui/Input';
import Badge from '../ui/Badge';
import { Trash2, Plus, Ban } from 'lucide-react';
import { api } from '../../services/api';

const Blocklist = ({ blocklist, onRefresh }) => {
    const [newIP, setNewIP] = useState('');
    const [reason, setReason] = useState('');
    const [loading, setLoading] = useState(false);

    const handleAdd = async (e) => {
        e.preventDefault();
        if (!newIP) return;
        setLoading(true);
        try {
            await api.addBlocklist(newIP, reason || 'Manual Block');
            setNewIP('');
            setReason('');
            onRefresh();
        } catch (error) {
            console.error("Failed to block IP", error);
            alert("Failed to block IP: " + (error.detail || error.message));
        } finally {
            setLoading(false);
        }
    };

    const handleRemove = async (id) => {
        if (!confirm('Unblock this IP?')) return;
        try {
            await api.removeBlocklist(id);
            onRefresh();
        } catch (error) {
            console.error("Failed to unblock", error);
        }
    };

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
            {/* List */}
            <Card title={`Restricted Targets (${blocklist.length})`} className="lg:col-span-2 flex flex-col h-full">
                <div className="overflow-y-auto flex-1 p-2 space-y-2">
                    {blocklist.map((entry) => (
                        <div key={entry._id} className="flex items-center justify-between p-3 bg-white/5 border border-white/5 hover:border-neon-red/50 transition-colors group">
                            <div className="flex items-center gap-4">
                                <Ban size={16} className="text-neon-red" />
                                <div>
                                    <div className="font-mono text-lg text-white tracking-wider">{entry.ip}</div>
                                    <div className="text-xs text-gray-400 uppercase">{entry.reason}</div>
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                <div className="text-right">
                                    <Badge variant="critical">{entry.threat_level}</Badge>
                                    <div className="text-[10px] text-gray-500 mt-1">{entry.blocked_at}</div>
                                </div>
                                <Button variant="ghost" size="icon" onClick={() => handleRemove(entry._id)} className="text-gray-500 hover:text-neon-red opacity-0 group-hover:opacity-100 transition-opacity">
                                    <Trash2 size={16} />
                                </Button>
                            </div>
                        </div>
                    ))}
                </div>
            </Card>

            {/* Add Form */}
            <Card title="Add Exclusion" className="h-fit">
                <form onSubmit={handleAdd} className="space-y-4">
                    <div>
                        <label className="text-[10px] uppercase font-bold text-gray-500 mb-1 block">Target IP Address</label>
                        <Input
                            value={newIP}
                            onChange={(e) => setNewIP(e.target.value)}
                            placeholder="0.0.0.0"
                            required
                        />
                    </div>
                    <div>
                        <label className="text-[10px] uppercase font-bold text-gray-500 mb-1 block">Reason / Note</label>
                        <Input
                            value={reason}
                            onChange={(e) => setReason(e.target.value)}
                            placeholder="Malicious Activity..."
                        />
                    </div>
                    <Button type="submit" variant="destructive" className="w-full" disabled={loading}>
                        {loading ? 'Processing...' : <><Plus size={16} className="mr-2" /> ENFORCE BLOCK</>}
                    </Button>
                </form>
            </Card>
        </div>
    );
};

export default Blocklist;
