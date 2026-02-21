const API_BASE = 'http://127.0.0.1:8888/api';

export const api = {
    getHealth: async () => {
        try {
            const res = await fetch(`${API_BASE}/health`);
            return res.json();
        } catch (e) {
            console.error('API Error: health', e);
            return { status: 'OFFLINE' };
        }
    },

    getAlerts: async (limit = 50, severity = '') => {
        const params = new URLSearchParams({ limit, ...(severity && { severity }) });
        const res = await fetch(`${API_BASE}/alerts?${params}`);
        return res.json();
    },

    getAlertStats: async () => {
        const res = await fetch(`${API_BASE}/alerts/stats`);
        return res.json();
    },

    updateAlertStatus: async (id, status) => {
        const res = await fetch(`${API_BASE}/alerts/${id}?status=${status}`, {
            method: 'PATCH',
        });
        return res.json();
    },

    getPackets: async (limit = 100) => {
        const res = await fetch(`${API_BASE}/packets?limit=${limit}`);
        return res.json();
    },

    getTraffic: async () => {
        const res = await fetch(`${API_BASE}/traffic`);
        return res.json();
    },

    getSystem: async () => {
        const res = await fetch(`${API_BASE}/system`);
        return res.json();
    },

    getBlocklist: async () => {
        const res = await fetch(`${API_BASE}/blocklist`);
        return res.json();
    },

    addBlocklist: async (ip, reason, threat_level = 'HIGH') => {
        const res = await fetch(`${API_BASE}/blocklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason, threat_level }),
        });
        if (!res.ok) throw await res.json();
        return res.json();
    },

    removeBlocklist: async (id) => {
        const res = await fetch(`${API_BASE}/blocklist/${id}`, {
            method: 'DELETE',
        });
        if (!res.ok) throw await res.json();
        return res.json();
    },

    // --- ML & Distribution ---
    getModelMetrics: async () => {
        const res = await fetch(`${API_BASE}/model/metrics`);
        return res.json();
    },

    getAlertDistribution: async () => {
        const res = await fetch(`${API_BASE}/alerts/distribution`);
        return res.json();
    },

    getTopIPs: async () => {
        const res = await fetch(`${API_BASE}/alerts/top-ips`);
        return res.json();
    },

    triggerTrain: async () => {
        const res = await fetch(`${API_BASE}/ml/train`, { method: 'POST' });
        return res.json();
    },

    triggerBenchmark: async () => {
        const res = await fetch(`${API_BASE}/ml/benchmark`, { method: 'POST' });
        return res.json();
    },
};
