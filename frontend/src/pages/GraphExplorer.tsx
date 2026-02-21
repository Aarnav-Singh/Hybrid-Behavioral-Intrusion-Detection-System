import React from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Network } from 'lucide-react';

const mockGraphData = {
    nodes: [
        { id: '10.0.0.45', group: 1, val: 20 },
        { id: '192.168.1.12', group: 2, val: 10 },
        { id: 'google.com', group: 3, val: 30 },
        { id: 'malicious.xyz', group: 4, val: 15 },
        { id: '8.8.8.8', group: 3, val: 25 },
    ],
    links: [
        { source: '10.0.0.45', target: '192.168.1.12' },
        { source: '10.0.0.45', target: 'google.com' },
        { source: '192.168.1.12', target: 'malicious.xyz' },
        { source: '10.0.0.45', target: '8.8.8.8' },
    ]
};

export function GraphExplorer() {
    return (
        <div className="space-y-6 h-full flex flex-col">
            <div className="flex justify-between items-center">
                <h1 className="text-3xl font-bold tracking-tight text-white flex items-center">
                    <Network className="h-8 w-8 text-blue-500 mr-3" />
                    Network Interaction Graph
                </h1>
                <div className="flex gap-2">
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-300">Nodes: {mockGraphData.nodes.length}</span>
                    <span className="px-3 py-1 bg-gray-800 rounded-full text-xs text-gray-300">Edges: {mockGraphData.links.length}</span>
                </div>
            </div>

            {/* Graph Container */}
            <div className="flex-1 bg-[#0f172a] border border-gray-800 rounded-xl overflow-hidden shadow-xl relative min-h-[500px]">
                {/* We use a hardcoded width/height for the mock, normally we'd use an AutoSizer */}
                <ForceGraph2D
                    graphData={mockGraphData}
                    nodeAutoColorBy="group"
                    nodeRelSize={6}
                    linkColor={() => '#334155'}
                    linkWidth={2}
                    backgroundColor="#0f172a"
                    width={1200}
                    height={600}
                />

                {/* Legend Overlay */}
                <div className="absolute bottom-4 right-4 bg-gray-900/80 p-4 rounded-lg border border-gray-800 backdrop-blur-sm">
                    <h4 className="text-gray-300 text-sm font-semibold mb-2">Legend</h4>
                    <div className="space-y-2 text-xs">
                        <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-blue-500 mr-2"></div><span className="text-gray-400">Trusted IPs</span></div>
                        <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div><span className="text-gray-400">Anomalous / Blocked</span></div>
                        <div className="flex items-center"><div className="w-3 h-3 rounded-full bg-emerald-500 mr-2"></div><span className="text-gray-400">External Domains</span></div>
                    </div>
                </div>
            </div>
        </div>
    );
}
