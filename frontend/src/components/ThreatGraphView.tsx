import React, { useMemo } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';

interface ThreatGraphViewProps {
  graphData: {
    nodes: any[];
    edges: any[];
    stats?: { node_count: number; edge_count: number; density: number };
  };
  onNodeClick?: (nodeId: string, nodeData: any) => void;
  onEdgeClick?: (edgeData: any) => void;
}

export const ThreatGraphView: React.FC<ThreatGraphViewProps> = ({
  graphData,
  onNodeClick,
  onEdgeClick,
}) => {
  const formattedNodes: Node[] = useMemo(() => {
    return (graphData?.nodes || []).map((n) => {
      const risk = n.data?.risk_score || 0;
      let borderClass = 'border-cyan-500/40';
      let bgClass = 'bg-slate-900/90 text-cyan-200';
      
      if (risk >= 80) {
        borderClass = 'border-rose-500 shadow-lg shadow-rose-500/20';
        bgClass = 'bg-rose-950/80 text-rose-200';
      } else if (risk >= 50) {
        borderClass = 'border-amber-500 shadow-md shadow-amber-500/10';
        bgClass = 'bg-amber-950/80 text-amber-200';
      }

      return {
        id: n.id,
        position: n.position || { x: 200, y: 150 },
        data: {
          label: (
            <div className="p-2.5 min-w-[140px] text-center">
              <span className="text-[9px] uppercase tracking-wider block font-bold opacity-75">
                {n.data?.type || 'Entity'}
              </span>
              <span className="text-xs font-mono font-bold block truncate max-w-[180px]">
                {n.data?.label || n.id}
              </span>
              {risk > 0 && (
                <span className="mt-1 inline-block text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/40">
                  Risk: {risk}
                </span>
              )}
            </div>
          ),
          raw: n.data,
        },
        style: {
          borderRadius: '12px',
          borderWidth: '2px',
          padding: '0px',
        },
        className: `${borderClass} ${bgClass} cursor-pointer hover:scale-105 transition duration-150`,
      };
    });
  }, [graphData]);

  const formattedEdges: Edge[] = useMemo(() => {
    return (graphData?.edges || []).map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.animated || false,
      style: { stroke: '#06b6d4', strokeWidth: 1.5 },
      labelStyle: { fill: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
      labelBgStyle: { fill: '#0f172a', fillOpacity: 0.9 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#06b6d4',
      },
    }));
  }, [graphData]);

  return (
    <div className="w-full h-full min-h-[480px] bg-[#070a10] rounded-2xl border border-card-border overflow-hidden relative">
      <ReactFlow
        nodes={formattedNodes}
        edges={formattedEdges}
        onNodeClick={(_, node) => onNodeClick && onNodeClick(node.id, node.data.raw)}
        onEdgeClick={(_, edge) => onEdgeClick && onEdgeClick(edge)}
        fitView
      >
        <Background color="#1e293b" gap={16} size={1} />
        <Controls className="bg-slate-900 border-slate-700 text-white fill-white" />
        <MiniMap
          nodeColor={() => '#06b6d4'}
          maskColor="rgba(11, 15, 23, 0.7)"
          className="bg-slate-900 border border-slate-800 rounded-lg"
        />
      </ReactFlow>

      {/* Graph Stats Overlay */}
      {graphData?.stats && (
        <div className="absolute top-4 left-4 bg-slate-900/80 backdrop-blur-md px-3.5 py-2 rounded-xl border border-slate-800 text-[11px] text-slate-300 flex items-center space-x-3 shadow-lg">
          <div><span className="text-slate-400">Nodes:</span> <span className="font-mono text-cyan-400 font-bold">{graphData.stats.node_count}</span></div>
          <div className="w-px h-3 bg-slate-700"></div>
          <div><span className="text-slate-400">Links:</span> <span className="font-mono text-cyan-400 font-bold">{graphData.stats.edge_count}</span></div>
        </div>
      )}
    </div>
  );
};
