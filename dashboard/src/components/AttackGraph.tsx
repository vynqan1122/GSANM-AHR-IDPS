interface GraphNode {
  id: string;
  kind: string;
  label: string;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

interface GraphData {
  nodes?: GraphNode[];
  edges?: GraphEdge[];
}

interface PositionedNode extends GraphNode {
  x: number;
  y: number;
}

function nodeLabel(node: GraphNode, index: number) {
  if (node.kind === 'request') return `Event ${index + 1}`;
  return node.label.length > 28 ? `${node.label.slice(0, 28)}...` : node.label;
}

function positionNodes(nodes: GraphNode[]): PositionedNode[] {
  const groups = {
    ip: nodes.filter((node) => node.kind === 'ip'),
    request: nodes.filter((node) => node.kind === 'request'),
    target: nodes.filter((node) => node.kind === 'target'),
    other: nodes.filter((node) => !['ip', 'request', 'target'].includes(node.kind)),
  };
  const layout: PositionedNode[] = [];
  const columns = [
    { nodes: groups.ip, x: 120 },
    { nodes: groups.request, x: 450 },
    { nodes: [...groups.target, ...groups.other], x: 780 },
  ];
  for (const column of columns) {
    const gap = 280 / Math.max(1, column.nodes.length - 1);
    column.nodes.forEach((node, index) => layout.push({ ...node, x: column.x, y: 110 + index * gap }));
  }
  return layout;
}

export function AttackGraph({ graph }: { graph?: GraphData | null }) {
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const positioned = positionNodes(nodes);
  const index = new Map(positioned.map((node) => [node.id, node]));

  if (!nodes.length) {
    return <p className="empty-state">No correlated entities for this incident.</p>;
  }

  return (
    <div className="attack-graph" role="img" aria-label="Attack graph from the selected incident">
      <svg viewBox="0 0 900 420" preserveAspectRatio="xMidYMid meet">
        <defs>
          <marker id="graph-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 Z" />
          </marker>
        </defs>
        {edges.map((edge, edgeIndex) => {
          const source = index.get(edge.source);
          const target = index.get(edge.target);
          if (!source || !target) return null;
          return <line key={`${edge.source}-${edge.target}-${edgeIndex}`} x1={source.x + 78} y1={source.y} x2={target.x - 78} y2={target.y} markerEnd="url(#graph-arrow)" />;
        })}
        {positioned.map((node, nodeIndex) => (
          <g key={node.id} className={`graph-node ${node.kind}`}>
            <rect x={node.x - 80} y={node.y - 27} width="160" height="54" rx="5" />
            <text x={node.x} y={node.y - 3} textAnchor="middle">{node.kind.toUpperCase()}</text>
            <text x={node.x} y={node.y + 16} textAnchor="middle">{nodeLabel(node, nodeIndex)}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}
