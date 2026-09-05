"use client";

import * as d3 from "d3";
import { useEffect, useRef } from "react";
import { SEVERITY_HEX, type PeerEdge, type PeerNode } from "@/lib/charts";

type SimNode = PeerNode & d3.SimulationNodeDatum;
type SimEdge = Omit<PeerEdge, "source" | "target"> & d3.SimulationLinkDatum<SimNode>;

/**
 * P4-T5. Peers as nodes, sessions as edges, node colour = the peer's worst
 * session. A responder that terminates one weak tunnel among twenty good ones
 * still shows red, because that is the tunnel someone has to go fix.
 *
 * D3 owns the SVG here rather than React: the simulation mutates node
 * positions sixty times a second, and re-rendering that through React would
 * be a lot of reconciliation for no benefit.
 */
export function PeerGraph({
  nodes,
  edges,
  onSelectPeer,
  onSelectSession,
}: {
  nodes: PeerNode[];
  edges: PeerEdge[];
  onSelectPeer: (ip: string) => void;
  onSelectSession: (sessionId: string) => void;
}) {
  const hostRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const simNodes: SimNode[] = nodes.map((n) => ({ ...n }));
    const simEdges: SimEdge[] = edges.map((e) => ({ ...e }));

    const svg = d3.select(host);
    svg.selectAll("*").remove();

    // A 2px line is a 2px click target. The visible stroke stays thin and the
    // hit target is a transparent line on top of it, which is the difference
    // between "clickable" and "clickable by someone with a steady hand".
    const edgeSelection = svg
      .append("g")
      .attr("stroke-linecap", "round")
      .attr("pointer-events", "none")
      .selectAll<SVGLineElement, SimEdge>("line")
      .data(simEdges)
      .join("line")
      .attr("stroke", (d) => SEVERITY_HEX[d.severity])
      .attr("stroke-opacity", 0.5)
      .attr("stroke-width", 2);

    const edgeHits = svg
      .append("g")
      .selectAll<SVGLineElement, SimEdge>("line")
      .data(simEdges)
      .join("line")
      .attr("data-testid", "graph-edge")
      .attr("data-session", (d) => d.sessionId)
      .attr("stroke", "transparent")
      .attr("stroke-width", 16)
      .style("cursor", "pointer")
      .on("click", (_event, d) => onSelectSession(d.sessionId));

    edgeHits.append("title").text((d) => `${d.severity} · ${d.sessionId}`);

    const nodeSelection = svg
      .append("g")
      .selectAll<SVGCircleElement, SimNode>("circle")
      .data(simNodes)
      .join("circle")
      .attr("data-testid", "graph-node")
      .attr("data-peer", (d) => d.id)
      .attr("data-severity", (d) => d.severity)
      // A literal hex, not a var(): the value is read back in the e2e specs.
      .attr("fill", (d) => SEVERITY_HEX[d.severity])
      .attr("r", (d) => 7 + Math.min(9, d.sessions * 1.6))
      .attr("stroke", "#1c1c1e")
      .attr("stroke-width", 2)
      .style("cursor", "pointer")
      .on("click", (_event, d) => onSelectPeer(d.id));

    nodeSelection
      .append("title")
      .text((d) => `${d.id} · ${d.sessions} session${d.sessions === 1 ? "" : "s"} · ${d.severity}`);

    const labels = svg
      .append("g")
      .selectAll<SVGTextElement, SimNode>("text")
      .data(simNodes)
      .join("text")
      .text((d) => d.id)
      .attr("fill", "#98989d")
      .attr("font-size", 11)
      .attr("font-family", "ui-monospace, 'SF Mono', Menlo, monospace")
      .attr("text-anchor", "middle")
      .attr("pointer-events", "none");

    const centre = d3.forceCenter(host.clientWidth / 2, host.clientHeight / 2);

    const simulation = d3
      .forceSimulation(simNodes)
      .force(
        "link",
        d3
          .forceLink<SimNode, SimEdge>(simEdges)
          .id((d) => d.id)
          .distance(120),
      )
      .force("charge", d3.forceManyBody().strength(-320))
      .force("center", centre)
      .force("collide", d3.forceCollide(34))
      // forceCenter alone only translates the centroid; a gentle pull toward
      // the middle keeps a sparse capture (two peers, one edge) from settling
      // in a corner of a large panel.
      .force("x", d3.forceX(() => host.clientWidth / 2).strength(0.06))
      .force("y", d3.forceY(() => host.clientHeight / 2).strength(0.06))
      .on("tick", () => {
        for (const lines of [edgeSelection, edgeHits]) {
          lines
            .attr("x1", (d) => (d.source as SimNode).x ?? 0)
            .attr("y1", (d) => (d.source as SimNode).y ?? 0)
            .attr("x2", (d) => (d.target as SimNode).x ?? 0)
            .attr("y2", (d) => (d.target as SimNode).y ?? 0);
        }
        nodeSelection.attr("cx", (d) => d.x ?? 0).attr("cy", (d) => d.y ?? 0);
        labels.attr("x", (d) => d.x ?? 0).attr("y", (d) => (d.y ?? 0) - 22);
      });

    nodeSelection.call(
      d3
        .drag<SVGCircleElement, SimNode>()
        .on("start", (event, d) => {
          if (!event.active) simulation.alphaTarget(0.25).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          // Released nodes stay put: a layout the user arranged is a layout
          // they meant, and re-floating it undoes their work.
          d.fx = event.x;
          d.fy = event.y;
        }),
    );

    // The panel is sized by flex layout, so its box is not final when the
    // effect runs -- centring on a stale measurement leaves the graph parked
    // in a corner. Re-centre whenever the box changes, including that first
    // settle.
    const resize = new ResizeObserver(() => {
      centre.x(host.clientWidth / 2).y(host.clientHeight / 2);
      simulation.alpha(0.3).restart();
    });
    resize.observe(host);

    return () => {
      resize.disconnect();
      simulation.stop();
    };
  }, [nodes, edges, onSelectPeer, onSelectSession]);

  return <svg ref={hostRef} className="h-full w-full" role="img" aria-label="Peer graph" />;
}
