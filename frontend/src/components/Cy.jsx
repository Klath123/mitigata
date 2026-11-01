import { useEffect, useRef } from "react";
import cytoscape from "cytoscape";

// Thin Cytoscape wrapper: rebuilds when elements/style/layout change (callers memoize them),
// reports taps on nodes/edges (null on background).
export default function Cy({ elements, style, layout, onTap, height = 540, legend, selected }) {
  const box = useRef(null);
  const cyRef = useRef(null);
  const tap = useRef(onTap);
  tap.current = onTap;

  useEffect(() => {
    const cy = cytoscape({ container: box.current, elements, style, layout, minZoom: 0.15, maxZoom: 3, boxSelectionEnabled: false, autounselectify: true });
    cy.on("tap", "node, edge", (e) => tap.current?.(e.target.data()));
    cy.on("tap", (e) => { if (e.target === cy) tap.current?.(null); });
    cy.on("mouseover", "node, edge", () => { box.current.style.cursor = "pointer"; });
    cy.on("mouseout", "node, edge", () => { box.current.style.cursor = ""; });
    cyRef.current = cy;
    return () => cy.destroy();
  }, [elements, style, layout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("picked");
    if (selected) cy.getElementById(selected).addClass("picked");
  }, [selected, elements]);

  const zoom = (f) => { const cy = cyRef.current; cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); };
  const png = () => {
    const a = document.createElement("a");
    a.href = cyRef.current.png({ full: true, scale: 2, bg: getComputedStyle(box.current).backgroundColor });
    a.download = "attack-graph.png";
    a.click();
  };

  return (
    <div className="cy-wrap" style={{ height }}>
      <div ref={box} className="cy" role="img" aria-label="Interactive graph" />
      <div className="cy-tools">
        <button className="btn sm" onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button className="btn sm" onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <button className="btn sm" onClick={() => cyRef.current.fit(undefined, 30)}>Fit</button>
        <button className="btn sm" onClick={png}>PNG</button>
      </div>
      {legend && <div className="cy-legend">{legend}</div>}
    </div>
  );
}
