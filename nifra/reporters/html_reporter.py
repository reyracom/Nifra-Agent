from __future__ import annotations

from pathlib import Path

from nifra.graph.builder import AttackSurfaceGraph
from nifra.reasoning.engine import ExploitChain, ReasoningResult

_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def _esc(s: str) -> str:
    """HTML-escape a value for safe embedding in HTML attributes and text content."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")  # NIFRA-015: prevent single-quote attribute breakout
    )


class HTMLReporter:
    """Generate a standalone HTML security report."""

    def render(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
    ) -> str:
        chains = reasoning_result.exploit_chains
        risk = reasoning_result.risk_level
        risk_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}.get(risk, "#6b7280")

        cards = "\n".join(self._render_chain_card(c, i + 1) for i, c in enumerate(chains))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'none';" />
  <title>NIfra Security Report — {_esc(project_name)}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; }}
    header {{ background: #1e293b; padding: 2rem; border-bottom: 2px solid #334155; }}
    h1 {{ font-size: 1.5rem; color: #38bdf8; }}
    .meta {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }}
    .risk-badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-weight: bold; font-size: 0.85rem; background: {risk_color}; color: white; margin-top: 0.75rem; }}
    .stats {{ display: flex; gap: 2rem; padding: 1.5rem 2rem; background: #1e293b; border-bottom: 1px solid #334155; }}
    .stat {{ text-align: center; }}
    .stat-val {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
    .stat-label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }}
    .findings {{ padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; overflow: hidden; }}
    .card-header {{ padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem; }}
    .sev {{ padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: bold; color: white; }}
    .card-body {{ padding: 1.5rem; }}
    .section-title {{ font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; margin-bottom: 0.5rem; letter-spacing: 0.05em; }}
    .chain-step {{ padding: 0.25rem 0; color: #cbd5e1; font-size: 0.9rem; }}
    .reasoning {{ color: #94a3b8; font-size: 0.9rem; line-height: 1.6; }}
    .payload {{ background: #0f172a; border: 1px solid #ef4444; border-radius: 0.5rem; padding: 1rem; font-family: monospace; font-size: 0.85rem; color: #fca5a5; white-space: pre-wrap; word-break: break-all; }}
    .remediation li {{ color: #86efac; font-size: 0.9rem; padding: 0.2rem 0; }}
    .score-row {{ display: flex; gap: 2rem; margin-top: 1rem; }}
    .score {{ text-align: center; background: #0f172a; border-radius: 0.5rem; padding: 0.75rem 1.25rem; }}
    .score-val {{ font-size: 1.5rem; font-weight: bold; color: #38bdf8; }}
    .score-lbl {{ font-size: 0.7rem; color: #64748b; text-transform: uppercase; }}
    footer {{ text-align: center; padding: 2rem; color: #475569; font-size: 0.8rem; }}
    a {{ color: #38bdf8; }}
  </style>
</head>
<body>
  <header>
    <h1>🛡 NIfra Security Report</h1>
    <div class="meta">Project: <strong>{_esc(project_name)}</strong> · Model: {_esc(reasoning_result.reasoning_model)}</div>
    <div class="risk-badge">Risk Level: {risk}</div>
  </header>
  <div class="stats">
    <div class="stat"><div class="stat-val">{attack_surface.node_count}</div><div class="stat-label">Nodes</div></div>
    <div class="stat"><div class="stat-val">{attack_surface.edge_count}</div><div class="stat-label">Edges</div></div>
    <div class="stat"><div class="stat-val">{len(attack_surface.findings)}</div><div class="stat-label">Findings</div></div>
    <div class="stat"><div class="stat-val">{sum(1 for c in chains if c.severity == "critical")}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-val">{sum(1 for c in chains if c.severity == "high")}</div><div class="stat-label">High</div></div>
  </div>
  <div class="findings">
    {cards if cards else "<p style='color:#64748b;padding:2rem'>No findings detected.</p>"}
  </div>
  <footer>Generated by <a href="https://github.com/reyracom/Nifra-Agent">NIfra</a> — AI Application Security Autopilot</footer>
</body>
</html>"""

    def _render_chain_card(self, chain: ExploitChain, index: int) -> str:
        sev = chain.severity.lower()
        color = _SEVERITY_COLOR.get(sev, "#6b7280")
        steps_html = "\n".join(
            f'<div class="chain-step">{_esc(step)}</div>'
            for step in chain.attack_chain_steps
        )
        payload_html = ""
        if chain.adversarial_payload:
            payload_html = f"""
              <div class="section-title" style="margin-top:1rem">Adversarial Payload</div>
              <div class="payload">{_esc(chain.adversarial_payload)}</div>"""

        rem_items = "\n".join(
            f'<li>{_esc(r.get("action", r) if isinstance(r, dict) else r)}</li>'
            for r in chain.remediation[:3]
        )

        return f"""
    <div class="card">
      <div class="card-header">
        <span style="font-size:1.1rem;font-weight:bold">#{index:03d}</span>
        <span class="sev" style="background:{color}">{_esc(chain.severity.upper())}</span>
        <span style="font-weight:600">{_esc(chain.finding_rule_id)}</span>
      </div>
      <div class="card-body">
        <div class="section-title">Attack Chain</div>
        {steps_html}
        <div class="section-title" style="margin-top:1rem">Reasoning</div>
        <div class="reasoning">{_esc(chain.reasoning)}</div>
        <div class="section-title" style="margin-top:1rem">Impact</div>
        <div class="reasoning">{_esc(chain.impact)}</div>
        {payload_html}
        <div class="section-title" style="margin-top:1rem">Remediation</div>
        <ul class="remediation">{rem_items}</ul>
        <div class="score-row">
          <div class="score"><div class="score-val">{chain.confidence:.0%}</div><div class="score-lbl">Confidence</div></div>
          <div class="score"><div class="score-val">{chain.cvss_ai:.1f}</div><div class="score-lbl">CVSS-AI</div></div>
          <div class="score"><div class="score-val">{"YES" if chain.exploit_reproducible else "NO"}</div><div class="score-lbl">Reproducible</div></div>
        </div>
      </div>
    </div>"""

    def write(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
        output_path: Path,
    ) -> None:
        content = self.render(attack_surface, reasoning_result, project_name)
        output_path.write_text(content, encoding="utf-8")
