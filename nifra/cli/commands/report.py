from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(help="Generate a security report from scan results.")
console = Console()


@app.command()
def report(
    format: str = typer.Option(
        "cli", "--format", "-f",
        help="Output format: cli | json | html | markdown",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Write report to file instead of stdout.",
    ),
    results: Optional[Path] = typer.Option(
        None, "--results", "-r",
        help="Path to nifra-results.json from a previous scan.",
    ),
) -> None:
    """
    Generate a formatted security report from scan results.

    Examples:
        nifra report --format html --output report.html
        nifra report --format markdown
        nifra report --format json --output nifra-results.json
    """
    from nifra.reasoning.engine import ExploitChain, ReasoningResult
    from nifra.graph.builder import AttackSurfaceGraph
    import networkx as nx

    # Locate results file
    if results is None:
        # Search common locations
        candidates = [
            Path("nifra-results.json"),
            Path("./nifra-results.json"),
        ]
        found = next((p for p in candidates if p.exists()), None)
        if not found:
            console.print("[red]Error:[/red] No results file found. Run [bold]nifra scan[/bold] first.")
            raise typer.Exit(code=1)
        results = found

    try:
        data = json.loads(results.read_text(encoding="utf-8"))
    except OSError:
        console.print("[red]Error:[/red] Could not read results file \u2014 check the path and permissions.")
        raise typer.Exit(code=1)
    except json.JSONDecodeError:
        console.print("[red]Error:[/red] Invalid JSON in results file.")
        raise typer.Exit(code=1)

    # Reconstruct objects from JSON
    project_name = data.get("project", "unknown")

    # Rebuild ReasoningResult from JSON
    chains = []
    for cd in data.get("exploit_chains", []):
        chains.append(ExploitChain(
            case_id=cd.get("case_id", "?"),
            finding_rule_id=cd.get("finding_rule_id", "?"),
            severity=cd.get("severity", "info"),
            attack_chain_steps=cd.get("attack_chain_steps", []),
            reasoning=cd.get("reasoning", ""),
            impact=cd.get("impact", ""),
            adversarial_payload=cd.get("adversarial_payload"),
            exploit_reproducible=cd.get("exploit_reproducible", False),
            confidence=cd.get("confidence", 0.0),
            cvss_ai=cd.get("cvss_ai", 0.0),
            remediation=cd.get("remediation", []),
        ))

    reasoning_result = ReasoningResult(
        exploit_chains=chains,
        reasoning_model=data.get("summary", {}).get("model", "unknown"),
    )

    # Rebuild minimal AttackSurfaceGraph from JSON
    graph_data = data.get("attack_graph", {})
    g = nx.DiGraph()
    for node in graph_data.get("nodes", []):
        # NIFRA-012: use get() instead of pop() to avoid mutating shared dict objects
        nid = node.get("id") or node.get("node_id")
        if nid:
            attrs = {k: v for k, v in node.items() if k != "id"}
            g.add_node(nid, **attrs)
    for edge in graph_data.get("edges", []):
        src = edge.get("source")
        tgt = edge.get("target")
        if src and tgt:
            g.add_edge(src, tgt, **{k: v for k, v in edge.items() if k not in ("source", "target")})

    from nifra.graph.rules import RiskFinding, Severity
    findings = []
    for fd in graph_data.get("findings", []):
        findings.append(RiskFinding(
            rule_id=fd.get("rule_id", "?"),
            rule_name=fd.get("rule_name", "?"),
            severity=Severity(fd.get("severity", "info")),
            owasp_ref=fd.get("owasp_ref", ""),
            description=fd.get("description", ""),
            evidence=fd.get("evidence", []),
            confidence=fd.get("confidence", 0.8),
            exploit_reproducible=fd.get("exploit_reproducible", False),
            remediation=fd.get("remediation", []),
        ))

    attack_surface = AttackSurfaceGraph(graph=g, project_path=results.parent)
    attack_surface.findings = findings

    # Render
    fmt = format.lower()
    if fmt == "cli":
        from nifra.reporters.cli_reporter import CLIReporter
        CLIReporter().render(attack_surface, reasoning_result, project_name)

    elif fmt == "json":
        from nifra.reporters.json_reporter import JSONReporter
        reporter = JSONReporter()
        content = reporter.render(attack_surface, reasoning_result, project_name)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Saved:[/green] {output}")
        else:
            sys.stdout.buffer.write(content.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")

    elif fmt == "html":
        from nifra.reporters.html_reporter import HTMLReporter
        reporter = HTMLReporter()
        content = reporter.render(attack_surface, reasoning_result, project_name)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Saved:[/green] {output}")
        else:
            sys.stdout.buffer.write(content.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")

    elif fmt == "markdown":
        from nifra.reporters.markdown_reporter import MarkdownReporter
        reporter = MarkdownReporter()
        content = reporter.render(attack_surface, reasoning_result, project_name)
        if output:
            output.write_text(content, encoding="utf-8")
            console.print(f"[green]Saved:[/green] {output}")
        else:
            sys.stdout.buffer.write(content.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
    else:
        console.print(f"[red]Unknown format:[/red] {format}. Choose: cli, json, html, markdown")
        raise typer.Exit(code=1)
