from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from nifra import __version__
from nifra.reasoning.engine import ExploitChain, ReasoningResult
from nifra.graph.builder import AttackSurfaceGraph


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "info": "blue",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "bold red on dark_red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}


class CLIReporter:
    """Renders full NIfra scan results to the terminal using Rich."""

    def __init__(self) -> None:
        self.console = Console()

    def render(
        self,
        attack_surface: AttackSurfaceGraph,
        reasoning_result: ReasoningResult,
        project_name: str,
    ) -> None:
        self._render_header(project_name, attack_surface, reasoning_result)
        for i, chain in enumerate(reasoning_result.exploit_chains):
            self._render_finding(chain, index=i + 1)
        self._render_footer(reasoning_result)

    def _render_header(
        self,
        project_name: str,
        attack_surface: AttackSurfaceGraph,
        result: ReasoningResult,
    ) -> None:
        self.console.print()
        self.console.rule(f"[bold cyan]NIfra — AI Application Security Autopilot v{__version__}[/bold cyan]")
        self.console.print()

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Key", style="dim")
        table.add_column("Value")
        table.add_row("Project", project_name)
        table.add_row("Nodes detected", str(attack_surface.node_count))
        table.add_row("Edges mapped", str(attack_surface.edge_count))
        table.add_row("Findings", str(len(attack_surface.findings)))
        table.add_row("Exploit chains", str(len(result.exploit_chains)))
        table.add_row("Model", result.reasoning_model)
        self.console.print(table)

        risk = result.risk_level
        color = RISK_LEVEL_COLORS.get(risk, "white")
        self.console.print()
        self.console.rule(f"[{color}] SCAN COMPLETE — Risk Level: {risk} [/{color}]")
        self.console.print()

    def _render_finding(self, chain: ExploitChain, index: int) -> None:
        sev = chain.severity.lower()
        color = SEVERITY_COLORS.get(sev, "white")

        # ── Layer 1: Finding header ──────────────────────────────────────────
        self.console.print()
        self.console.rule(
            f"[{color}] Finding #{index:03d} · {chain.finding_rule_id} · "
            f"{chain.severity.upper()} [/{color}]",
            align="left",
        )

        # ── Layer 2: Exploit Chain ──────────────────────────────────────────
        self.console.print(f"\n  [bold cyan]Exploit Chain[/bold cyan]")
        for step in chain.attack_chain_steps:
            self.console.print(f"    [dim]{step}[/dim]")

        # ── Layer 3: Reasoning ──────────────────────────────────────────────
        self.console.print(
            Panel(
                chain.reasoning,
                title="[bold]AI Reasoning[/bold]",
                border_style="dim",
                padding=(0, 2),
            )
        )

        # ── Layer 4: Adversarial Payload ────────────────────────────────────
        if chain.adversarial_payload:
            self.console.print(f"\n  [bold red]Adversarial Payload[/bold red]")
            self.console.print(
                Panel(
                    f"[bold yellow]{chain.adversarial_payload}[/bold yellow]",
                    border_style="red",
                    padding=(0, 2),
                )
            )

        # ── Layer 5: Scoring + Fix ──────────────────────────────────────────
        score_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        score_table.add_column("K", style="dim")
        score_table.add_column("V")
        score_table.add_row("Confidence", f"{chain.confidence:.0%}")
        score_table.add_row("CVSS-AI Score", f"{chain.cvss_ai:.1f}")
        score_table.add_row("Reproducible", "YES" if chain.exploit_reproducible else "NO")
        self.console.print(score_table)

        if chain.remediation:
            self.console.print(f"  [bold green]Fix[/bold green]")
            for fix in chain.remediation[:3]:
                action = fix.get("action", fix) if isinstance(fix, dict) else fix
                self.console.print(f"    [green]✓[/green] {action}")

    def _render_footer(self, result: ReasoningResult) -> None:
        self.console.print()
        self.console.rule()
        self.console.print("  [dim]Full report:[/dim]  nifra report --format html")
        self.console.print("  [dim]JSON export:[/dim]  nifra report --format json")
        self.console.print("  [dim]PR comment:[/dim]   nifra report --format markdown")
        self.console.rule()
        self.console.print()
