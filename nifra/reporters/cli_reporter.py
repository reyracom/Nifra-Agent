from __future__ import annotations

import sys
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
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

SEVERITY_ICONS = {
    "critical": "💀",
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "bold red on dark_red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}

class CLIReporter:
    """Renders NIfra scan results with animated terminal UI."""

    def __init__(self) -> None:
        self.console = Console()
        # Only animate in real terminals; disable for CI/pipes/redirected output
        self._animate = sys.stdout.isatty()

    # ── Animation helpers ────────────────────────────────────────────────────

    def _sleep(self, t: float) -> None:
        if self._animate:
            time.sleep(t)

    def _spinner(self, message: str, duration: float = 0.8, color: str = "cyan") -> None:
        """Show a transient spinner for a given duration."""
        if not self._animate:
            return
        with Live(
            Spinner("dots2", text=f"[{color}]{message}[/{color}]"),
            console=self.console,
            refresh_per_second=20,
            transient=True,
        ):
            time.sleep(duration)

    def _typewriter(self, text: str, style: str = "", delay: float = 0.012) -> None:
        """Print text character by character with typewriter effect."""
        if not self._animate:
            self.console.print(text, style=style, end="\n")
            return
        for char in text:
            self.console.print(char, end="", style=style, highlight=False)
            sys.stdout.flush()
            time.sleep(delay)
        self.console.print()

    def _glitch_reveal(self, text: str, style: str = "bold red") -> None:
        """Reveal text with a brief glitch animation."""
        if not self._animate:
            self.console.print(text, style=style)
            return
        glitch_chars = "▓▒░█▄▀■□▪▫"
        import random
        words = text.split()
        for i, word in enumerate(words):
            scrambled = "".join(random.choice(glitch_chars) for _ in word)
            line = " ".join(words[:i] + [scrambled] + [""] * (len(words) - i - 1))
            self.console.print(f"\r  {line}", end="", style=style, highlight=False)
            time.sleep(0.04)
            self.console.print(f"\r  {' '.join(words[:i+1]):<{len(text)}}", end="", style=style, highlight=False)
            time.sleep(0.03)
        self.console.print()

    # ── Main render ──────────────────────────────────────────────────────────

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

        rows = [
            ("Project",        project_name),
            ("Nodes detected", str(attack_surface.node_count)),
            ("Edges mapped",   str(attack_surface.edge_count)),
            ("Findings",       str(len(attack_surface.findings))),
            ("Exploit chains", str(len(result.exploit_chains))),
            ("Model",          result.reasoning_model),
        ]

        if self._animate:
            with Live(table, console=self.console, refresh_per_second=20):
                for key, val in rows:
                    table.add_row(key, val)
                    time.sleep(0.10)
        else:
            for key, val in rows:
                table.add_row(key, val)
            self.console.print(table)

        risk = result.risk_level
        color = RISK_LEVEL_COLORS.get(risk, "white")

        if self._animate:
            self._spinner("Compiling threat intelligence...", 0.7, "yellow")

        self.console.print()
        self.console.rule(f"[{color}] SCAN COMPLETE — Risk Level: {risk} [/{color}]")
        self.console.print()

    def _render_finding(self, chain: ExploitChain, index: int) -> None:
        sev = chain.severity.lower()
        color = SEVERITY_COLORS.get(sev, "white")
        icon  = SEVERITY_ICONS.get(sev, "⚪")
        base_color = color.replace("bold ", "")

        # ── Finding header ──────────────────────────────────────────────────
        self.console.print()
        self.console.rule(
            f"[{color}] {icon}  Finding #{index:03d} · {chain.finding_rule_id} · "
            f"{chain.severity.upper()} [/{color}]",
            align="left",
        )

        # ── Simulate attack loading ─────────────────────────────────────────
        self._spinner(
            f"Simulating exploit for {chain.finding_rule_id}...",
            duration=1.0,
            color=base_color,
        )

        # ── Exploit Chain steps (animated typewriter per step) ──────────────
        self.console.print(f"\n  [bold cyan]Exploit Chain[/bold cyan]")
        for step in chain.attack_chain_steps:
            if self._animate:
                self.console.print(f"    [dim cyan]▶[/dim cyan] ", end="", highlight=False)
                self._typewriter(step, style="dim", delay=0.008)
                self._sleep(0.12)
            else:
                self.console.print(f"    [dim]▶ {step}[/dim]")

        # ── Adversarial Payload (typewriter injection effect) ───────────────
        if chain.adversarial_payload:
            self._sleep(0.3)
            self.console.print()
            if self._animate:
                self._spinner("Crafting adversarial payload...", 0.8, "red")
                self.console.print(f"  [bold red]⚡ Adversarial Payload[/bold red]")
                self._sleep(0.1)
                width = min(len(chain.adversarial_payload) + 4, 70)
                self.console.print(f"  [red]╭{'─' * width}╮[/red]")
                self.console.print(f"  [red]│[/red]  ", end="", highlight=False)
                self._typewriter(chain.adversarial_payload, style="bold yellow", delay=0.018)
                self.console.print(f"  [red]╰{'─' * width}╯[/red]")
            else:
                self.console.print(f"  [bold red]⚡ Adversarial Payload[/bold red]")
                self.console.print(
                    Panel(
                        f"[bold yellow]{chain.adversarial_payload}[/bold yellow]",
                        border_style="red",
                        padding=(0, 2),
                    )
                )

        # ── AI Reasoning ──────────────────────────────────────────────────
        self._sleep(0.2)
        if self._animate:
            self._spinner("AI analyzing exploit path...", 0.6, "cyan")
        self.console.print(
            Panel(
                chain.reasoning,
                title="[bold]AI Reasoning[/bold]",
                border_style="dim",
                padding=(0, 2),
            )
        )

        # ── Scoring ──────────────────────────────────────────────────────────
        conf_color = "red" if chain.confidence >= 0.85 else ("yellow" if chain.confidence >= 0.7 else "green")
        cvss_color = "red" if chain.cvss_ai >= 7 else ("yellow" if chain.cvss_ai >= 4 else "green")

        score_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        score_table.add_column("K", style="dim")
        score_table.add_column("V")
        score_table.add_row("Confidence",    f"[{conf_color}]{chain.confidence:.0%}[/{conf_color}]")
        score_table.add_row("CVSS-AI Score", f"[{cvss_color}]{chain.cvss_ai:.1f}[/{cvss_color}]")
        score_table.add_row("Reproducible",  "[bold red]YES ⚠[/bold red]" if chain.exploit_reproducible else "[green]NO[/green]")
        self.console.print(score_table)

        # ── Fix (animated checkmarks) ──────────────────────────────────────
        if chain.remediation:
            self.console.print(f"  [bold green]🔧 Fix[/bold green]")
            for fix in chain.remediation[:3]:
                action = fix.get("action", fix) if isinstance(fix, dict) else fix
                if self._animate:
                    self._sleep(0.08)
                    self.console.print(f"    [green]✓[/green] ", end="", highlight=False)
                    self._typewriter(str(action), delay=0.005)
                else:
                    self.console.print(f"    [green]✓[/green] {action}")

    def _render_footer(self, result: ReasoningResult) -> None:
        self.console.print()
        if self._animate:
            self._spinner("Finalizing report...", 0.5, "green")
        self.console.rule()
        self.console.print("  [dim]Full report:[/dim]  nifra report --format html")
        self.console.print("  [dim]JSON export:[/dim]  nifra report --format json")
        self.console.print("  [dim]PR comment:[/dim]   nifra report --format markdown")
        self.console.rule()
        self.console.print()
