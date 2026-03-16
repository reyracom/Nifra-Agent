from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel

app = typer.Typer(help="Scan an AI application for security vulnerabilities.")
console = Console()


@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="Path to the AI application directory to scan.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Save scan results to file (JSON format).",
    ),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit with error code if findings at this severity or above. Options: critical, high, medium.",
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai",
        help="Skip LLM reasoning — deterministic findings only (no OPENAI_API_KEY required).",
    ),
    model: str = typer.Option(
        "nvidia/nemotron-3-super-120b-a12b:free", "--model", "-m",
        help="Model for AI reasoning. OpenRouter (default): nvidia/nemotron-3-super-120b-a12b:free, mistralai/mistral-7b-instruct:free, nvidia/nemotron-super-49b-v1:free. OpenAI: gpt-4o, gpt-4o-mini.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed scan progress."),
) -> None:
    """
    Scan an AI application directory for security vulnerabilities.

    Examples:
        nifra scan ./my-rag-agent
        nifra scan ./my-agent --output results.json --fail-on critical
        nifra scan ./my-agent --no-ai
    """
    from nifra.detectors.dependency_scanner import DependencyScanner
    from nifra.detectors.ast_parser import ASTParser
    from nifra.graph.builder import AttackSurfaceGraphBuilder
    from nifra.reasoning.engine import ReasoningEngine
    from nifra.reporters.cli_reporter import CLIReporter
    from nifra.reporters.json_reporter import JSONReporter

    project_name = target.name

    console.print()
    console.print(Panel(
        f"[bold cyan]Target:[/bold cyan] [white]{target}[/white]\n"
        f"[bold cyan]Model  :[/bold cyan] [white]{'deterministic' if no_ai else model}[/white]",
        title="[bold red]⚔  NIfra Attack Surface Analysis[/bold red]",
        border_style="red",
        padding=(0, 2),
    ))
    console.print()

    with Progress(
        SpinnerColumn(spinner_name="dots2", style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:

        # Step 1: Dependency scan
        task = progress.add_task("[cyan]Mapping AI dependencies...[/cyan]", total=None)
        dep_scanner = DependencyScanner(target)
        dep_result = dep_scanner.scan()
        progress.update(task, description=f"[green]✓[/green] [cyan]Found {len(dep_result.detected_libraries)} AI libraries[/cyan]")

        if verbose:
            for lib in dep_result.detected_libraries:
                console.print(f"  [dim]  dep:[/dim] {lib.name} {lib.version or ''}")

        # Step 2: AST scan
        progress.update(task, description="[cyan] Parsing AST patterns in source code...[/cyan]")
        ast_parser = ASTParser(target)
        ast_result = ast_parser.scan()
        progress.update(
            task,
            description=f"[green]✓[/green] [cyan]Scanned {ast_result.scanned_files} files — "
                        f"{len(ast_result.patterns)} patterns detected[/cyan]",
        )

        if verbose:
            for pattern in ast_result.patterns[:10]:
                console.print(
                    f"  [dim]  ast:[/dim] {pattern.pattern_type} — "
                    f"{pattern.class_or_func} ({pattern.file_path}:{pattern.line_number})"
                )

        # Step 3: Build attack surface graph
        progress.update(task, description="[cyan]🕸  Building threat graph...[/cyan]")
        builder = AttackSurfaceGraphBuilder(dep_result=dep_result, ast_result=ast_result)
        attack_surface = builder.build()
        progress.update(
            task,
            description=f"[green]✓[/green] [cyan]Threat graph: {attack_surface.node_count} nodes, "
                        f"{attack_surface.edge_count} edges — "
                        f"{len(attack_surface.findings)} findings[/cyan]",
        )

        # Step 4: AI reasoning
        if no_ai:
            from nifra.reasoning.engine import ReasoningResult, ExploitChain
            from nifra.reasoning.confidence import ConfidenceComponents, compute_hybrid_confidence

            chains = []
            engine = ReasoningEngine.__new__(ReasoningEngine)
            engine.model = "deterministic"
            engine.temperature = 0
            engine._client = None
            engine._on_progress = lambda _: None
            result = engine._build_deterministic_result(attack_surface)

    # ── Step 4: AI reasoning (outside Progress context so Live can render freely) ──
    if not no_ai:
        import threading
        import time as _time
        from rich.live import Live
        from rich.table import Table
        from rich.console import Console as _Console
        from rich.columns import Columns
        from rich.spinner import Spinner
        from rich.align import Align

        current_step: list[str] = ["Initializing..."]
        step_history: list[str] = []
        result_holder: list = []
        error_holder:  list = []
        start_ts = _time.time()

        STEP_ICONS = {
            "Connecting":  "📡",
            "Reading":     "📂",
            "Mapping":     "🗺 ",
            "Sending":     "📤",
            "Waiting":     "⏳",
            "Received":    "📥",
            "Parsing":     "🔍",
            "Targeting":   "🎯",
            "Severity":    "⚠ ",
            "Done":        "✅",
            "Error":       "❌",
        }

        def _icon_for(msg: str) -> str:
            for key, icon in STEP_ICONS.items():
                if key.lower() in msg.lower():
                    return icon
            return "▸ "

        def _progress_cb(msg: str) -> None:
            # Strip Rich markup for history display
            import re
            clean = re.sub(r"\[/?[^\]]+\]", "", msg).strip()
            if clean:
                step_history.append(clean)
                current_step[0] = clean

        def _run_engine() -> None:
            eng = ReasoningEngine(model=model, on_progress=_progress_cb)
            try:
                result_holder.append(eng.reason(attack_surface))
            except EnvironmentError as e:
                error_holder.append(e)
                _progress_cb(f"Error: {e}")
                result_holder.append(eng._build_deterministic_result(attack_surface))
            except Exception as e:
                error_holder.append(e)
                _progress_cb(f"Error: {e}")
                result_holder.append(eng._build_deterministic_result(attack_surface))
            finally:
                _progress_cb("Done")

        def _build_live_panel() -> Table:
            elapsed = _time.time() - start_ts
            is_alive = t.is_alive()

            root = Table.grid(expand=True)
            root.add_column()

            # ── Header bar ──────────────────────────────────────────────────
            short_model = model.split("/")[-1] if "/" in model else model
            header = Table.grid(padding=(0, 2), expand=True)
            header.add_column(style="dim")
            header.add_column()
            header.add_column(style="dim")
            header.add_column()
            header.add_column(style="dim")
            header.add_column()
            header.add_row(
                "model", f"[cyan]{short_model}[/cyan]",
                "target", f"[white]{project_name}[/white]",
                "elapsed", f"[yellow]{elapsed:.1f}s[/yellow]",
            )
            root.add_row(header)
            root.add_row("")

            # ── Current action (big, prominent) ────────────────────────────
            step = current_step[0]
            icon = _icon_for(step)
            if is_alive:
                spinner = Spinner("dots2", text=f"[bold cyan]{icon}  {step}[/bold cyan]", style="cyan")
                root.add_row(Align(spinner, align="left", pad=True))
            else:
                root.add_row(f"  [bold green]✅  {step}[/bold green]")

            root.add_row("")

            # ── History (last 8 steps, dimmed) ─────────────────────────────
            if len(step_history) > 1:
                shown = step_history[-8:-1]  # exclude current step
                for h in shown:
                    root.add_row(f"   [dim]{'─' * 2}  {h}[/dim]")

            # ── Status bar ─────────────────────────────────────────────────
            root.add_row("")
            if is_alive:
                dots = "●" * (int(elapsed) % 4 + 1) + "○" * (3 - int(elapsed) % 4)
                root.add_row(f"   [dim]{dots}  {len(step_history)} steps completed[/dim]")
            else:
                root.add_row(f"   [dim]─  Complete in {elapsed:.1f}s[/dim]")

            from rich.panel import Panel as _Panel
            return _Panel(
                root,
                title="[bold red]🤖  NIfra — AI Exploit Simulation[/bold red]",
                border_style="red",
                padding=(0, 2),
            )

        t = threading.Thread(target=_run_engine, daemon=True)
        t.start()

        # Use a fresh console for Live so it manages its own terminal state
        live_console = _Console(highlight=False)
        with Live(
            _build_live_panel(),
            console=live_console,
            refresh_per_second=8,
            vertical_overflow="crop",
            transient=False,
        ) as live:
            while t.is_alive():
                _time.sleep(0.125)
                live.update(_build_live_panel())
            live.update(_build_live_panel())

        result = result_holder[0]

    # Render CLI report
    reporter = CLIReporter()
    reporter.render(attack_surface, result, project_name)

    # Save JSON output
    if output:
        json_reporter = JSONReporter()
        json_reporter.write(attack_surface, result, project_name, output)
        console.print(f"[green]Results saved to:[/green] {output}")
    else:
        # NIFRA-010: write to cwd instead of inside the scanned project to prevent
        # accidental git-commit of results containing LLM-generated exploit payloads.
        default_out = Path.cwd() / "nifra-results.json"
        if default_out.exists():
            console.print(f"[yellow]Warning:[/yellow] {default_out} already exists and will be overwritten.")
        json_reporter = JSONReporter()
        json_reporter.write(attack_surface, result, project_name, default_out)
        if verbose:
            console.print(f"[dim]Results cached at {default_out}[/dim]")

    # Exit code logic
    if fail_on:
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = severity_order.get(fail_on.lower(), 4)
        if any(
            severity_order.get(c.severity.lower(), 0) >= threshold
            for c in result.exploit_chains
        ):
            raise typer.Exit(code=1)
