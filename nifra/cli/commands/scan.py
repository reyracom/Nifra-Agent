from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

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

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:

        # Step 1: Dependency scan
        task = progress.add_task("Scanning dependencies...", total=None)
        dep_scanner = DependencyScanner(target)
        dep_result = dep_scanner.scan()
        progress.update(task, description=f"Found {len(dep_result.detected_libraries)} AI libraries")

        if verbose:
            for lib in dep_result.detected_libraries:
                console.print(f"  [dim]  dep:[/dim] {lib.name} {lib.version or ''}")

        # Step 2: AST scan
        progress.update(task, description="Parsing source code...")
        ast_parser = ASTParser(target)
        ast_result = ast_parser.scan()
        progress.update(
            task,
            description=f"Scanned {ast_result.scanned_files} files, "
                        f"found {len(ast_result.patterns)} patterns",
        )

        if verbose:
            for pattern in ast_result.patterns[:10]:
                console.print(
                    f"  [dim]  ast:[/dim] {pattern.pattern_type} — "
                    f"{pattern.class_or_func} ({pattern.file_path}:{pattern.line_number})"
                )

        # Step 3: Build attack surface graph
        progress.update(task, description="Building attack surface graph...")
        builder = AttackSurfaceGraphBuilder(dep_result=dep_result, ast_result=ast_result)
        attack_surface = builder.build()
        progress.update(
            task,
            description=f"Graph: {attack_surface.node_count} nodes, "
                        f"{attack_surface.edge_count} edges, "
                        f"{len(attack_surface.findings)} deterministic findings",
        )

        # Step 4: AI reasoning
        if no_ai:
            from nifra.reasoning.engine import ReasoningResult, ExploitChain
            from nifra.reasoning.confidence import ConfidenceComponents, compute_hybrid_confidence

            # Build deterministic chains without LLM
            chains = []
            engine = ReasoningEngine.__new__(ReasoningEngine)
            engine.model = "deterministic"
            engine.temperature = 0
            engine._client = None
            result = engine._build_deterministic_result(attack_surface)
        else:
            progress.update(task, description="Running AI exploit chain reasoning...")
            engine = ReasoningEngine(model=model)
            try:
                result = engine.reason(attack_surface)
            except EnvironmentError as e:
                console.print(f"\n[yellow]Warning:[/yellow] {e}")
                console.print("[dim]Falling back to deterministic mode (--no-ai)[/dim]\n")
                result = engine._build_deterministic_result(attack_surface)

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
