import typer
from nifra.cli.commands.scan import scan
from nifra.cli.commands.report import report
from nifra.cli.commands.reproduce import reproduce
from nifra.cli.commands.fix import fix

app = typer.Typer(
    name="nifra",
    help="AI Application Security Autopilot — exploit simulation & attack surface mapping for LLM apps.",
    add_completion=False,
    rich_markup_mode="markdown",
)

app.command("scan")(scan)
app.command("report")(report)
app.command("reproduce")(reproduce)
app.command("fix")(fix)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
