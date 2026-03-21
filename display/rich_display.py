"""
Rich-based renderer: polished terminal output using the `rich` library.

Imported lazily — if rich is not installed, display/__init__.py falls back
to plain.py automatically. This file must not be imported directly from
outside the display package.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

_console = Console()


def _score_color(score: int) -> str:
    if score < 25:
        return "bright_red"
    if score < 40:
        return "red"
    if score < 60:
        return "yellow"
    if score < 80:
        return "green"
    return "bright_green"


def _score_bar(score: int, width: int = 38) -> Text:
    filled = int(score / 100 * width)
    color = _score_color(score)
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="bright_black")
    return bar


def _check(flag: bool) -> Text:
    if flag:
        return Text("✓", style="bright_green")
    return Text("✗", style="bright_red")


def render_analysis(result) -> None:
    """Render a full analysis report using rich."""
    color = _score_color(result.score)

    # ---- Score bar panel ----
    score_text = Text()
    score_text.append(_score_bar(result.score))
    score_text.append(f"  {result.label} ", style=f"bold {color}")
    score_text.append(f"({result.score}/100)", style="dim")

    _console.print()
    _console.print(Panel(score_text, title="[bold]Password Analysis[/bold]",
                          border_style=color, expand=False, padding=(0, 1)))

    # ---- Details table ----
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("key", style="dim", width=14)
    table.add_column("value")

    table.add_row(
        "Entropy",
        f"[cyan]{result.entropy_bits:.1f} bits[/cyan] effective  "
        f"[dim](raw: {result.raw_entropy_bits:.1f} bits)[/dim]",
    )
    table.add_row("Length", str(len(result.password)))

    # Character classes
    classes = Text()
    classes.append("Lowercase ")
    classes.append(_check(result.has_lower))
    classes.append("   Uppercase ")
    classes.append(_check(result.has_upper))
    classes.append("   Digits ")
    classes.append(_check(result.has_digit))
    classes.append("   Symbols ")
    classes.append(_check(result.has_symbol))
    table.add_row("Classes", classes)

    _console.print(table)

    # HIBP
    if result.hibp_count is not None:
        if result.hibp_count > 0:
            _console.print(
                f"  [bold red]⚠  Seen {result.hibp_count:,} times in HaveIBeenPwned breach databases[/bold red]"
            )
        else:
            _console.print("  [bright_green]✓  Not found in HaveIBeenPwned[/bright_green]")
        _console.print()

    # Penalties
    if result.penalties:
        _console.print("  [bold yellow]Issues detected:[/bold yellow]")
        for p in result.penalties:
            _console.print(f"    [yellow]•[/yellow] {p.description}")
        _console.print()

    # Suggestions
    if result.suggestions:
        _console.print("  [bold]Recommendations:[/bold]")
        for i, s in enumerate(result.suggestions, 1):
            _console.print(f"    [dim]{i}.[/dim] {s.message}")
        _console.print()


def render_password(password: str, score: int, label: str, length: int) -> None:
    """Render a generated random password."""
    color = _score_color(score)
    content = Text()
    content.append(password, style=f"bold cyan")
    content.append(f"\n\nLength: {length}   Strength: ", style="dim")
    content.append(label, style=f"bold {color}")
    content.append(f"   Score: {score}/100", style="dim")

    _console.print()
    _console.print(Panel(content, title="[bold]Generated Password[/bold]",
                          border_style="cyan", expand=False, padding=(0, 2)))
    _console.print()


def render_passphrase(phrase: str, word_count: int, entropy_bits: float, augmented: bool) -> None:
    """Render a generated passphrase."""
    aug_note = "  (augmented with digit + symbol)" if augmented else ""
    content = Text()
    content.append(phrase, style="bold cyan")
    content.append(f"\n\n{word_count} words  ≈ {entropy_bits:.1f} bits of entropy{aug_note}", style="dim")

    _console.print()
    _console.print(Panel(content, title="[bold]Generated Passphrase[/bold]",
                          border_style="cyan", expand=False, padding=(0, 2)))
    _console.print()


def render_pin(pin: str, warning: str | None) -> None:
    """Render a generated PIN."""
    content = Text()
    content.append(pin, style="bold cyan")
    if warning:
        content.append(f"\n\n⚠  {warning}", style="yellow")

    _console.print()
    _console.print(Panel(content, title="[bold]Generated PIN[/bold]",
                          border_style="cyan", expand=False, padding=(0, 2)))
    _console.print()
