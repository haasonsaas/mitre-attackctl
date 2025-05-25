"""Main CLI entry point for attackctl."""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional
from pathlib import Path

from attackctl import __version__

app = typer.Typer(
    name="attackctl",
    help="A fast, batteries-included CLI companion for MITRE ATT&CK® TTPs",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        typer.echo(f"attackctl version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    )
) -> None:
    """attackctl - MITRE ATT&CK® CLI companion."""
    pass


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query for techniques"),
    limit: int = typer.Option(10, "--limit", "-l", help="Maximum results to show"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json, yaml)"),
    update: bool = typer.Option(False, "--update", help="Update cache before searching"),
) -> None:
    """Search for ATT&CK techniques using fuzzy matching."""
    from attackctl.data import AttackDataManager
    from attackctl.search import TechniqueSearcher, render_search_results
    
    data_manager = AttackDataManager()
    
    try:
        bundle = data_manager.get_data(force_update=update)
        searcher = TechniqueSearcher(bundle)
        results = searcher.search(query, limit=limit)
        
        if results:
            console.print(f"🔍 Found {len(results)} technique(s) for: [bold cyan]{query}[/bold cyan]")
            render_search_results(results, format=format)
        else:
            console.print(f"[yellow]No techniques found for: {query}[/yellow]")
            console.print("[dim]Try a broader search term or use partial matches[/dim]")
            
    except Exception as e:
        console.print(f"[red]Error during search: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def show(
    technique_id: str = typer.Argument(..., help="Technique ID (e.g., T1098.004)"),
    format: str = typer.Option("yaml", "--format", "-f", help="Output format (yaml, json, markdown)"),
    update: bool = typer.Option(False, "--update", help="Update cache before showing"),
) -> None:
    """Show detailed information about a specific technique."""
    from attackctl.data import AttackDataManager
    from attackctl.display import render_technique_details
    
    data_manager = AttackDataManager()
    
    try:
        bundle = data_manager.get_data(force_update=update)
        technique = bundle.get_technique_by_id(technique_id.upper())
        
        if technique:
            render_technique_details(technique, format=format)
        else:
            console.print(f"[red]Technique {technique_id} not found[/red]")
            console.print("[dim]Try using 'attackctl search' to find the correct ID[/dim]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Error retrieving technique: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def update(
    force: bool = typer.Option(False, "--force", help="Force update even if cache is recent"),
) -> None:
    """Update the local ATT&CK data cache."""
    from attackctl.data import AttackDataManager
    from attackctl.display import render_update_status
    
    data_manager = AttackDataManager()
    
    try:
        if not force and data_manager.is_cache_fresh():
            console.print("✅ Cache is already fresh")
            bundle = data_manager.load_from_cache()
            if bundle:
                render_update_status(bundle)
        else:
            bundle = data_manager.update_cache(force=force)
            render_update_status(bundle)
            
    except Exception as e:
        console.print(f"[red]Error updating cache: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def diff(
    version1: str = typer.Argument(..., help="First version to compare"),
    version2: str = typer.Argument(..., help="Second version to compare"),
) -> None:
    """Show differences between ATT&CK versions."""
    console.print(f"📊 Comparing [cyan]{version1}[/cyan] vs [cyan]{version2}[/cyan]")
    console.print("[yellow]Note: Diff functionality coming soon![/yellow]")


@app.command()
def map(
    technique_id: str = typer.Argument(..., help="Technique ID to map"),
    to: str = typer.Option("sigma", "--to", help="Target format (sigma, splunk, sentinel)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Map technique to detection rules."""
    console.print(f"🗺️  Mapping [cyan]{technique_id}[/cyan] to [cyan]{to}[/cyan] rules")
    console.print("[yellow]Note: Mapping functionality coming soon![/yellow]")


@app.command()
def coverage(
    rules_path: Path = typer.Argument(..., help="Path to rules directory"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, markdown, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Analyze detection coverage across ATT&CK techniques."""
    console.print(f"📈 Analyzing coverage for rules in: [cyan]{rules_path}[/cyan]")
    console.print("[yellow]Note: Coverage functionality coming soon![/yellow]")


@app.command()
def testgen(
    technique_id: str = typer.Argument(..., help="Technique ID for test generation"),
    output: Path = typer.Option("./tests", "--output", "-o", help="Output directory for tests"),
    format: str = typer.Option("json", "--format", "-f", help="Log format (json, csv)"),
) -> None:
    """Generate synthetic test data for a technique."""
    console.print(f"🧪 Generating test data for: [cyan]{technique_id}[/cyan]")
    console.print("[yellow]Note: Test generation functionality coming soon![/yellow]")


@app.command()
def export(
    format: str = typer.Option("markdown", "--format", "-f", help="Export format (markdown, html, json)"),
    filter: Optional[str] = typer.Option(None, "--filter", help="Filter criteria (e.g., tactic=persistence)"),
    output: Path = typer.Option("export.md", "--output", "-o", help="Output file path"),
) -> None:
    """Export ATT&CK data in various formats."""
    console.print(f"📤 Exporting to [cyan]{format}[/cyan] format")
    if filter:
        console.print(f"🔍 Using filter: [cyan]{filter}[/cyan]")
    console.print("[yellow]Note: Export functionality coming soon![/yellow]")


if __name__ == "__main__":
    app()