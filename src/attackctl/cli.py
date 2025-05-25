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
    update: bool = typer.Option(False, "--update", help="Update cache before mapping"),
) -> None:
    """Generate detection rules for a specific technique."""
    from attackctl.data import AttackDataManager
    from attackctl.rules import SigmaRuleGenerator
    
    data_manager = AttackDataManager()
    
    try:
        bundle = data_manager.get_data(force_update=update)
        technique = bundle.get_technique_by_id(technique_id.upper())
        
        if not technique:
            console.print(f"[red]Technique {technique_id} not found[/red]")
            console.print("[dim]Try using 'attackctl search' to find the correct ID[/dim]")
            raise typer.Exit(1)
        
        if to.lower() == "sigma":
            generator = SigmaRuleGenerator()
            rule = generator.generate_sigma_rule(technique)
            
            if rule:
                rule_yaml = generator.export_rule_yaml(rule)
                
                if output:
                    # Write to file
                    output.write_text(rule_yaml, encoding='utf-8')
                    console.print(f"✅ Sigma rule saved to: [cyan]{output}[/cyan]")
                else:
                    # Print to console
                    console.print(f"🗺️  Generated Sigma rule for [cyan]{technique_id}[/cyan]:")
                    console.print()
                    console.print(rule_yaml)
            else:
                console.print(f"[yellow]No rule template available for technique {technique_id}[/yellow]")
                console.print("[dim]Rule generation supports: T1003, T1003.001, T1059, T1059.003, T1055, T1053[/dim]")
        else:
            console.print(f"[red]Unsupported format: {to}[/red]")
            console.print("[dim]Currently supported: sigma[/dim]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Error generating detection rule: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def coverage(
    rules_path: Path = typer.Argument(..., help="Path to rules directory"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, markdown, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    update: bool = typer.Option(False, "--update", help="Update cache before analysis"),
    show_covered: bool = typer.Option(False, "--show-covered", help="Show techniques with detection coverage"),
    show_gaps: bool = typer.Option(True, "--show-gaps/--hide-gaps", help="Show techniques without coverage"),
) -> None:
    """Analyze detection coverage across ATT&CK techniques."""
    from attackctl.data import AttackDataManager
    from attackctl.rules import CoverageAnalyzer
    import json
    
    data_manager = AttackDataManager()
    
    try:
        if not rules_path.exists():
            console.print(f"[red]Rules directory does not exist: {rules_path}[/red]")
            raise typer.Exit(1)
        
        console.print(f"📈 Analyzing coverage for rules in: [cyan]{rules_path}[/cyan]")
        
        bundle = data_manager.get_data(force_update=update)
        analyzer = CoverageAnalyzer(bundle)
        
        # Perform coverage analysis
        with console.status("Analyzing detection coverage..."):
            coverage_results = analyzer.analyze_directory(rules_path)
            report = analyzer.generate_coverage_report(coverage_results)
        
        if format == "json":
            report_json = json.dumps(report, indent=2)
            if output:
                output.write_text(report_json, encoding='utf-8')
                console.print(f"✅ Coverage report saved to: [cyan]{output}[/cyan]")
            else:
                console.print(report_json)
        
        elif format == "table":
            _render_coverage_table(report, show_covered, show_gaps)
            
        elif format == "markdown":
            markdown_report = _generate_coverage_markdown(report, show_covered, show_gaps)
            if output:
                output.write_text(markdown_report, encoding='utf-8')
                console.print(f"✅ Coverage report saved to: [cyan]{output}[/cyan]")
            else:
                console.print(markdown_report)
        
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Error analyzing coverage: {e}[/red]")
        raise typer.Exit(1)


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


def _render_coverage_table(report: dict, show_covered: bool, show_gaps: bool) -> None:
    """Render coverage analysis as a Rich table."""
    from rich.table import Table
    
    # Summary
    summary = report["summary"]
    console.print()
    console.print(f"📊 [bold]Coverage Summary[/bold]")
    console.print(f"   Total Techniques: {summary['total_techniques']}")
    console.print(f"   Covered: [green]{summary['covered_techniques']}[/green] ({summary['coverage_percentage']:.1f}%)")
    console.print(f"   Gaps: [red]{summary['uncovered_techniques']}[/red]")
    console.print()
    
    # Tactic breakdown
    tactic_table = Table(title="Coverage by Tactic")
    tactic_table.add_column("Tactic", style="cyan")
    tactic_table.add_column("Covered", style="green", justify="right")
    tactic_table.add_column("Total", style="blue", justify="right")
    tactic_table.add_column("Percentage", style="magenta", justify="right")
    
    for tactic, data in report["tactic_breakdown"].items():
        percentage = data["percentage"]
        color = "green" if percentage >= 70 else "yellow" if percentage >= 40 else "red"
        tactic_table.add_row(
            tactic.replace("-", " ").title(),
            str(data["covered"]),
            str(data["total"]),
            f"[{color}]{percentage:.1f}%[/{color}]"
        )
    
    console.print(tactic_table)
    
    # Technique details
    if show_gaps or show_covered:
        console.print()
        techniques = report["technique_details"]
        
        if show_gaps:
            gaps = [t for t in techniques if not t["has_detection"]]
            if gaps:
                gap_table = Table(title=f"Techniques Without Detection ({len(gaps)})")
                gap_table.add_column("ID", style="cyan", no_wrap=True)
                gap_table.add_column("Name", style="red")
                
                for technique in gaps[:20]:  # Show first 20
                    gap_table.add_row(technique["technique_id"], technique["technique_name"])
                
                if len(gaps) > 20:
                    gap_table.add_row("...", f"and {len(gaps) - 20} more")
                
                console.print(gap_table)
        
        if show_covered:
            covered = [t for t in techniques if t["has_detection"]]
            if covered:
                covered_table = Table(title=f"Techniques With Detection ({len(covered)})")
                covered_table.add_column("ID", style="cyan", no_wrap=True)
                covered_table.add_column("Name", style="green")
                covered_table.add_column("Rules", style="blue", justify="right")
                
                for technique in covered[:20]:  # Show first 20
                    covered_table.add_row(
                        technique["technique_id"], 
                        technique["technique_name"],
                        str(technique["rule_count"])
                    )
                
                if len(covered) > 20:
                    covered_table.add_row("...", f"and {len(covered) - 20} more", "")
                
                console.print(covered_table)


def _generate_coverage_markdown(report: dict, show_covered: bool, show_gaps: bool) -> str:
    """Generate coverage report as Markdown."""
    summary = report["summary"]
    
    md = f"""# ATT&CK Detection Coverage Report

## Summary

- **Total Techniques**: {summary['total_techniques']}
- **Covered**: {summary['covered_techniques']} ({summary['coverage_percentage']:.1f}%)
- **Gaps**: {summary['uncovered_techniques']}

## Coverage by Tactic

| Tactic | Covered | Total | Percentage |
|--------|---------|-------|------------|
"""
    
    for tactic, data in report["tactic_breakdown"].items():
        md += f"| {tactic.replace('-', ' ').title()} | {data['covered']} | {data['total']} | {data['percentage']:.1f}% |\n"
    
    if show_gaps:
        techniques = report["technique_details"]
        gaps = [t for t in techniques if not t["has_detection"]]
        
        if gaps:
            md += f"\n## Techniques Without Detection ({len(gaps)})\n\n"
            md += "| ID | Name |\n|----|----- |\n"
            for technique in gaps:
                md += f"| {technique['technique_id']} | {technique['technique_name']} |\n"
    
    if show_covered:
        techniques = report["technique_details"]
        covered = [t for t in techniques if t["has_detection"]]
        
        if covered:
            md += f"\n## Techniques With Detection ({len(covered)})\n\n"
            md += "| ID | Name | Rules |\n|----|------|-------|\n"
            for technique in covered:
                md += f"| {technique['technique_id']} | {technique['technique_name']} | {technique['rule_count']} |\n"
    
    return md


if __name__ == "__main__":
    app()