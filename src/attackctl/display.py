"""Display utilities for technique details and other data."""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.markdown import Markdown
import yaml
import json

from attackctl.models import Technique, AttackBundle

console = Console()


def get_mitre_attack_url(technique_id: str) -> str:
    """Generate MITRE ATT&CK URL for a technique ID."""
    base_url = "https://attack.mitre.org/techniques"
    if "." in technique_id:
        parent_id, sub_id = technique_id.split(".", 1)
        return f"{base_url}/{parent_id}/{sub_id}/"
    else:
        return f"{base_url}/{technique_id}/"


def render_technique_details(technique: Technique, format: str = "yaml") -> None:
    """Render detailed information about a technique."""
    if format == "yaml":
        _render_technique_yaml(technique)
    elif format == "json":
        _render_technique_json(technique)
    elif format == "markdown":
        _render_technique_markdown(technique)
    else:
        console.print(f"[red]Unknown format: {format}[/red]")


def _render_technique_yaml(technique: Technique) -> None:
    """Render technique as YAML."""
    # Prepare data for YAML output
    data = {
        "id": technique.mitre_id,
        "name": technique.name,
        "description": technique.description,
        "is_subtechnique": technique.is_subtechnique,
    }
    
    if technique.parent_technique:
        data["parent_technique"] = technique.parent_technique
    
    if technique.platforms:
        data["platforms"] = technique.platforms
    
    if technique.data_sources:
        data["data_sources"] = technique.data_sources
    
    if technique.kill_chain_phases:
        data["tactics"] = [phase.phase_name for phase in technique.kill_chain_phases]
    
    if technique.external_references:
        data["references"] = []
        for ref in technique.external_references:
            ref_data = {"source": ref.source_name}
            if ref.url:
                ref_data["url"] = ref.url
            if ref.external_id:
                ref_data["id"] = ref.external_id
            if ref.description:
                ref_data["description"] = ref.description
            data["references"].append(ref_data)
    
    if technique.created:
        data["created"] = technique.created.isoformat()
    
    if technique.modified:
        data["modified"] = technique.modified.isoformat()
    
    if technique.version:
        data["version"] = technique.version
    
    yaml_output = yaml.dump(data, default_flow_style=False, sort_keys=False)
    technique_url = get_mitre_attack_url(technique.mitre_id)
    clickable_title = f"[bold cyan][link={technique_url}]{technique.mitre_id}[/link][/bold cyan]"
    console.print(Panel(yaml_output, title=clickable_title, 
                       title_align="left", border_style="cyan"))


def _render_technique_json(technique: Technique) -> None:
    """Render technique as JSON."""
    data = technique.model_dump(exclude_none=True)
    json_output = json.dumps(data, indent=2, default=str)
    technique_url = get_mitre_attack_url(technique.mitre_id)
    clickable_title = f"[bold cyan][link={technique_url}]{technique.mitre_id}[/link][/bold cyan]"
    console.print(Panel(json_output, title=clickable_title, 
                       title_align="left", border_style="cyan"))


def _render_technique_markdown(technique: Technique) -> None:
    """Render technique as Markdown."""
    technique_url = get_mitre_attack_url(technique.mitre_id)
    md_content = f"""# {technique.name} ([{technique.mitre_id}]({technique_url}))

## Description
{technique.description}

## Details
"""
    
    if technique.is_subtechnique:
        md_content += f"- **Type**: Sub-technique of {technique.parent_technique}\n"
    else:
        md_content += "- **Type**: Technique\n"
    
    if technique.platforms:
        md_content += f"- **Platforms**: {', '.join(technique.platforms)}\n"
    
    if technique.kill_chain_phases:
        tactics = [phase.phase_name.replace('-', ' ').title() for phase in technique.kill_chain_phases]
        md_content += f"- **Tactics**: {', '.join(tactics)}\n"
    
    if technique.data_sources:
        md_content += f"- **Data Sources**: {', '.join(technique.data_sources)}\n"
    
    if technique.version:
        md_content += f"- **Version**: {technique.version}\n"
    
    if technique.created:
        md_content += f"- **Created**: {technique.created.strftime('%Y-%m-%d')}\n"
    
    if technique.modified:
        md_content += f"- **Modified**: {technique.modified.strftime('%Y-%m-%d')}\n"
    
    if technique.external_references:
        md_content += "\n## References\n"
        for ref in technique.external_references:
            if ref.url:
                md_content += f"- [{ref.source_name}]({ref.url})\n"
            else:
                md_content += f"- {ref.source_name}\n"
    
    markdown = Markdown(md_content)
    console.print(markdown)


def render_technique_summary(technique: Technique) -> None:
    """Render a compact summary of a technique."""
    # Create header with ID and name
    technique_url = get_mitre_attack_url(technique.mitre_id)
    header = Text()
    header.append(technique.mitre_id, style=f"bold cyan link {technique_url}")
    header.append(" - ", style="dim")
    header.append(technique.name, style="bold green")
    
    console.print(header)
    
    # Create info table
    info_table = Table.grid(padding=1)
    info_table.add_column(style="dim")
    info_table.add_column()
    
    if technique.is_subtechnique:
        info_table.add_row("Type:", f"Sub-technique of {technique.parent_technique}")
    else:
        info_table.add_row("Type:", "Technique")
    
    if technique.kill_chain_phases:
        tactics = [phase.phase_name.replace('-', ' ').title() for phase in technique.kill_chain_phases]
        info_table.add_row("Tactics:", ", ".join(tactics))
    
    if technique.platforms:
        platforms_str = ", ".join(technique.platforms[:5])
        if len(technique.platforms) > 5:
            platforms_str += f" (+{len(technique.platforms)-5} more)"
        info_table.add_row("Platforms:", platforms_str)
    
    console.print(info_table)
    
    # Description
    if technique.description:
        desc_preview = technique.description[:300]
        if len(technique.description) > 300:
            desc_preview += "..."
        
        console.print(Panel(
            desc_preview,
            title="Description",
            title_align="left",
            border_style="dim",
            padding=(0, 1)
        ))
    
    console.print()  # Add spacing


def render_update_status(bundle: AttackBundle) -> None:
    """Render cache update status."""
    table = Table(title="ATT&CK Data Cache Status")
    table.add_column("Item", style="cyan")
    table.add_column("Count", style="green", justify="right")
    
    table.add_row("Techniques", str(len(bundle.techniques)))
    table.add_row("Sub-techniques", str(sum(1 for t in bundle.techniques if t.is_subtechnique)))
    table.add_row("Tactics", str(len(bundle.tactics)))
    table.add_row("Groups", str(len(bundle.groups)))
    table.add_row("Software", str(len(bundle.software)))
    table.add_row("Mitigations", str(len(bundle.mitigations)))
    table.add_row("Data Sources", str(len(bundle.data_sources)))
    
    if bundle.last_updated:
        table.add_row("Last Updated", bundle.last_updated.strftime("%Y-%m-%d %H:%M:%S"))
    
    if bundle.version != "unknown":
        table.add_row("Version", bundle.version)
    
    console.print(table)