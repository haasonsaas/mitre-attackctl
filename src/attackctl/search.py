"""Search functionality for ATT&CK techniques."""

from typing import List, Tuple, Optional
from rapidfuzz import fuzz, process
from rich.console import Console
from rich.table import Table
from rich.text import Text

from attackctl.models import AttackBundle, Technique
from attackctl.display import get_mitre_attack_url

console = Console()


class TechniqueSearcher:
    """Handles searching and ranking of ATT&CK techniques."""
    
    def __init__(self, bundle: AttackBundle):
        """Initialize searcher with ATT&CK data bundle."""
        self.bundle = bundle
        self._build_search_index()
    
    def _build_search_index(self) -> None:
        """Build search index for efficient fuzzy matching."""
        self.search_items = []
        
        for technique in self.bundle.techniques:
            # Create searchable strings combining various fields
            search_strings = [
                technique.name,
                technique.mitre_id,
                technique.description[:200],  # Truncate long descriptions
            ]
            
            # Add tactic names from kill chain phases
            for phase in technique.kill_chain_phases:
                if phase.phase_name:
                    search_strings.append(phase.phase_name.replace("-", " "))
            
            # Add platform information
            if technique.platforms:
                search_strings.extend(technique.platforms)
            
            # Create combined search string
            combined = " | ".join(filter(None, search_strings))
            self.search_items.append((combined, technique))
    
    def search(
        self, 
        query: str, 
        limit: int = 10, 
        min_score: int = 40
    ) -> List[Tuple[Technique, int]]:
        """
        Search for techniques using fuzzy matching.
        
        Args:
            query: Search query string
            limit: Maximum number of results
            min_score: Minimum fuzzy match score (0-100)
            
        Returns:
            List of (technique, score) tuples sorted by relevance
        """
        if not query.strip():
            return []
        
        # Extract search strings for fuzzy matching
        search_strings = [item[0] for item in self.search_items]
        
        # Perform fuzzy matching
        matches = process.extract(
            query,
            search_strings,
            scorer=fuzz.WRatio,
            limit=limit * 2,  # Get more results to filter
            score_cutoff=min_score
        )
        
        # Convert back to techniques with scores
        results = []
        seen_ids = set()
        
        for match_string, score, index in matches:
            technique = self.search_items[index][1]
            
            # Avoid duplicates
            if technique.id in seen_ids:
                continue
            seen_ids.add(technique.id)
            
            # Boost score for exact ID matches
            if query.upper() == technique.mitre_id:
                score = 100
            elif query.upper() in technique.mitre_id:
                score = min(100, score + 20)
            
            # Boost score for exact name matches
            if query.lower() == technique.name.lower():
                score = min(100, score + 15)
            elif query.lower() in technique.name.lower():
                score = min(100, score + 10)
            
            results.append((technique, score))
            
            if len(results) >= limit:
                break
        
        # Sort by score (descending)
        results.sort(key=lambda x: x[1], reverse=True)
        
        return results
    
    def search_by_tactic(self, tactic: str) -> List[Technique]:
        """Search techniques by tactic name."""
        tactic_lower = tactic.lower().replace("-", " ")
        results = []
        
        for technique in self.bundle.techniques:
            for phase in technique.kill_chain_phases:
                if tactic_lower in phase.phase_name.lower().replace("-", " "):
                    results.append(technique)
                    break
        
        return results
    
    def search_by_platform(self, platform: str) -> List[Technique]:
        """Search techniques by platform."""
        platform_lower = platform.lower()
        results = []
        
        for technique in self.bundle.techniques:
            for tech_platform in technique.platforms:
                if platform_lower in tech_platform.lower():
                    results.append(technique)
                    break
        
        return results


def render_search_results(
    results: List[Tuple[Technique, int]], 
    format: str = "table",
    limit: Optional[int] = None
) -> None:
    """Render search results in the specified format."""
    if limit:
        results = results[:limit]
    
    if not results:
        console.print("[yellow]No techniques found matching your query.[/yellow]")
        return
    
    if format == "table":
        _render_table(results)
    elif format == "json":
        _render_json(results)
    elif format == "yaml":
        _render_yaml(results)
    else:
        console.print(f"[red]Unknown format: {format}[/red]")


def _render_table(results: List[Tuple[Technique, int]]) -> None:
    """Render results as a Rich table."""
    table = Table(title="ATT&CK Technique Search Results")
    
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Tactics", style="blue")
    table.add_column("Platforms", style="magenta")
    table.add_column("Score", style="yellow", justify="right")
    
    for technique, score in results:
        # Extract tactics from kill chain phases
        tactics = [phase.phase_name.replace("-", " ").title() 
                  for phase in technique.kill_chain_phases]
        tactics_str = ", ".join(tactics[:2])  # Limit to first 2 tactics
        if len(tactics) > 2:
            tactics_str += f" (+{len(tactics)-2} more)"
        
        # Format platforms
        platforms_str = ", ".join(technique.platforms[:3])  # Limit to first 3
        if len(technique.platforms) > 3:
            platforms_str += f" (+{len(technique.platforms)-3} more)"
        
        # Create score text with color coding
        if score >= 80:
            score_text = Text(str(score), style="bright_green")
        elif score >= 60:
            score_text = Text(str(score), style="yellow")
        else:
            score_text = Text(str(score), style="red")
        
        # Create clickable technique ID with URL
        technique_url = get_mitre_attack_url(technique.mitre_id)
        clickable_id = f"[link={technique_url}]{technique.mitre_id}[/link]"
        
        table.add_row(
            clickable_id,
            technique.name[:50] + ("..." if len(technique.name) > 50 else ""),
            tactics_str,
            platforms_str,
            score_text
        )
    
    console.print(table)


def _render_json(results: List[Tuple[Technique, int]]) -> None:
    """Render results as JSON."""
    import json
    
    output = []
    for technique, score in results:
        output.append({
            "id": technique.mitre_id,
            "name": technique.name,
            "description": technique.description[:200] + "..." if len(technique.description) > 200 else technique.description,
            "tactics": [phase.phase_name for phase in technique.kill_chain_phases],
            "platforms": technique.platforms,
            "score": score
        })
    
    console.print(json.dumps(output, indent=2))


def _render_yaml(results: List[Tuple[Technique, int]]) -> None:
    """Render results as YAML."""
    import yaml
    
    output = []
    for technique, score in results:
        output.append({
            "id": technique.mitre_id,
            "name": technique.name,
            "description": technique.description[:200] + "..." if len(technique.description) > 200 else technique.description,
            "tactics": [phase.phase_name for phase in technique.kill_chain_phases],
            "platforms": technique.platforms,
            "score": score
        })
    
    console.print(yaml.dump(output, default_flow_style=False))