"""Data fetching and caching for MITRE ATT&CK framework."""

import json
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import stix2
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from attackctl.models import AttackBundle, Technique, Tactic, Group, Software, Mitigation, DataSource, ExternalReference, KillChainPhase

console = Console()

# MITRE ATT&CK TAXII server endpoints
ENTERPRISE_COLLECTION = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
TAXII_SERVER = "https://cti-taxii.mitre.org/taxii/"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class AttackDataManager:
    """Manages ATT&CK data fetching, caching, and access."""
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize the data manager."""
        self.cache_dir = cache_dir or Path.home() / ".attackctl" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "attack_data.json"
        self.metadata_file = self.cache_dir / "metadata.json"
        
    def _get_cache_metadata(self) -> Dict[str, Any]:
        """Get cache metadata."""
        if not self.metadata_file.exists():
            return {"last_updated": None, "version": None}
        
        try:
            with open(self.metadata_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"last_updated": None, "version": None}
    
    def _save_cache_metadata(self, version: str) -> None:
        """Save cache metadata."""
        metadata = {
            "last_updated": datetime.now().isoformat(),
            "version": version,
        }
        with open(self.metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)
    
    def is_cache_fresh(self, max_age_days: int = 7) -> bool:
        """Check if cache is fresh enough."""
        metadata = self._get_cache_metadata()
        if not metadata.get("last_updated") or not self.cache_file.exists():
            return False
        
        last_updated = datetime.fromisoformat(metadata["last_updated"])
        age = datetime.now() - last_updated
        return age < timedelta(days=max_age_days)
    
    def _fetch_attack_data(self) -> Dict[str, Any]:
        """Fetch ATT&CK data from MITRE's GitHub repository."""
        console.print("🌐 Fetching ATT&CK data from MITRE repository...")
        
        try:
            response = requests.get(STIX_URL, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            console.print(f"[red]Error fetching ATT&CK data: {e}[/red]")
            raise
    
    def _parse_external_references(self, refs: List[Dict[str, Any]]) -> List[ExternalReference]:
        """Parse external references from STIX data."""
        result = []
        for ref in refs:
            result.append(ExternalReference(
                source_name=ref.get("source_name", ""),
                url=ref.get("url"),
                external_id=ref.get("external_id"),
                description=ref.get("description")
            ))
        return result
    
    def _parse_kill_chain_phases(self, phases: List[Dict[str, Any]]) -> List[KillChainPhase]:
        """Parse kill chain phases from STIX data."""
        result = []
        for phase in phases:
            result.append(KillChainPhase(
                kill_chain_name=phase.get("kill_chain_name", ""),
                phase_name=phase.get("phase_name", "")
            ))
        return result
    
    def _parse_stix_bundle(self, stix_data: Dict[str, Any]) -> AttackBundle:
        """Parse STIX bundle into our data models."""
        objects = stix_data.get("objects", [])
        
        techniques = []
        tactics = []
        groups = []
        software = []
        mitigations = []
        data_sources = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Parsing ATT&CK data...", total=len(objects))
            
            for obj in objects:
                obj_type = obj.get("type")
                
                if obj_type == "attack-pattern":
                    # Determine if this is a sub-technique
                    is_subtechnique = "." in obj.get("x_mitre_shortname", "")
                    parent_technique = None
                    if is_subtechnique:
                        parent_technique = obj.get("x_mitre_shortname", "").split(".")[0]
                    
                    technique = Technique(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        technique_id=obj.get("x_mitre_shortname", ""),
                        platforms=obj.get("x_mitre_platforms", []),
                        data_sources=obj.get("x_mitre_data_sources", []),
                        kill_chain_phases=self._parse_kill_chain_phases(obj.get("kill_chain_phases", [])),
                        external_references=self._parse_external_references(obj.get("external_references", [])),
                        created=datetime.fromisoformat(obj["created"].replace("Z", "+00:00")) if obj.get("created") else None,
                        modified=datetime.fromisoformat(obj["modified"].replace("Z", "+00:00")) if obj.get("modified") else None,
                        version=obj.get("x_mitre_version"),
                        is_subtechnique=is_subtechnique,
                        parent_technique=parent_technique
                    )
                    techniques.append(technique)
                
                elif obj_type == "x-mitre-tactic":
                    tactic = Tactic(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        shortname=obj.get("x_mitre_shortname", ""),
                        external_references=self._parse_external_references(obj.get("external_references", []))
                    )
                    tactics.append(tactic)
                
                elif obj_type == "intrusion-set":
                    group = Group(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        aliases=obj.get("aliases", []),
                        external_references=self._parse_external_references(obj.get("external_references", []))
                    )
                    groups.append(group)
                
                elif obj_type in ["malware", "tool"]:
                    sw = Software(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        labels=obj.get("labels", []),
                        platforms=obj.get("x_mitre_platforms", []),
                        external_references=self._parse_external_references(obj.get("external_references", []))
                    )
                    software.append(sw)
                
                elif obj_type == "course-of-action":
                    mitigation = Mitigation(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        external_references=self._parse_external_references(obj.get("external_references", []))
                    )
                    mitigations.append(mitigation)
                
                elif obj_type == "x-mitre-data-source":
                    data_source = DataSource(
                        id=obj["id"],
                        name=obj["name"],
                        description=obj.get("description", ""),
                        data_components=obj.get("x_mitre_data_source_platform", []),
                        external_references=self._parse_external_references(obj.get("external_references", []))
                    )
                    data_sources.append(data_source)
                
                progress.advance(task)
        
        # Determine version from the bundle
        version = "unknown"
        for obj in objects:
            if obj.get("type") == "x-mitre-collection":
                version = obj.get("x_mitre_version", "unknown")
                break
        
        return AttackBundle(
            techniques=techniques,
            tactics=tactics,
            groups=groups,
            software=software,
            mitigations=mitigations,
            data_sources=data_sources,
            version=version,
            last_updated=datetime.now()
        )
    
    def update_cache(self, force: bool = False) -> AttackBundle:
        """Update the local cache with latest ATT&CK data."""
        if not force and self.is_cache_fresh():
            console.print("✅ Cache is fresh, loading from local storage")
            return self.load_from_cache()
        
        stix_data = self._fetch_attack_data()
        bundle = self._parse_stix_bundle(stix_data)
        
        # Save to cache
        console.print("💾 Saving to cache...")
        with open(self.cache_file, "w") as f:
            json.dump(bundle.model_dump(), f, default=str, indent=2)
        
        self._save_cache_metadata(bundle.version)
        console.print(f"✅ Successfully cached ATT&CK data (version: {bundle.version})")
        
        return bundle
    
    def load_from_cache(self) -> Optional[AttackBundle]:
        """Load ATT&CK data from cache."""
        if not self.cache_file.exists():
            return None
        
        try:
            with open(self.cache_file) as f:
                data = json.load(f)
            return AttackBundle.model_validate(data)
        except (json.JSONDecodeError, IOError, ValueError) as e:
            console.print(f"[red]Error loading cache: {e}[/red]")
            return None
    
    def get_data(self, force_update: bool = False) -> AttackBundle:
        """Get ATT&CK data, updating cache if necessary."""
        if force_update or not self.is_cache_fresh():
            return self.update_cache(force=force_update)
        
        cached_data = self.load_from_cache()
        if cached_data is None:
            return self.update_cache(force=True)
        
        return cached_data