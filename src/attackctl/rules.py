"""
Detection rule generation and mapping functionality.

This module provides comprehensive capabilities for generating Sigma detection rules
from ATT&CK techniques and analyzing detection coverage across rule repositories.

Key Components:
    - RuleTemplateManager: Manages built-in and custom rule templates
    - SigmaRuleGenerator: Generates Sigma rules from ATT&CK techniques  
    - CoverageAnalyzer: Analyzes detection coverage across technique repositories

The module supports:
    - Sigma rule generation for common ATT&CK techniques
    - Template-based rule creation with technique-specific patterns
    - Coverage analysis and gap identification
    - Multiple output formats (YAML, JSON, Markdown)
    - Extensible template system for new platforms and techniques
"""

import uuid
import yaml
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from attackctl.models import (
    Technique, SigmaRule, RuleTemplate, RuleStatus, RuleLevel, 
    LogSource, DetectionCoverage, AttackBundle
)


class RuleTemplateManager:
    """
    Manages detection rule templates for different platforms and log sources.
    
    The template manager maintains a library of rule templates that can be used
    to generate detection rules for specific ATT&CK techniques. Templates are
    organized by platform (sigma, splunk, etc.) and template type (process_creation,
    file_event, etc.).
    
    Templates use placeholder substitution to customize rules based on technique
    characteristics like process names, command patterns, file paths, etc.
    
    Attributes:
        templates: Dictionary structure organizing templates by platform and type
                  Format: {platform: {template_type: template_content}}
    """
    
    def __init__(self):
        """Initialize template manager with built-in templates."""
        self.templates = self._load_builtin_templates()
    
    def _load_builtin_templates(self) -> Dict[str, Dict[str, str]]:
        """
        Load built-in rule templates for common detection scenarios.
        
        Returns a comprehensive set of Sigma rule templates covering the most
        common ATT&CK techniques and log source categories. Each template includes
        placeholder variables that get substituted with technique-specific values.
        
        Template Categories:
            - process_creation: Detects malicious process execution
            - file_creation: Detects suspicious file operations  
            - registry_event: Detects registry modifications
            - network_connection: Detects suspicious network activity
            
        Placeholder Variables:
            - {technique_name}: ATT&CK technique name
            - {rule_id}: Unique UUID for the rule
            - {technique_description}: Technique description (truncated)
            - {mitre_url}: Link to MITRE ATT&CK page
            - {attack_tags}: ATT&CK framework tags
            - {process_names}: Process names to detect
            - {command_patterns}: Command line patterns
            - {file_patterns}: File path patterns
            - {registry_paths}: Registry key patterns
            - {severity}: Rule severity level
            
        Returns:
            Dictionary of templates organized by platform and type
        """
        return {
            "sigma": {
                "process_creation": """title: {technique_name}
id: {rule_id}
status: experimental
description: Detects {technique_description}
author: attackctl
date: {date}
references:
    - {mitre_url}
tags:
{attack_tags}
logsource:
    product: {product}
    category: process_creation
detection:
    selection:
        Image|endswith:
{process_names}
        CommandLine|contains:
{command_patterns}
    condition: selection
falsepositives:
    - Legitimate administrative activities
    - Software installations
level: {severity}""",
                
                "file_creation": """title: {technique_name}
id: {rule_id}
status: experimental
description: Detects {technique_description}
author: attackctl
date: {date}
references:
    - {mitre_url}
tags:
    - {attack_tags}
logsource:
    product: {product}
    category: file_event
detection:
    selection:
        TargetFilename|contains: '{file_patterns}'
        ProcessImage|endswith: '{process_names}'
    condition: selection
falsepositives:
    - Legitimate file operations
level: {severity}""",

                "registry_event": """title: {technique_name}
id: {rule_id}
status: experimental
description: Detects {technique_description}
author: attackctl
date: {date}
references:
    - {mitre_url}
tags:
    - {attack_tags}
logsource:
    product: {product}
    category: registry_event
detection:
    selection:
        TargetObject|contains: '{registry_paths}'
        Details|contains: '{registry_values}'
    condition: selection
falsepositives:
    - Legitimate registry modifications
level: {severity}""",

                "network_connection": """title: {technique_name}
id: {rule_id}
status: experimental
description: Detects {technique_description}
author: attackctl
date: {date}
references:
    - {mitre_url}
tags:
    - {attack_tags}
logsource:
    product: {product}
    category: network_connection
detection:
    selection:
        DestinationHostname|contains: '{domains}'
        DestinationPort: {ports}
        ProcessImage|endswith: '{process_names}'
    condition: selection
falsepositives:
    - Legitimate network connections
level: {severity}"""
            }
        }


class SigmaRuleGenerator:
    """
    Generates Sigma detection rules for ATT&CK techniques.
    
    The generator uses a combination of rule templates and technique-specific
    mappings to create customized Sigma rules. Each technique mapping defines
    the detection patterns, platforms, and severity levels appropriate for
    that specific technique.
    
    The generation process:
    1. Look up technique in mappings to get detection patterns
    2. Select appropriate template based on technique characteristics  
    3. Substitute template variables with technique-specific values
    4. Parse and validate the generated YAML content
    5. Return structured SigmaRule object
    
    Attributes:
        template_manager: Manages rule templates for different log sources
        technique_mappings: Maps technique IDs to detection patterns and metadata
    """
    
    def __init__(self):
        """Initialize generator with template manager and technique mappings."""
        self.template_manager = RuleTemplateManager()
        self.technique_mappings = self._load_technique_mappings()
    
    def _load_technique_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Load technique-specific detection patterns and metadata.
        
        Each mapping defines how to detect a specific ATT&CK technique, including:
        - Template type to use (process_creation, file_event, etc.)
        - Target platform (windows, linux, etc.)
        - Process names commonly associated with the technique
        - Command line patterns that indicate technique usage
        - Severity level based on technique impact
        - Relevant data sources for detection
        
        The mappings are curated based on:
        - Real-world attack observations
        - Common tool usage patterns
        - MITRE ATT&CK technique documentation
        - Community detection rules and research
        
        Returns:
            Dictionary mapping technique IDs to detection configuration
            
        Example mapping structure:
            "T1003": {
                "template_type": "process_creation",
                "product": "windows", 
                "process_names": ["lsass.exe", "mimikatz.exe"],
                "command_patterns": ["lsass", "sekurlsa"],
                "severity": "high",
                "data_sources": ["Process: Process Creation"]
            }
        """
        return {
            "T1003": {  # OS Credential Dumping
                "template_type": "process_creation",
                "product": "windows",
                "process_names": ["lsass.exe", "mimikatz.exe", "procdump.exe", "taskmgr.exe"],
                "command_patterns": ["lsass", "mimikatz", "sekurlsa", "procdump", "comsvcs.dll"],
                "severity": "high",
                "data_sources": ["Process: Process Creation", "Process: Process Access"]
            },
            "T1003.001": {  # LSASS Memory
                "template_type": "process_creation",
                "product": "windows", 
                "process_names": ["procdump.exe", "rundll32.exe", "taskmgr.exe"],
                "command_patterns": ["lsass", "comsvcs.dll", "MiniDump"],
                "severity": "high",
                "data_sources": ["Process: Process Creation", "Process: Process Access"]
            },
            "T1059": {  # Command and Scripting Interpreter
                "template_type": "process_creation",
                "product": "windows",
                "process_names": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"],
                "command_patterns": ["encoded", "bypass", "hidden", "download"],
                "severity": "medium",
                "data_sources": ["Process: Process Creation", "Command: Command Execution"]
            },
            "T1059.003": {  # Windows Command Shell
                "template_type": "process_creation", 
                "product": "windows",
                "process_names": ["cmd.exe"],
                "command_patterns": ["bypass", "encoded", "/c", "/k", "download"],
                "severity": "medium",
                "data_sources": ["Process: Process Creation", "Command: Command Execution"]
            },
            "T1055": {  # Process Injection
                "template_type": "process_creation",
                "product": "windows",
                "process_names": ["svchost.exe", "explorer.exe", "winlogon.exe"],
                "command_patterns": ["inject", "hollow", "dll"],
                "severity": "high",
                "data_sources": ["Process: Process Creation", "Process: Process Access"]
            },
            "T1053": {  # Scheduled Task/Job
                "template_type": "process_creation",
                "product": "windows",
                "process_names": ["schtasks.exe", "at.exe", "taskeng.exe"],
                "command_patterns": ["create", "/sc", "/tr", "/tn"],
                "severity": "medium", 
                "data_sources": ["Process: Process Creation", "Scheduled Job: Scheduled Job Creation"]
            }
        }
    
    def generate_sigma_rule(self, technique: Technique) -> Optional[SigmaRule]:
        """
        Generate a Sigma detection rule for the given ATT&CK technique.
        
        Creates a customized Sigma rule by combining technique metadata with
        predefined detection patterns and templates. The process includes:
        
        1. Validate technique has a mapping with detection patterns
        2. Select appropriate template based on technique characteristics
        3. Extract ATT&CK tactics and generate framework tags
        4. Build MITRE ATT&CK reference URL
        5. Substitute template variables with technique-specific values
        6. Parse generated YAML and create structured rule object
        
        Args:
            technique: ATT&CK technique object to generate rule for
            
        Returns:
            SigmaRule object if generation successful, None if technique
            not supported or generation fails
            
        Example:
            technique = bundle.get_technique_by_id("T1003")
            rule = generator.generate_sigma_rule(technique)
            if rule:
                yaml_content = generator.export_rule_yaml(rule)
        """
        technique_id = technique.mitre_id
        
        # Check if we have a mapping for this technique
        if technique_id not in self.technique_mappings:
            return None
        
        mapping = self.technique_mappings[technique_id]
        template_type = mapping.get("template_type", "process_creation")
        
        # Get the template
        if template_type not in self.template_manager.templates["sigma"]:
            return None
        
        template = self.template_manager.templates["sigma"][template_type]
        
        # Generate ATT&CK tags
        attack_tags = []
        for phase in technique.kill_chain_phases:
            tactic = phase.phase_name.replace("-", "_")
            attack_tags.append(f"attack.{tactic}")
        
        # Add technique tag
        technique_tag = technique_id.lower().replace("t", "attack.t")
        attack_tags.append(technique_tag)
        
        # Get MITRE URL
        mitre_url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        
        # Prepare template variables
        template_vars = {
            "technique_name": technique.name,
            "rule_id": str(uuid.uuid4()),
            "technique_description": technique.description[:200] + "..." if len(technique.description) > 200 else technique.description,
            "date": datetime.now().strftime("%Y/%m/%d"),
            "mitre_url": mitre_url,
            "attack_tags": "\n".join([f"    - {tag}" for tag in attack_tags]),
            "product": mapping.get("product", "windows"),
            "process_names": "\n".join([f"            - '{name}'" for name in mapping.get("process_names", [])]),
            "command_patterns": "\n".join([f"            - '{pattern}'" for pattern in mapping.get("command_patterns", [])]),
            "file_patterns": "\n".join([f"            - '{pattern}'" for pattern in mapping.get("file_patterns", [])]),
            "registry_paths": "\n".join([f"            - '{path}'" for path in mapping.get("registry_paths", [])]),
            "registry_values": "\n".join([f"            - '{value}'" for value in mapping.get("registry_values", [])]),
            "domains": "\n".join([f"            - '{domain}'" for domain in mapping.get("domains", [])]),
            "ports": mapping.get("ports", []),
            "severity": mapping.get("severity", "medium")
        }
        
        # Generate rule content
        rule_content = template.format(**template_vars)
        
        # Parse the generated YAML to create SigmaRule object
        try:
            rule_data = yaml.safe_load(rule_content)
            
            sigma_rule = SigmaRule(
                title=rule_data["title"],
                id=rule_data["id"],
                status=RuleStatus(rule_data["status"]),
                description=rule_data["description"],
                author=rule_data.get("author"),
                date=rule_data.get("date"),
                references=rule_data.get("references", []),
                tags=rule_data.get("tags", []),
                logsource=LogSource(**rule_data["logsource"]),
                detection=rule_data.get("detection", {}),
                condition=rule_data["detection"].get("condition", ""),
                falsepositives=rule_data.get("falsepositives", []),
                level=RuleLevel(rule_data.get("level", "medium"))
            )
            
            return sigma_rule
            
        except Exception as e:
            print(f"Error parsing generated rule: {e}")
            return None
    
    def export_rule_yaml(self, rule: SigmaRule) -> str:
        """Export Sigma rule as YAML string."""
        rule_dict = {
            "title": rule.title,
            "id": rule.id,
            "status": rule.status.value,
            "description": rule.description,
            "author": rule.author,
            "date": rule.date,
            "references": rule.references,
            "tags": rule.tags,
            "logsource": {
                k: v for k, v in rule.logsource.model_dump().items() if v is not None
            },
            "detection": rule.detection,
            "falsepositives": rule.falsepositives,
            "level": rule.level.value
        }
        
        # Remove None values
        rule_dict = {k: v for k, v in rule_dict.items() if v is not None}
        
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)


class CoverageAnalyzer:
    """
    Analyzes detection coverage for ATT&CK techniques across rule repositories.
    
    The analyzer examines existing Sigma rules in a directory structure to
    determine which ATT&CK techniques have detection coverage. It parses
    rule files, extracts ATT&CK tags, and generates comprehensive coverage
    reports showing gaps and statistics.
    
    Analysis includes:
    - Technique-level coverage assessment
    - Tactic-level coverage statistics  
    - Platform and data source coverage mapping
    - Coverage scoring based on completeness
    - Gap identification for uncovered techniques
    
    Attributes:
        bundle: ATT&CK data bundle containing all techniques for analysis
    """
    
    def __init__(self, bundle: AttackBundle):
        """
        Initialize coverage analyzer with ATT&CK data bundle.
        
        Args:
            bundle: AttackBundle containing techniques, tactics, and metadata
        """
        self.bundle = bundle
    
    def analyze_directory(self, rules_path: Path) -> List[DetectionCoverage]:
        """
        Analyze detection coverage for all techniques against rules in directory.
        
        Recursively scans the provided directory for YAML files containing
        Sigma rules, extracts ATT&CK technique mappings, and generates
        coverage assessments for all techniques in the ATT&CK framework.
        
        Args:
            rules_path: Path to directory containing Sigma rule files (.yml/.yaml)
            
        Returns:
            List of DetectionCoverage objects, one per technique in ATT&CK
            
        Process:
            1. Iterate through all ATT&CK techniques
            2. Search rule files for techniques with matching tags
            3. Count rules and extract platform/data source coverage
            4. Calculate coverage scores based on completeness
            5. Return comprehensive coverage assessment
        """
        coverage_results = []
        
        # Get all techniques
        for technique in self.bundle.techniques:
            coverage = DetectionCoverage(
                technique_id=technique.mitre_id,
                technique_name=technique.name
            )
            
            # Find rules that map to this technique
            rule_files = self._find_rules_for_technique(rules_path, technique.mitre_id)
            
            if rule_files:
                coverage.has_detection = True
                coverage.rule_count = len(rule_files)
                coverage.rule_files = rule_files
                coverage.calculate_coverage_score(technique)
            
            coverage_results.append(coverage)
        
        return coverage_results
    
    def _find_rules_for_technique(self, rules_path: Path, technique_id: str) -> List[str]:
        """Find Sigma rules that map to a specific technique."""
        rule_files = []
        
        if not rules_path.exists():
            return rule_files
        
        # Search for YAML files
        for rule_file in rules_path.rglob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                
                # Check if rule maps to this technique
                tags = rule_data.get("tags", [])
                technique_tag = technique_id.lower().replace("t", "attack.t")
                
                if technique_tag in tags:
                    rule_files.append(str(rule_file))
                    
            except Exception:
                continue  # Skip invalid YAML files
        
        return rule_files
    
    def generate_coverage_report(self, coverage_results: List[DetectionCoverage]) -> Dict[str, Any]:
        """Generate a coverage report with statistics."""
        total_techniques = len(coverage_results)
        covered_techniques = sum(1 for c in coverage_results if c.has_detection)
        
        # Calculate coverage by tactic
        tactic_coverage = {}
        for technique in self.bundle.techniques:
            for phase in technique.kill_chain_phases:
                tactic = phase.phase_name
                if tactic not in tactic_coverage:
                    tactic_coverage[tactic] = {"total": 0, "covered": 0}
                
                tactic_coverage[tactic]["total"] += 1
                
                # Find coverage for this technique
                coverage = next((c for c in coverage_results if c.technique_id == technique.mitre_id), None)
                if coverage and coverage.has_detection:
                    tactic_coverage[tactic]["covered"] += 1
        
        # Calculate percentages
        for tactic in tactic_coverage:
            total = tactic_coverage[tactic]["total"]
            covered = tactic_coverage[tactic]["covered"]
            tactic_coverage[tactic]["percentage"] = (covered / total * 100) if total > 0 else 0
        
        return {
            "summary": {
                "total_techniques": total_techniques,
                "covered_techniques": covered_techniques,
                "coverage_percentage": (covered_techniques / total_techniques * 100) if total_techniques > 0 else 0,
                "uncovered_techniques": total_techniques - covered_techniques
            },
            "tactic_breakdown": tactic_coverage,
            "technique_details": [c.model_dump() for c in coverage_results]
        }