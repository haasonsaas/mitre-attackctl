# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

**Setup:**
```bash
pip install -e ".[dev]"  # Install in development mode with dev dependencies
```

**Testing:**
```bash
pytest                   # Run test suite
pytest tests/test_cli.py # Run specific test file
pytest -v               # Verbose output
```

**Code Quality:**
```bash
black .                  # Format code (88 char line length)
ruff .                   # Lint code
mypy src/               # Type checking
```

**Build and Package:**
```bash
python -m build                    # Build distribution packages
python -m twine check dist/*       # Validate packages
python -m twine upload dist/*      # Upload to PyPI
```

**CLI Usage:**
```bash
attackctl search "credential access" --limit 5
attackctl show T1003 --format yaml
attackctl update --force
attackctl map T1003 --to sigma                    # Generate Sigma rule for T1003
attackctl map T1003 --to sigma --output rule.yml  # Save Sigma rule to file
attackctl coverage ./sigma-rules --format table   # Analyze detection coverage
```

## Architecture Overview

**Core Data Flow:**
1. **Data Layer** (`data.py`): Fetches MITRE ATT&CK STIX data from GitHub, caches locally in `~/.attackctl/cache/`
2. **Models** (`models.py`): Pydantic models for type-safe data structures (Technique, Tactic, SigmaRule, etc.)
3. **Search** (`search.py`): RapidFuzz-powered fuzzy search with score boosting for exact matches
4. **Rules** (`rules.py`): Sigma rule generation and detection coverage analysis
5. **Display** (`display.py`): Rich terminal formatting with clickable technique IDs linking to MITRE website
6. **CLI** (`cli.py`): Typer-based command interface

**Key Design Patterns:**
- **Smart Caching**: 7-day cache expiry with metadata tracking
- **Fuzzy Search Index**: Combines technique names, IDs, descriptions, tactics, and platforms
- **Rich Terminal UI**: Tables, panels, progress bars, and clickable links
- **Multiple Output Formats**: YAML, JSON, Markdown for different use cases

**Entry Point:** `attackctl.cli:app` (configured in pyproject.toml)

## Important Implementation Details

**Search Scoring Logic:**
- Base fuzzy matching with RapidFuzz WRatio scorer
- +20 score boost for partial technique ID matches
- +15 score boost for exact technique name matches
- +10 score boost for partial technique name matches

**URL Generation for Clickable Links:**
- Techniques: `https://attack.mitre.org/techniques/{ID}/`
- Sub-techniques: `https://attack.mitre.org/techniques/{PARENT_ID}/{SUB_ID}/`

**Data Sources:**
- Primary: MITRE's GitHub STIX JSON endpoint
- Cache location: `~/.attackctl/cache/attack_data.json`
- Freshness check: 7 days (configurable in data.py)

**Package Configuration:**
- Package name: `mitre-attackctl` (for PyPI)
- Python support: 3.9-3.13
- CLI command: `attackctl`
- Version tracking in both `pyproject.toml` and `src/attackctl/__init__.py`

## Testing Notes

Current test coverage focuses on CLI command help and basic functionality. Tests use pytest and are located in `tests/` directory. The test suite is minimal but covers core CLI entry points.

## Sigma Rule Generation

**Supported Techniques:**
The `map` command currently supports Sigma rule generation for these techniques:
- `T1003`: OS Credential Dumping
- `T1003.001`: LSASS Memory
- `T1059`: Command and Scripting Interpreter  
- `T1059.003`: Windows Command Shell
- `T1055`: Process Injection
- `T1053`: Scheduled Task/Job

**Detection Coverage Analysis:**
The `coverage` command analyzes existing Sigma rule repositories to identify:
- Techniques with detection coverage
- Coverage gaps requiring new rules
- Coverage statistics by tactic
- Platform-specific coverage analysis

**Rule Templates:**
Built-in templates support multiple log source categories:
- `process_creation`: Process execution detection
- `file_creation`: File operation monitoring
- `registry_event`: Registry modification detection  
- `network_connection`: Network activity monitoring

## Planned Features (Currently Placeholders)

Several commands in `cli.py` are implemented as placeholders for future development:
- `diff`: Compare ATT&CK versions
- `testgen`: Generate synthetic test data
- `export`: Export data in various formats

**Future Detection Platforms:**
- Splunk detection rules
- Microsoft Sentinel analytics rules
- Elastic detection rules