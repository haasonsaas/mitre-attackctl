# mitre-attackctl

A fast, batteries-included CLI companion for MITRE ATT&CK® TTPs with detection rule generation and coverage analysis.

## ✨ Features

- **🔍 Instant, offline TTP lookup** - Search techniques using fuzzy matching
- **📋 Rich technique details** - View comprehensive information in YAML, JSON, or Markdown
- **🔗 Clickable links** - Technique IDs link directly to MITRE ATT&CK website
- **🔄 Stay current** - Easy updates to latest ATT&CK framework data
- **💾 Smart caching** - Local storage for offline access and performance
- **🎨 Beautiful output** - Rich terminal UI with tables, colors, and formatting
- **🛡️ Detection rule generation** - Generate Sigma rules for ATT&CK techniques
- **📊 Coverage analysis** - Analyze detection coverage gaps in rule repositories

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (recommended)
pip install mitre-attackctl

# Or install with pipx for isolated installation
pipx install mitre-attackctl

# Or install from source
git clone https://github.com/haasonsaas/mitre-attackctl
cd mitre-attackctl
pip install -e .
```

### Basic Usage

```bash
# Search for techniques
attackctl search "gcp persistence"
attackctl search "powershell"
attackctl search "T1059"

# Show technique details
attackctl show T1098.004
attackctl show T1059.003 --format markdown

# Update local data cache
attackctl update

# Generate Sigma detection rules
attackctl map T1003 --to sigma
attackctl map T1059.003 --to sigma --output powershell_rule.yml

# Analyze detection coverage
attackctl coverage ./sigma-rules --format table

# Get help
attackctl --help
attackctl search --help
```

> 💡 **Tip**: Technique IDs in all output formats are clickable links that open the corresponding MITRE ATT&CK page in your browser (requires a terminal that supports clickable links).

## 📖 Commands

### `search` - Find techniques

Search for ATT&CK techniques using fuzzy string matching:

```bash
# Basic search
attackctl search "credential access"

# Limit results
attackctl search "persistence" --limit 5

# JSON output
attackctl search "powershell" --format json

# Update cache before searching
attackctl search "docker" --update
```

### `show` - Technique details

Display comprehensive information about a specific technique:

```bash
# Default YAML format
attackctl show T1098.004

# Markdown format
attackctl show T1059.003 --format markdown

# JSON format  
attackctl show T1055 --format json
```

### `update` - Refresh data

Update the local ATT&CK framework data cache:

```bash
# Update if cache is stale
attackctl update

# Force update regardless of cache age
attackctl update --force
```

### `map` - Generate detection rules

Generate Sigma detection rules for specific ATT&CK techniques:

```bash
# Generate Sigma rule for credential dumping
attackctl map T1003 --to sigma

# Save rule to file
attackctl map T1059.003 --to sigma --output powershell_detection.yml

# View supported techniques
attackctl map --help
```

**Supported Techniques:**
- `T1003`: OS Credential Dumping
- `T1003.001`: LSASS Memory
- `T1059`: Command and Scripting Interpreter  
- `T1059.003`: Windows Command Shell
- `T1055`: Process Injection
- `T1053`: Scheduled Task/Job

### `coverage` - Analyze detection coverage

Analyze existing Sigma rule repositories to identify coverage gaps:

```bash
# Analyze detection coverage
attackctl coverage ./sigma-rules --format table

# JSON output for integration
attackctl coverage /path/to/rules --format json

# Identify coverage gaps
attackctl coverage ./detections --format markdown
```

## 🏗️ Architecture

### Tech Stack
- **Language**: Python 3.9-3.13 with Typer for CLI
- **Search**: RapidFuzz for fuzzy string matching
- **Data**: MITRE ATT&CK STIX bundles via JSON API
- **Output**: Rich for beautiful terminal formatting
- **Caching**: Local JSON cache in `~/.attackctl/cache/`
- **Detection Rules**: Sigma rule generation and coverage analysis

### Core Architecture
1. **Data Layer** (`data.py`): Fetches MITRE ATT&CK STIX data, smart caching with 7-day expiry
2. **Models** (`models.py`): Pydantic models for type-safe data structures
3. **Search** (`search.py`): RapidFuzz-powered fuzzy search with intelligent score boosting
4. **Rules** (`rules.py`): Sigma rule generation and detection coverage analysis
5. **Display** (`display.py`): Rich terminal formatting with clickable technique IDs
6. **CLI** (`cli.py`): Typer-based command interface

### Data Sources
- MITRE ATT&CK Enterprise Matrix
- Cached locally for offline access
- Auto-updates with version tracking
- Smart cache invalidation

## 🛣️ Roadmap

### Recently Added ✅
- **🛡️ Sigma rule generation** - Generate detection rules for supported techniques
- **📊 Coverage analysis** - Analyze rule repositories for coverage gaps
- **🎯 Rule templates** - Built-in templates for multiple log source categories

### Coming Soon
- **🗺️ Additional detection platforms** - Splunk, Sentinel, Elastic rule generation
- **🧪 Test data generation** - Synthetic logs for rule validation
- **📤 Report export** - Generate comprehensive coverage reports
- **🔀 Version comparison** - Diff between ATT&CK versions
- **🔍 Enhanced filtering** - Sub-technique, tactic, and platform filtering
- **🎯 Custom mappings** - User-defined rule templates and mappings

## 🤝 Contributing

Contributions welcome! This project aims to solve real pain points in threat hunting and detection engineering.

### Development Setup

```bash
git clone https://github.com/haasonsaas/mitre-attackctl
cd mitre-attackctl
pip install -e ".[dev]"
pytest
```

### Project Structure
```
mitre-attackctl/
├── src/attackctl/
│   ├── cli.py          # Main CLI interface
│   ├── data.py         # ATT&CK data fetching/caching  
│   ├── models.py       # Pydantic data models
│   ├── search.py       # Fuzzy search implementation
│   ├── rules.py        # Sigma rule generation & coverage analysis
│   └── display.py      # Output formatting
├── tests/              # Test suite
└── docs/               # Documentation
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org/) framework and team
- [Typer](https://typer.tiangolo.com/) for the excellent CLI framework
- [Rich](https://rich.readthedocs.io/) for beautiful terminal output

---

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.