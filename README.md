# mitre-attackctl

A fast, batteries-included CLI companion for MITRE ATT&CK® TTPs.

## ✨ Features

- **🔍 Instant, offline TTP lookup** - Search techniques using fuzzy matching
- **📋 Rich technique details** - View comprehensive information in YAML, JSON, or Markdown
- **🔗 Clickable links** - Technique IDs link directly to MITRE ATT&CK website
- **🔄 Stay current** - Easy updates to latest ATT&CK framework data
- **💾 Smart caching** - Local storage for offline access and performance
- **🎨 Beautiful output** - Rich terminal UI with tables, colors, and formatting

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

## 🏗️ Architecture

### Tech Stack
- **Language**: Python 3.12+ with Typer for CLI
- **Search**: RapidFuzz for fuzzy string matching
- **Data**: MITRE ATT&CK STIX bundles via JSON API
- **Output**: Rich for beautiful terminal formatting
- **Caching**: Local JSON cache in `~/.attackctl/cache/`

### Data Sources
- MITRE ATT&CK Enterprise Matrix
- Cached locally for offline access
- Auto-updates with version tracking

## 🛣️ Roadmap

### Planned Features
- **🗺️ Detection mapping** - Map techniques to Sigma, Splunk, Sentinel rules
- **📊 Coverage analysis** - Gap analysis for detection rules
- **🧪 Test data generation** - Synthetic logs for rule validation
- **📤 Report export** - Generate reports in multiple formats
- **🔀 Version comparison** - Diff between ATT&CK versions
- **🔍 Semantic search** - AI-powered technique discovery

### Coming Soon
- Sub-technique filtering
- Tactic and platform filtering  
- Custom rule mappings
- Integration with detection platforms

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