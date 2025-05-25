# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-05-24

### Added
- Initial release of mitre-attackctl CLI tool
- **Search functionality**: Fast fuzzy search across 800+ MITRE ATT&CK techniques
  - `attackctl search "powershell"` - Find techniques by name, description, or ID
  - Support for multiple output formats: table (default), JSON, YAML
  - Configurable result limits with `--limit` option
  - Smart relevance scoring with exact ID and name match boosting
- **Technique details**: Comprehensive technique information display
  - `attackctl show T1059.001` - Show detailed technique information
  - Multiple output formats: YAML (default), JSON, Markdown
  - Rich formatting with panels, colors, and structured data
  - Complete metadata: platforms, tactics, data sources, references, timestamps
- **Data management**: Smart caching and updates
  - `attackctl update` - Fetch latest MITRE ATT&CK data
  - Local JSON cache in `~/.attackctl/cache/` for offline access
  - Automatic freshness checking (7-day default)
  - Version tracking and update notifications
- **Rich terminal UI**: Beautiful command-line interface
  - Colored tables with Rich formatting
  - Progress indicators for data fetching
  - Intuitive help system and error messages
  - Cross-platform compatibility

### Technical Features
- **Fast search**: RapidFuzz-powered fuzzy matching with sub-second response times
- **Type safety**: Full Pydantic models with comprehensive validation
- **Modular architecture**: Clean separation of concerns for extensibility
- **Comprehensive testing**: Pytest test suite covering CLI functionality
- **Modern Python**: Support for Python 3.9+ with type hints throughout

### Data Sources
- MITRE ATT&CK Enterprise Matrix v17.1 (April 2025)
- 823 techniques and sub-techniques
- 14 tactics, 181 threat groups, 758 software entries
- 268 mitigations and 38 data sources

[0.1.0]: https://github.com/haasonsaas/mitre-attackctl/releases/tag/v0.1.0