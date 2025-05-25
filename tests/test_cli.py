"""Tests for CLI functionality."""

import pytest
from typer.testing import CliRunner
from attackctl.cli import app

runner = CliRunner()


def test_version():
    """Test version command."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "attackctl version" in result.stdout


def test_help():
    """Test help command."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "MITRE ATT&CK" in result.stdout


def test_search_help():
    """Test search command help."""
    result = runner.invoke(app, ["search", "--help"])
    assert result.exit_code == 0
    assert "Search for ATT&CK techniques" in result.stdout


def test_show_help():
    """Test show command help."""
    result = runner.invoke(app, ["show", "--help"])
    assert result.exit_code == 0
    assert "Show detailed information" in result.stdout


def test_update_help():
    """Test update command help."""
    result = runner.invoke(app, ["update", "--help"])
    assert result.exit_code == 0
    assert "Update the local ATT&CK data cache" in result.stdout