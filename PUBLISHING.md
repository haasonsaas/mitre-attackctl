# Publishing Guide

This document outlines how to publish attackctl to PyPI.

## Prerequisites

1. **PyPI Account**: Create accounts on both [Test PyPI](https://test.pypi.org) and [PyPI](https://pypi.org)
2. **API Tokens**: Generate API tokens for both Test PyPI and PyPI for secure authentication
3. **Build Tools**: Install build dependencies:
   ```bash
   pip install build twine
   ```

## Publishing Process

### 1. Prepare Release

1. **Update Version**: Bump version in `pyproject.toml` and `src/attackctl/__init__.py`
2. **Update Changelog**: Add release notes to `CHANGELOG.md`
3. **Run Tests**: Ensure all tests pass
   ```bash
   pytest
   ```

### 2. Build Package

Clean and build the distribution packages:

```bash
# Clean previous builds
rm -rf dist/ build/ src/attackctl.egg-info/

# Build source distribution and wheel
python -m build
```

### 3. Validate Package

Check the built packages for common issues:

```bash
# Validate packages
twine check dist/*

# Test install locally
python -m venv test_env
source test_env/bin/activate
pip install dist/attackctl-*.whl
attackctl --version
deactivate
rm -rf test_env
```

### 4. Test on Test PyPI (Recommended)

First upload to Test PyPI to verify everything works:

```bash
# Upload to Test PyPI
twine upload --repository testpypi dist/*

# Test install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ attackctl
```

### 5. Upload to PyPI

Once verified on Test PyPI, upload to the real PyPI:

```bash
# Upload to PyPI
twine upload dist/*
```

### 6. Verify Release

1. Check the package page on PyPI: https://pypi.org/project/attackctl/
2. Test installation: `pip install attackctl`
3. Create a GitHub release with the same version tag

## Configuration

### Setting Up API Tokens

1. **PyPI Token**: Go to PyPI > Account Settings > API Tokens
2. **Test PyPI Token**: Go to Test PyPI > Account Settings > API Tokens

Store tokens in `~/.pypirc`:

```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-...

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-...
```

### Alternative: Using Environment Variables

```bash
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=pypi-...  # Your PyPI API token
twine upload dist/*
```

## Release Checklist

- [ ] Version bumped in pyproject.toml
- [ ] Version bumped in __init__.py
- [ ] CHANGELOG.md updated
- [ ] Tests passing
- [ ] Package builds cleanly
- [ ] Package validates with twine check
- [ ] Tested on Test PyPI
- [ ] Uploaded to PyPI
- [ ] GitHub release created
- [ ] Installation tested: `pip install attackctl`

## Troubleshooting

### Common Issues

1. **Version Already Exists**: PyPI doesn't allow re-uploading the same version
   - Solution: Bump the version number

2. **Missing Files**: Check MANIFEST.in includes all necessary files
   - Solution: Add missing files to MANIFEST.in

3. **Authentication Errors**: Check API tokens and ~/.pypirc configuration
   - Solution: Regenerate tokens and update configuration

4. **Metadata Issues**: Validate pyproject.toml configuration
   - Solution: Use `twine check` to identify and fix issues