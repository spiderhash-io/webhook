# Release Checklist

Quick reference for creating new releases.

## Pre-Release Checklist

- [ ] All tests passing locally (`make test-all`)
- [ ] Code formatted (`make format`)
- [ ] Linting clean (`make lint`)
- [ ] Type checking clean (`make type-check`)
- [ ] Security scans clean (`make security-scan`)
- [ ] Documentation updated
- [ ] CHANGELOG.md updated with new version

## Release Process

### 1. Update Version

```bash
# Update version in src/__version__.py
echo '__version__ = "0.2.0"' | sed 's/0.2.0/YOUR_VERSION/' > src/__version__.py

# Or manually edit:
vim src/__version__.py
```

### 2. Update CHANGELOG.md

Add new section:
```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- New feature A
- New feature B

### Changed
- Updated X
- Improved Y

### Fixed
- Bug fix A
- Bug fix B
```

### 3. Commit Changes

```bash
git add src/__version__.py CHANGELOG.md
git commit -m "chore: bump version to 0.2.0"
```

### 4. Push to Both Remotes

```bash
# Push to GitLab (origin)
git push origin main

# Push to GitHub
git push github main
```

### 5. Create and Push Tag

```bash
# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0

New Features:
- Feature A
- Feature B

Bug Fixes:
- Fix X
- Fix Y
"

# Push to both remotes
git push origin v0.2.0
git push github v0.2.0
```

### 6. Create GitHub Release

```bash
# Using GitHub CLI
gh release create v0.2.0 \
  --title "Release v0.2.0" \
  --notes-file CHANGELOG.md

# Or manually at:
# https://github.com/spiderhash-io/webhook/releases/new?tag=v0.2.0
```

### 7. Verify

- [ ] GitHub Actions workflows completed successfully
- [ ] Docker images published to Docker Hub
- [ ] GitHub Release created
- [ ] Tag visible on both GitHub and GitLab

## Post-Release

- [ ] Announce on social media
- [ ] Update documentation if needed
- [ ] Close related issues/PRs
- [ ] Update project board

## Quick Commands

```bash
# Check current version
grep "__version__" src/__version__.py

# View recent tags
git tag -l -n5

# Check remote tags
git ls-remote --tags github
git ls-remote --tags origin

# Delete tag if needed (use carefully!)
git tag -d v0.2.0
git push origin :refs/tags/v0.2.0
git push github :refs/tags/v0.2.0
```

## Semantic Versioning Guide

- **MAJOR** (1.0.0 → 2.0.0): Breaking changes
- **MINOR** (0.1.0 → 0.2.0): New features, backward compatible
- **PATCH** (0.1.0 → 0.1.1): Bug fixes, backward compatible

## Version History

- **0.2.0** - 2026-02-13 - Vault, etcd, connector fixes, security hardening, K8s support
- **0.1.0** - 2025-01-20 - Initial public release

---

For detailed release workflow documentation, see [DOCKER_RELEASE_GUIDE.md](DOCKER_RELEASE_GUIDE.md)
