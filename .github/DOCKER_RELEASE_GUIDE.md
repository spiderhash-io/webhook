# Docker Release Guide

This guide explains how Docker images are built and released for Core Webhook Module.

## Workflow Overview

We use **two separate workflows** following industry best practices:

### 1. **docker-build.yml** - Continuous Integration (CI)
- **Triggers**: Push to `main`/`develop`, Pull Requests
- **Purpose**: Build Docker images for testing
- **Push to Docker Hub**: No (except main branch for testing)
- **Platforms**: Single platform (linux/amd64) for speed

### 2. **docker-release.yml** - Release Publishing
- **Triggers**: Git tags (`v*.*.*`), GitHub Releases, Manual dispatch
- **Purpose**: Build and publish official releases
- **Push to Docker Hub**: Yes, with version tags
- **Platforms**: Multi-arch (linux/amd64, linux/arm64)

---

## How to Release a New Version

### Step 1: Update Version

```bash
# Update version in src/__version__.py
echo '__version__ = "0.2.0"' > src/__version__.py

# Update CHANGELOG.md
# Add new section for v0.2.0 with changes
```

### Step 2: Commit and Push

```bash
git add src/__version__.py CHANGELOG.md
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

### Step 3: Create Git Tag

```bash
# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0

New features:
- Feature A
- Feature B

Bug fixes:
- Fix X
- Fix Y
"

# Push tag to GitHub
git push origin v0.2.0
```

### Step 4: Automated Build

The `docker-release.yml` workflow will automatically:

1. ✅ Detect the new tag `v0.2.0`
2. ✅ Build multi-arch Docker images (amd64 + arm64)
3. ✅ Tag images as:
   - `spiderhash/webhook:0.2.0`
   - `spiderhash/webhook:0.2`
   - `spiderhash/webhook:0` (only if version >= 1.0.0)
4. ✅ Push to Docker Hub
5. ✅ Update Docker Hub description

### Step 5: Create GitHub Release (Optional but Recommended)

```bash
# Using GitHub CLI
gh release create v0.2.0 \
  --title "Release v0.2.0" \
  --notes "See CHANGELOG.md for details"

# Or create manually on GitHub:
# https://github.com/spiderhash-io/webhook/releases/new
```

When you create a GitHub Release, the workflow runs again with the `latest` tag.

---

## Docker Tag Strategy

### Version Tags (Semantic Versioning)

For tag `v0.2.3`, the following Docker tags are created:

| Docker Tag | Description | Example |
|------------|-------------|---------|
| `0.2.3` | Full version (recommended for production) | `spiderhash/webhook:0.2.3` |
| `0.2` | Minor version (auto-updates with patches) | `spiderhash/webhook:0.2` |
| `0` | Major version (only for v1.0.0+) | `spiderhash/webhook:0` |
| `latest` | Latest stable release (only on GitHub Release) | `spiderhash/webhook:latest` |

### When to Use Each Tag

- **Production**: Use specific version (e.g., `0.2.3`)
- **Development/Testing**: Use minor version (e.g., `0.2`) or `latest`
- **Avoid**: Using `main` or `develop` tags in production

---

## Manual Release (Emergency/Special Cases)

If you need to manually trigger a release:

### Using GitHub UI

1. Go to: https://github.com/spiderhash-io/webhook/actions/workflows/docker-release.yml
2. Click "Run workflow"
3. Enter tag (e.g., `v0.2.0`)
4. Click "Run workflow"

### Using GitHub CLI

```bash
gh workflow run docker-release.yml -f tag=v0.2.0
```

---

## Troubleshooting

### Issue: Workflow failed with "unauthorized"

**Solution**: Check Docker Hub secrets are configured:

```bash
# In GitHub repository settings > Secrets and variables > Actions
# Add:
DOCKERHUB_USERNAME=your_username
DOCKERHUB_TOKEN=your_access_token
```

### Issue: Multi-arch build failed

**Possible causes**:
1. QEMU setup failed (transient issue, retry)
2. Architecture-specific build issue (check Dockerfile)

**Solution**: Manually trigger workflow to retry

### Issue: Tag already exists on Docker Hub

**Solution**: 
1. Delete the tag on Docker Hub
2. Manually trigger the workflow
3. Or create a new patch version

### Issue: `latest` tag not updated

**Expected behavior**: `latest` tag only updates when creating a **GitHub Release**, not on git tags.

**Solution**: Create a GitHub Release to update `latest` tag.

---

## Comparison: CI vs Release Workflows

| Feature | docker-build.yml (CI) | docker-release.yml (Release) |
|---------|----------------------|------------------------------|
| **Trigger** | Push, PR | Git tags, Releases |
| **Platforms** | linux/amd64 | linux/amd64, linux/arm64 |
| **Push to Docker Hub** | No (PRs), Yes (main) | Yes |
| **Tags** | Branch names, PR numbers | Semantic versions, latest |
| **Purpose** | Testing | Production releases |
| **Speed** | Fast | Slower (multi-arch) |
| **Build time** | ~3-5 min | ~8-12 min |

---

## Best Practices

### 1. Version Tagging

- ✅ **DO**: Use semantic versioning (v0.1.0, v0.2.0, v1.0.0)
- ✅ **DO**: Create annotated tags with release notes
- ❌ **DON'T**: Use non-semantic tags (v1, alpha, beta as tags)
- ❌ **DON'T**: Delete and recreate tags

### 2. Release Process

- ✅ **DO**: Test on `main` branch before tagging
- ✅ **DO**: Update CHANGELOG.md before release
- ✅ **DO**: Create GitHub Releases for major/minor versions
- ❌ **DON'T**: Tag directly without testing
- ❌ **DON'T**: Skip version bumps in code

### 3. Docker Image Usage

- ✅ **DO**: Pin specific versions in production (e.g., `0.2.3`)
- ✅ **DO**: Use `latest` for quick testing only
- ❌ **DON'T**: Use `latest` in production
- ❌ **DON'T**: Use branch tags (`main`, `develop`) in production

---

## Examples

### Example 1: Patch Release (0.1.0 → 0.1.1)

```bash
# 1. Update version
sed -i 's/__version__ = "0.1.0"/__version__ = "0.1.1"/' src/__version__.py

# 2. Update CHANGELOG
echo "## [0.1.1] - $(date +%Y-%m-%d)" >> CHANGELOG.md
echo "### Fixed" >> CHANGELOG.md
echo "- Bug fix description" >> CHANGELOG.md

# 3. Commit and tag
git add src/__version__.py CHANGELOG.md
git commit -m "chore: release v0.1.1"
git push origin main

git tag -a v0.1.1 -m "Release v0.1.1 - Bug fixes"
git push origin v0.1.1
```

**Result**: Docker tags `0.1.1` and `0.1` created

### Example 2: Minor Release (0.1.x → 0.2.0)

```bash
# 1. Update version
sed -i 's/__version__ = "0.1.1"/__version__ = "0.2.0"/' src/__version__.py

# 2. Update CHANGELOG with new features
# ... (add features to CHANGELOG.md)

# 3. Commit and tag
git add src/__version__.py CHANGELOG.md
git commit -m "feat: release v0.2.0 with new features"
git push origin main

git tag -a v0.2.0 -m "Release v0.2.0

New Features:
- Feature A
- Feature B
"
git push origin v0.2.0

# 4. Create GitHub Release for 'latest' tag
gh release create v0.2.0 \
  --title "Release v0.2.0" \
  --notes-file CHANGELOG.md
```

**Result**: Docker tags `0.2.0`, `0.2`, and `latest` created

---

## Monitoring

### Check Build Status

- **GitHub Actions**: https://github.com/spiderhash-io/webhook/actions
- **Docker Hub**: https://hub.docker.com/r/spiderhash/webhook/tags

### View Published Tags

```bash
# List all Docker tags
curl -s https://hub.docker.com/v2/repositories/spiderhash/webhook/tags | jq -r '.results[].name'

# Or using Docker
docker search spiderhash/webhook --limit 100
```

---

## Questions?

- **Workflow Issues**: [GitHub Issues](https://github.com/spiderhash-io/webhook/issues)
- **Docker Hub**: https://hub.docker.com/r/spiderhash/webhook
- **Releases**: https://github.com/spiderhash-io/webhook/releases
