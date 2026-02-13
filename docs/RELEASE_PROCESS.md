# Release Process

Step-by-step guide for creating a new release of Core Webhook Module. Follow this document exactly for every release to ensure consistency.

## Overview

Releases publish to three targets:
1. **GitHub** — git tag + GitHub Release with release notes
2. **Docker Hub** — `spiderhash/webhook:{version}` and `spiderhash/webhook:latest`
3. **GHCR** — `ghcr.io/spiderhash-io/webhook:{version}` (automatic via GitHub Actions)

## Prerequisites

Before starting:
- [ ] Docker Hub secrets configured in GitHub (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`) — see `.github/DOCKER_BUILD_GUIDE.md`
- [ ] `gh` CLI authenticated (`gh auth status`)
- [ ] Docker running locally (for manual builds, optional if using GitHub Actions)
- [ ] Both git remotes set up: `origin` (GitLab) and `github` (GitHub)

## Step-by-Step Process

### Step 1: Verify Tests Pass

```bash
# Run full unit test suite
make test

# Optional: run all tests including integration
make test-all

# Optional: code quality checks
make format
make lint
make type-check
```

All tests must pass before proceeding. Note the test count for release notes.

### Step 2: Bump Version

Edit `src/__version__.py`:

```python
__version__ = "X.Y.Z"  # Update this line
```

Follow [Semantic Versioning](https://semver.org/):
- **MAJOR** (1.0.0 → 2.0.0): Breaking API changes
- **MINOR** (1.0.0 → 1.1.0): New features, backward compatible
- **PATCH** (1.0.0 → 1.0.1): Bug fixes only

### Step 3: Update CHANGELOG.md

Add a new section under `## [Unreleased]`:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature descriptions

### Changed
- Changes to existing functionality
- **Breaking Changes** (call these out explicitly)

### Fixed
- Bug fixes

### Security
- Security-related changes

### Documentation
- Documentation updates

### Testing
- Test count and coverage stats
```

Keep the `## [Unreleased]` section with planned items for the next release.

### Step 4: Update Release Documents

Update these files:

| File | What to Update |
|------|---------------|
| `.github/RELEASE_NOTES_v{X.Y.Z}.md` | **Create new** — detailed release notes (copy structure from previous version) |
| `.github/RELEASE_BODY.txt` | **Replace** — short summary used for GitHub Release body |
| `.github/RELEASE_CHECKLIST.md` | **Append** version to Version History section |

#### Release Notes Template

Copy `.github/RELEASE_NOTES_v1.1.0.md` and update:
- Title and description
- Highlights (3-6 bullet points)
- New features with details
- Breaking changes
- Bug fixes
- Installation instructions (update version numbers)
- Migration notes (from previous version)
- Test count
- Full changelog link

#### Release Body Template

Short version for GitHub Release page — keep under 50 lines. Include:
- One-line summary
- Highlights (bullet points)
- Docker install command
- Auth methods and output modules counts
- Migration notes
- Links

### Step 5: Update Project Documentation (if needed)

If the release changes any of these, update the corresponding docs:
- `CLAUDE.md` — architecture overview, module list, auth methods, command references
- `docs/DEVELOPMENT_STANDARDS.md` — new patterns, conventions, file locations
- `README.md` — version references, feature counts

### Step 6: Commit Release Changes

```bash
git add src/__version__.py CHANGELOG.md .github/RELEASE_NOTES_v{X.Y.Z}.md \
  .github/RELEASE_BODY.txt .github/RELEASE_CHECKLIST.md docs/RELEASE_PROCESS.md

git commit -m "chore: release v{X.Y.Z}

- Bump version to {X.Y.Z}
- Update CHANGELOG.md
- Add release notes
- Update release checklist"
```

### Step 7: Push to Remotes

```bash
# Push to GitLab (origin)
git push origin main

# Push to GitHub
git push github main
```

### Step 8: Create Annotated Git Tag

```bash
git tag -a v{X.Y.Z} -m "Release v{X.Y.Z}

{One-line summary of what this release brings}

Key changes:
- Feature A
- Feature B
- Fix C"
```

### Step 9: Push Tag to Remotes

```bash
git push origin v{X.Y.Z}
git push github v{X.Y.Z}
```

> Pushing the tag to GitHub triggers `.github/workflows/docker-release.yml` which automatically builds and pushes multi-arch Docker images.

### Step 10: Create GitHub Release

```bash
gh release create v{X.Y.Z} \
  --title "Release v{X.Y.Z}" \
  --notes-file .github/RELEASE_BODY.txt
```

Or create manually at: `https://github.com/spiderhash-io/webhook/releases/new?tag=v{X.Y.Z}`

### Step 11: Docker Image (Automated vs Manual)

#### Option A: Automated (Recommended)

The GitHub Release from Step 10 triggers `docker-release.yml` which:
1. Builds multi-arch image (`linux/amd64`, `linux/arm64`)
2. Pushes to Docker Hub as `spiderhash/webhook:{version}` and `spiderhash/webhook:latest`
3. Updates Docker Hub description with README

Wait 3-5 minutes for the workflow to complete, then verify:
```bash
# Check workflow status
gh run list --workflow=docker-release.yml --limit=1

# Pull and test the image
docker pull spiderhash/webhook:{X.Y.Z}
docker run -p 8000:8000 spiderhash/webhook:{X.Y.Z}
curl http://localhost:8000/health
```

#### Option B: Manual Build & Push

If GitHub Actions is unavailable or you need to push manually:

```bash
# Login to Docker Hub
docker login

# Build multi-arch and push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t spiderhash/webhook:{X.Y.Z} \
  -t spiderhash/webhook:latest \
  -f docker/Dockerfile.smaller \
  --push \
  .
```

For single-arch (faster, current platform only):
```bash
docker build -t spiderhash/webhook:{X.Y.Z} -f docker/Dockerfile.smaller .
docker tag spiderhash/webhook:{X.Y.Z} spiderhash/webhook:latest
docker push spiderhash/webhook:{X.Y.Z}
docker push spiderhash/webhook:latest
```

### Step 12: Verify Release

- [ ] GitHub Release visible: `https://github.com/spiderhash-io/webhook/releases/tag/v{X.Y.Z}`
- [ ] Docker Hub tag exists: `https://hub.docker.com/r/spiderhash/webhook/tags`
- [ ] Tag visible on GitHub: `git ls-remote --tags github | grep v{X.Y.Z}`
- [ ] Tag visible on GitLab: `git ls-remote --tags origin | grep v{X.Y.Z}`
- [ ] Docker image runs: `docker run -p 8000:8000 spiderhash/webhook:{X.Y.Z}` then `curl localhost:8000/health`
- [ ] GitHub Actions workflows passed: `gh run list --limit=5`

## File Reference

| File | Purpose |
|------|---------|
| `src/__version__.py` | Source of truth for version number |
| `CHANGELOG.md` | Full changelog (Keep a Changelog format) |
| `.github/RELEASE_NOTES_v{X.Y.Z}.md` | Detailed release notes for each version |
| `.github/RELEASE_BODY.txt` | Short release body for GitHub Release page |
| `.github/RELEASE_CHECKLIST.md` | Quick reference checklist |
| `.github/DOCKER_BUILD_GUIDE.md` | Docker Hub setup and troubleshooting |
| `.github/workflows/docker-release.yml` | Automated Docker build on tag/release |
| `.github/workflows/ghcr-build.yml` | Automated GHCR build |
| `docker/Dockerfile.smaller` | Production Dockerfile (used by CI/CD) |

## Naming Conventions

- **Git tags**: `v{MAJOR}.{MINOR}.{PATCH}` (e.g., `v1.1.0`)
- **Docker tags**: `{MAJOR}.{MINOR}.{PATCH}` (no `v` prefix, e.g., `1.1.0`)
- **Release notes file**: `.github/RELEASE_NOTES_v{MAJOR}.{MINOR}.{PATCH}.md`
- **Commit message**: `chore: release v{X.Y.Z}`

## Troubleshooting

### GitHub Actions Docker push fails
Check secrets at `https://github.com/spiderhash-io/webhook/settings/secrets/actions`:
- `DOCKERHUB_USERNAME` = `spiderhash`
- `DOCKERHUB_TOKEN` = valid Docker Hub access token

### Tag already exists
```bash
# Delete local and remote tag (use carefully!)
git tag -d v{X.Y.Z}
git push origin :refs/tags/v{X.Y.Z}
git push github :refs/tags/v{X.Y.Z}
```

### Multi-arch build fails locally
```bash
docker buildx create --name multiarch --use
docker buildx inspect --bootstrap
```

## Release History

| Version | Date | Highlights |
|---------|------|------------|
| v1.1.0 | 2026-02-13 | Vault, etcd, connector fixes, security hardening, K8s |
| v0.1.0 | 2025-01-20 | Initial public release |
