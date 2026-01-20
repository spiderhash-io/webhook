# Docker Build and Push Guide

This guide shows how to build and push Docker images to Docker Hub, both manually and automatically.

---

## Option 1: Automated (Recommended) ✅

GitHub Actions automatically builds and pushes multi-architecture images when you create a release or push a tag.

### Prerequisites

**Add Docker Hub secrets to GitHub** (one-time setup):

1. **Create Docker Hub Access Token:**
   - Go to: https://hub.docker.com/settings/security
   - Click "New Access Token"
   - Description: `GitHub Actions - webhook`
   - Permissions: `Read & Write`
   - Click "Generate"
   - **Copy the token** (shown only once!)

2. **Add secrets to GitHub:**
   - Go to: https://github.com/spiderhash-io/webhook/settings/secrets/actions
   - Click "New repository secret"
   
   Add `DOCKERHUB_USERNAME`:
   - Name: `DOCKERHUB_USERNAME`
   - Secret: `spiderhash`
   - Click "Add secret"
   
   Add `DOCKERHUB_TOKEN`:
   - Name: `DOCKERHUB_TOKEN`
   - Secret: (paste the token from step 1)
   - Click "Add secret"

### Triggering Automated Builds

#### Method A: Push a Git Tag (Recommended)

```bash
# Create a new version tag
git tag -a v0.1.1 -m "Release v0.1.1"
git push github v0.1.1

# Or re-push existing tag (forces rebuild)
git push github v0.1.0 --force
```

**What happens:**
- Workflow `.github/workflows/docker-release.yml` triggers
- Builds for `linux/amd64` and `linux/arm64`
- Pushes to Docker Hub:
  - `spiderhash/webhook:0.1.0` (version tag)
  - `spiderhash/webhook:latest` (if it's a release)

#### Method B: Create GitHub Release

1. Go to: https://github.com/spiderhash-io/webhook/releases
2. Click "Draft a new release"
3. Choose tag `v0.1.0`
4. Fill in release notes
5. Click "Publish release"

**What happens:**
- Same as Method A, plus:
- Updates `latest` tag
- Updates Docker Hub description with README.md

#### Method C: Manual Workflow Dispatch

1. Go to: https://github.com/spiderhash-io/webhook/actions/workflows/docker-release.yml
2. Click "Run workflow"
3. Enter tag (e.g., `v0.1.0`)
4. Click "Run workflow"

### Verify Automated Build

After triggering:

1. **Check workflow:**
   - Go to: https://github.com/spiderhash-io/webhook/actions
   - Find "Docker Release" workflow
   - Wait for it to complete (3-5 minutes)

2. **Check Docker Hub:**
   - Go to: https://hub.docker.com/r/spiderhash/webhook/tags
   - You should see your new tag

3. **Test the image:**
   ```bash
   docker pull spiderhash/webhook:0.1.0
   docker run -p 8000:8000 spiderhash/webhook:0.1.0
   ```

---

## Option 2: Manual Build (Local)

Build and push from your local machine.

### Prerequisites

1. **Docker installed and running**
   ```bash
   docker --version
   ```

2. **Docker Hub account**
   - Create at: https://hub.docker.com/signup

3. **Docker Hub repository created**
   - Repository: `spiderhash/webhook`
   - Visibility: Public

### Step 1: Login to Docker Hub

```bash
docker login

# Enter your Docker Hub credentials:
# Username: spiderhash
# Password: (your Docker Hub password or access token)
```

### Step 2: Build the Image

Navigate to project root:
```bash
cd /Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module
```

#### Option A: Single Architecture (Fast)

Build for your current architecture only:

```bash
# Build for current platform (amd64 or arm64)
docker build -t spiderhash/webhook:0.1.0 -f docker/Dockerfile.smaller .

# Also tag as latest
docker tag spiderhash/webhook:0.1.0 spiderhash/webhook:latest
```

#### Option B: Multi-Architecture (Recommended)

Build for multiple platforms (requires buildx):

```bash
# Set up buildx (one-time)
docker buildx create --name mybuilder --use
docker buildx inspect --bootstrap

# Build and push for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t spiderhash/webhook:0.1.0 \
  -t spiderhash/webhook:latest \
  -f docker/Dockerfile.smaller \
  --push \
  .
```

### Step 3: Push to Docker Hub

If you used single architecture build:

```bash
# Push version tag
docker push spiderhash/webhook:0.1.0

# Push latest tag
docker push spiderhash/webhook:latest
```

If you used multi-architecture build with `--push`, images are already pushed!

### Step 4: Verify

Check Docker Hub:
```bash
# List your images
docker images | grep spiderhash/webhook

# Pull and test
docker pull spiderhash/webhook:0.1.0
docker run -p 8000:8000 spiderhash/webhook:0.1.0
```

Visit: https://hub.docker.com/r/spiderhash/webhook/tags

---

## Available Dockerfiles

The project has three Dockerfiles:

| File | Size | Use Case | Build Time |
|------|------|----------|------------|
| `docker/Dockerfile` | ~500MB | Development | Fast (1-2 min) |
| `docker/Dockerfile.small` | ~200MB | Production (optimized) | Medium (2-3 min) |
| `docker/Dockerfile.smaller` | ~150MB | Production (smallest) | Slow (3-5 min) |

**Recommended:** `docker/Dockerfile.smaller` (used by CI/CD)

---

## Quick Commands Reference

### Manual Build & Push (Single Platform)
```bash
cd /Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module

# Login
docker login

# Build
docker build -t spiderhash/webhook:0.1.0 -f docker/Dockerfile.smaller .
docker tag spiderhash/webhook:0.1.0 spiderhash/webhook:latest

# Push
docker push spiderhash/webhook:0.1.0
docker push spiderhash/webhook:latest
```

### Manual Build & Push (Multi-Platform)
```bash
cd /Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module

# Login
docker login

# Setup buildx (one-time)
docker buildx create --name mybuilder --use

# Build and push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t spiderhash/webhook:0.1.0 \
  -t spiderhash/webhook:latest \
  -f docker/Dockerfile.smaller \
  --push \
  .
```

### Automated (GitHub Actions)
```bash
# Just push a tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push github v0.1.0

# Done! GitHub Actions handles the rest
```

---

## Troubleshooting

### Error: "denied: requested access to the resource is denied"

**Cause:** Not logged in or wrong credentials

**Solution:**
```bash
docker logout
docker login
# Enter correct credentials
```

### Error: "repository does not exist"

**Cause:** Repository not created on Docker Hub

**Solution:**
1. Go to: https://hub.docker.com
2. Click "Create Repository"
3. Name: `webhook`
4. Visibility: Public
5. Click "Create"

### Error: "multiple platforms feature is currently not supported"

**Cause:** Need to use buildx for multi-platform

**Solution:**
```bash
docker buildx create --name mybuilder --use
docker buildx inspect --bootstrap
# Then try build again
```

### Error: GitHub Actions fails with "unauthorized"

**Cause:** Missing or wrong Docker Hub secrets

**Solution:**
1. Check secrets exist: https://github.com/spiderhash-io/webhook/settings/secrets/actions
2. Verify `DOCKERHUB_USERNAME` = `spiderhash`
3. Regenerate `DOCKERHUB_TOKEN` if needed

---

## Testing the Image

After pushing, test the image:

```bash
# Pull the image
docker pull spiderhash/webhook:0.1.0

# Run it
docker run -p 8000:8000 spiderhash/webhook:0.1.0

# Test the endpoint
curl http://localhost:8000/health

# Run with custom config
docker run -p 8000:8000 \
  -v $(pwd)/config:/app/config \
  spiderhash/webhook:0.1.0
```

---

## Best Practices

1. **Use automated builds** for releases (consistent, reproducible)
2. **Use multi-arch builds** (supports both Intel and ARM)
3. **Tag both version and latest** (e.g., `0.1.0` and `latest`)
4. **Test images before releasing** (pull and run locally)
5. **Keep Docker Hub description updated** (automated in CI)

---

## Summary

**Recommended workflow:**

1. ✅ Add Docker Hub secrets to GitHub (one-time)
2. ✅ Create GitHub Release or push tag
3. ✅ GitHub Actions builds and pushes automatically
4. ✅ Verify on Docker Hub
5. ✅ Test by pulling and running

**Manual is useful for:**
- Testing local changes before committing
- Quick iterations during development
- When you don't want to create a tag/release

---

## Links

- Docker Hub: https://hub.docker.com/r/spiderhash/webhook
- GitHub Actions: https://github.com/spiderhash-io/webhook/actions
- Workflow File: `.github/workflows/docker-release.yml`
- Docker Hub Setup: `.github/DOCKER_HUB_SETUP.md`
