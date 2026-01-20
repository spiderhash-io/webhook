# Docker Hub Setup Guide

This guide explains how to configure Docker Hub credentials for automated Docker image releases.

## Overview

The repository uses GitHub Actions to automatically build and push Docker images to Docker Hub when new releases are created. This requires Docker Hub credentials to be stored as GitHub Secrets.

## Prerequisites

1. **Docker Hub Account**: You need a Docker Hub account at https://hub.docker.com
2. **Docker Hub Repository**: The repository `spiderhash/webhook` should exist on Docker Hub
3. **GitHub Repository Admin Access**: You need admin access to configure secrets

## Step 1: Create Docker Hub Access Token

1. Log in to Docker Hub at https://hub.docker.com
2. Click on your username in the top right corner
3. Select **Account Settings** from the dropdown
4. Navigate to **Security** in the left sidebar
5. Click **New Access Token**
6. Configure the token:
   - **Description**: `GitHub Actions - webhook repository`
   - **Access permissions**: `Read & Write` (or `Read, Write, Delete` if you want to manage tags)
7. Click **Generate**
8. **IMPORTANT**: Copy the token immediately - it will only be shown once!

## Step 2: Add Secrets to GitHub Repository

1. Go to your GitHub repository: https://github.com/spiderhash-io/webhook
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**

### Add DOCKERHUB_USERNAME

1. **Name**: `DOCKERHUB_USERNAME`
2. **Secret**: Your Docker Hub username (e.g., `spiderhash`)
3. Click **Add secret**

### Add DOCKERHUB_TOKEN

1. Click **New repository secret** again
2. **Name**: `DOCKERHUB_TOKEN`
3. **Secret**: Paste the access token you copied from Docker Hub
4. Click **Add secret**

## Step 3: Verify Configuration

After adding the secrets, the Docker release workflow will be able to push images automatically.

### Test the Setup

1. Create a new git tag (or use the existing `v0.1.0` tag):
   ```bash
   git tag -a v0.1.1 -m "Release v0.1.1"
   git push github v0.1.1
   ```

2. Go to the **Actions** tab in your GitHub repository
3. Watch the **Docker Release** workflow run
4. After completion, verify the image on Docker Hub: https://hub.docker.com/r/spiderhash/webhook/tags

## Workflow Behavior

The Docker release workflow (`.github/workflows/docker-release.yml`) will:

- **Trigger**: Automatically when you push a tag matching `v*` (e.g., `v0.1.0`, `v1.2.3`)
- **Build**: Multi-architecture images for `linux/amd64` and `linux/arm64`
- **Push Tags**:
  - Version tag (e.g., `0.1.0` from tag `v0.1.0`)
  - `latest` tag (for the most recent release)
- **Skip**: If secrets are not configured, the workflow will fail with authentication errors

## Security Best Practices

1. **Use Access Tokens**: Never use your Docker Hub password directly
2. **Limit Permissions**: Create tokens with minimum required permissions (Read & Write)
3. **Rotate Tokens**: Periodically rotate access tokens (every 6-12 months)
4. **Revoke Unused Tokens**: Remove tokens that are no longer needed
5. **Monitor Usage**: Check Docker Hub activity logs for unexpected pushes

## Troubleshooting

### Error: "denied: requested access to the resource is denied"

**Cause**: Invalid credentials or insufficient permissions

**Solution**:
1. Verify `DOCKERHUB_USERNAME` matches your Docker Hub username exactly
2. Regenerate the access token and update `DOCKERHUB_TOKEN`
3. Ensure the token has `Read & Write` permissions
4. Verify the repository `spiderhash/webhook` exists on Docker Hub

### Error: "repository does not exist"

**Cause**: The Docker Hub repository hasn't been created

**Solution**:
1. Go to https://hub.docker.com
2. Click **Create Repository**
3. Name: `webhook`
4. Visibility: `Public` (for open-source)
5. Click **Create**

### Workflow Not Triggering

**Cause**: Tag format doesn't match the pattern

**Solution**:
- Ensure tags follow the format `vX.Y.Z` (e.g., `v0.1.0`, `v1.2.3`)
- Tags must start with `v` followed by semantic version numbers

## Manual Docker Push (Alternative)

If you prefer to push Docker images manually instead of using GitHub Actions:

```bash
# Build the image
docker build -t spiderhash/webhook:0.1.0 -f docker/Dockerfile .

# Tag as latest
docker tag spiderhash/webhook:0.1.0 spiderhash/webhook:latest

# Login to Docker Hub
docker login -u spiderhash

# Push both tags
docker push spiderhash/webhook:0.1.0
docker push spiderhash/webhook:latest
```

## Additional Resources

- [Docker Hub Access Tokens Documentation](https://docs.docker.com/docker-hub/access-tokens/)
- [GitHub Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [Docker Release Workflow](.github/workflows/docker-release.yml)
- [Docker Release Guide](DOCKER_RELEASE_GUIDE.md)

## Support

If you encounter issues not covered in this guide:

1. Check the [GitHub Actions logs](https://github.com/spiderhash-io/webhook/actions)
2. Review the [Docker Hub activity](https://hub.docker.com/r/spiderhash/webhook)
3. Open an issue at https://github.com/spiderhash-io/webhook/issues
