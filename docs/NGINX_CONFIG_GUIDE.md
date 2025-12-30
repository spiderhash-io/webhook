# Nginx Configuration Guide for /webhook/ Proxy

## Problem
When nginx proxies `/webhook/docs` to the backend, FastAPI receives `/webhook/docs` but expects `/docs`, causing 405 errors.

## Solution Options

### Option 1: Use nginx rewrite (Recommended)
Rewrite docs endpoints before proxying:

```nginx
# Rewrite docs endpoints to remove /webhook prefix
location ~ ^/webhook/(docs|redoc|openapi\.json)$ {
    rewrite ^/webhook/(.*)$ /$1 break;
    proxy_pass http://10.10.10.103:3015;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Port  $server_port;
}

# Webhook endpoints (all other /webhook/* requests)
location /webhook/ {
    proxy_pass http://10.10.10.103:3015/webhook/;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Port  $server_port;
}
```

### Option 2: Set ROOT_PATH environment variable
Set `ROOT_PATH=/webhook` in your Docker container and use uvicorn's `--root-path`:

**docker-compose.yml:**
```yaml
services:
  webhook:
    environment:
      - ROOT_PATH=/webhook
```

**Then nginx can proxy directly:**
```nginx
location /webhook/ {
    proxy_pass http://10.10.10.103:3015;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header X-Forwarded-Port  $server_port;
}
```

## Current Status
- Dockerfile.smaller updated to use `--root-path` flag
- Set `ROOT_PATH=/webhook` environment variable in your container
- Or use nginx rewrite (Option 1) for immediate fix
