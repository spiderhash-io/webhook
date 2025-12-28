# Core Webhook Module Documentation

This is the documentation site for the Core Webhook Module, built with Docusaurus.

## Development

```bash
# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build

# Serve production build
npm run serve
```

## Docker Deployment

### Build

```bash
docker build -t core-webhook-docs:latest .
```

### Run

```bash
docker run -p 8080:80 core-webhook-docs:latest
```

The documentation will be available at `http://localhost:8080`.

## Structure

- `docs/` - Documentation pages
  - `getting-started/` - Installation and configuration guides
  - `modules/` - Output module documentation
  - `authentication/` - Authentication method documentation
  - `features/` - Feature documentation
- `blog/` - Blog posts
- `src/` - Custom React components
- `static/` - Static assets
