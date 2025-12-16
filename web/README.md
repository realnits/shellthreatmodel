# AI Threat Model - Web UI

This directory contains the static web application for AI Threat Model. It runs entirely in the browser using [PyScript](https://pyscript.net/).

## Setup

1.  **Build the Package**: Before deploying or testing, you must build the Python package wheel.
    Run the build script from the project root:
    ```bash
    ./build_web.sh
    ```
    This will generate a `.whl` file and copy it into this directory.

2.  **Local Testing**:
    Serve this directory using a simple HTTP server:
    ```bash
    python3 -m http.server
    ```
    Open `http://localhost:8000` in your browser.

## Deployment to GitHub Pages

1.  Ensure the `.whl` file is generated and committed to the repository.
2.  Go to your GitHub repository settings -> Pages.
3.  Select "Deploy from a branch".
4.  If you want to serve this from a specific folder (like `/web`), you might need to configure a GitHub Action or move these files to `/docs` (if supported) or the root of a `gh-pages` branch.

### Recommended GitHub Action Workflow

Create `.github/workflows/static.yml`:

```yaml
name: Deploy Web UI

on:
  push:
    branches: ["main"]

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: false

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"
          
      - name: Build Wheel
        run: |
          pip install build
          python -m build
          cp dist/*.whl web/shellthreatmodel-0.1.0-py3-none-any.whl
          
      - name: Setup Pages
        uses: actions/configure-pages@v5
        
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: 'web'
          
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
```
