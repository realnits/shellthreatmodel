#!/bin/bash
set -e

echo "Creating virtual environment for build..."
python3 -m venv .build_venv
source .build_venv/bin/activate

echo "Installing build tools..."
pip install build

echo "Building Python package..."
python -m build

echo "Copying wheel to web directory..."
cp dist/*.whl web/shellthreatmodel-0.1.0-py3-none-any.whl

echo "Cleaning up..."
deactivate
rm -rf .build_venv

echo "Web assets are ready in web/"
echo "To test locally: cd web && python3 -m http.server"
