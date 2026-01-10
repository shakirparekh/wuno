#!/bin/bash
# Script to staple notarization tickets to wentuno apps
set -e

# Check for version parameter
if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 5.0.5"
    exit 1
fi

VERSION=$1

# Check if signed zip files exist
if [ ! -f "wentuno-${VERSION}-arm64-apple-darwin-signed.zip" ] || [ ! -f "wentuno-${VERSION}-x86_64-apple-darwin-signed.zip" ]; then
    echo "Error: Signed zip files not found!"
    echo "Expected files:"
    echo "  - wentuno-${VERSION}-arm64-apple-darwin-signed.zip"
    echo "  - wentuno-${VERSION}-x86_64-apple-darwin-signed.zip"
    echo ""
    echo "Run ./sign-mac-binaries.sh ${VERSION} and ./notarize-mac-binaries.sh ${VERSION} first."
    exit 1
fi

echo "=== Stapling notarization tickets to wentuno apps v${VERSION} ==="

# Create working directory
mkdir -p stapled_tmp

# Process ARM64 binary
echo "Processing ARM64 binary..."
rm -rf stapled_tmp/arm64
unzip -q "wentuno-${VERSION}-arm64-apple-darwin-signed.zip" -d stapled_tmp/arm64/
echo "Stapling notarization ticket..."
if ! xcrun stapler staple stapled_tmp/arm64/wentuno-Qt.app; then
    echo "Error: Failed to staple ARM64 app. Was it notarized?"
    echo "Run ./notarize-mac-binaries.sh ${VERSION} first."
    rm -rf stapled_tmp
    exit 1
fi
echo "Verifying..."
xcrun stapler validate stapled_tmp/arm64/wentuno-Qt.app

# Process x86_64 binary
echo -e "\nProcessing x86_64 binary..."
rm -rf stapled_tmp/x86_64
unzip -q "wentuno-${VERSION}-x86_64-apple-darwin-signed.zip" -d stapled_tmp/x86_64/
echo "Stapling notarization ticket..."
if ! xcrun stapler staple stapled_tmp/x86_64/wentuno-Qt.app; then
    echo "Error: Failed to staple x86_64 app. Was it notarized?"
    echo "Run ./notarize-mac-binaries.sh ${VERSION} first."
    rm -rf stapled_tmp
    exit 1
fi
echo "Verifying..."
xcrun stapler validate stapled_tmp/x86_64/wentuno-Qt.app

# Create final distribution packages
echo -e "\nCreating final distribution packages..."
cd stapled_tmp/arm64
zip -r -q "../../wentuno-${VERSION}-arm64-apple-darwin-notarized.zip" wentuno-Qt.app
cd ../x86_64
zip -r -q "../../wentuno-${VERSION}-x86_64-apple-darwin-notarized.zip" wentuno-Qt.app
cd ../..

# Clean up
rm -rf stapled_tmp

echo -e "\n=== Complete! ==="
echo "Final notarized packages created:"
echo "  - wentuno-${VERSION}-arm64-apple-darwin-notarized.zip"
echo "  - wentuno-${VERSION}-x86_64-apple-darwin-notarized.zip"
echo ""
echo "These packages are fully signed, notarized, and stapled."
echo "They will run on any macOS without security warnings!"
echo ""
echo "You can verify the final apps with:"
echo "  codesign --verify --deep --strict --verbose=2 <extracted-app>"
echo "  xcrun stapler validate <extracted-app>" 