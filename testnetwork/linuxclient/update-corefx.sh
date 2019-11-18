#!/usr/bin/env bash

# Copy and patch files if present
echo "Patching Microsoft.NETCore.App/3.0.0 files"
cp -r /setup/patch/. /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0
