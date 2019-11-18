#!/usr/bin/env bash

echo "Restoring Microsoft.NETCore.App/3.0.0 files from backup"
cp /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0-backup/*.* /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0
