#!/usr/bin/env bash

# Copy and patch files if present
#echo "Patching Microsoft.NETCore.App/3.0.0 files"
#ls -l /patch
#cp -r /patch/. /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0

#dotnet test EnterpriseTests/EnterpriseTests.csproj --logger:trx --results-directory /testresults

# Running 'dotnet test' will cause an exit code of '1' if tests fail.
# That breaks the Azure Pipelines and won't propagate test results.
# Clear the exit code.
#exit 0

export ASPNETCORE_URLS="http://+:80;https://+:443"
export ASPNETCORE_ENVIRONMENT="Development"

cp /SHARED/linuxweb.keytab /etc/krb5.keytab

# Build and run NegotiateStream server listening on port 8080
cd /negserver
dotnet build
bin/Debug/netcoreapp3.0/negserver 8080 &> /SHARED/negserver.log &

# Build and run ASP.NET Core server which uses Negotiate authentication
cd /webserver
dotnet build
bin/Debug/netcoreapp3.0/webserver &> /SHARED/webserver.log &

# Keep the container running since both servers are running the background
tail -f /dev/null
