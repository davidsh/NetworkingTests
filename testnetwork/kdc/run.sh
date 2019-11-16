#!/usr/bin/env bash

echo "Starting KDC"
service krb5-kdc restart
service krb5-admin-server restart

cp /setup/*.keytab /keytabs

#echo "Login with 'defaultcred' user"
echo password | kinit defaultcred && klist

# Copy and patch files if present
echo "Patching Microsoft.NETCore.App/3.0.0 files"
ls -l /patch
cp -r /patch/. /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0

#dotnet test EnterpriseTests/EnterpriseTests.csproj --logger:trx --results-directory /testresults

# Running 'dotnet test' will cause an exit code of '1' if tests fail.
# That breaks the Azure Pipelines and won't propagate test results.
# Clear the exit code.
#exit 0

# Keep the container running
tail -f /dev/null
