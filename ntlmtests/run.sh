#!/usr/bin/env bash

echo "/etc/hosts"
cat /etc/hosts
echo "/etc/resolv.conf"
cat /etc/resolv.conf
echo "hostname -f"
hostname -f

echo "Starting KDC"
service krb5-kdc restart

#echo "Testing KDC with defaultcred user"
#echo password | kinit defaultcred && klist

# Copy and patch files if present
echo "Patching Microsoft.NETCore.App/3.0.0 files"
ls -l /patch
cp -r /patch/. /usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0

cd ntlmserver
dotnet run
