#!/usr/bin/env bash

# Echo
set -x

# WorkingDirectory
WORKINGDIR=$1

# Clone and build the dotnet/runtime repo (TODO: Wait for repo to become public)
#git clone https://github.com/dotnet/runtime.git
git clone https://github.com/dotnet/corefx.git
docker run --rm -v $WORKINGDIR/corefx:/corefx -w /corefx mcr.microsoft.com/dotnet-buildtools/prereqs:fedora-29-helix-09ca40b-20190508143249 ./build.sh

# Start up the test network and machine
cd testnetwork
docker-compose up -d

# Copy the latest Microsoft.NETCore.App into the client machine
docker cp $WORKINGDIR/corefx/artifacts/bin/testhost/netcoreapp-Linux-Debug-x64/shared/Microsoft.NETCore.App/5.0.0/*.* linuxclient:/usr/share/dotnet/shared/Microsoft.NETCore.App/3.0.0

# Run the client tests and copy the test results of the container
docker exec linuxclient dotnet test /EnterpriseTests/EnterpriseTests.csproj --logger:trx --results-directory /testresults
docker cp linuxclient:/testresults .

# Shut down the test network and machines
docker-compose down
