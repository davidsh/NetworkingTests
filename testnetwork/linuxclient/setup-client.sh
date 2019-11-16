#!/usr/bin/env bash

# Install Kerberos client
apt-get update && \
    apt-get install -y --no-install-recommends krb5-user iputils-ping dnsutils && \
    apt-get clean
