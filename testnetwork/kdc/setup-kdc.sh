#!/usr/bin/env bash

# Install KDC
apt-get update && \
    apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server iputils-ping dnsutils && \
    apt-get clean

# Create Kerberos database
kdb5_util create -r LINUX.CONTOSO.COM -P password -s

# Start KDC service
krb5kdc

# Add users
kadmin.local -q "add_principal -pw password defaultcred@LINUX.CONTOSO.COM"
kadmin.local -q "add_principal -pw password user1@LINUX.CONTOSO.COM"
kadmin.local -q "add_principal -pw password user2@LINUX.CONTOSO.COM"
kadmin.local -q "add_principal -pw password user4krb@LINUX.CONTOSO.COM"

# Add SPNs for services for realm
kadmin.local -q "add_principal -pw password HOST/localhost"
kadmin.local -q "add_principal -pw password HOST/kdc.linux.contoso.com"
kadmin.local -q "add_principal -pw password HTTP/localhost"
kadmin.local -q "add_principal -pw password HTTP/kdc.linux.contoso.com"
kadmin.local -q "add_principal -pw password HOST/webserver.linux.contoso.com"
kadmin.local -q "add_principal -pw password NEWSERVICE/localhost"

# Add a subset of SPNs for localhost machine
kadmin.local ktadd -norandkey HOST/kdc.linux.contoso.com
kadmin.local ktadd -norandkey HOST/localhost
kadmin.local ktadd -norandkey HTTP/localhost

# Fix permissions
chmod 644 /etc/krb5.keytab
chmod 644 /etc/krb5kdc/kdc.conf /etc/krb5.conf
