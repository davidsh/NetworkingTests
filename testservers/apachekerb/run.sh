#!/usr/bin/env bash

service krb5-kdc restart
service krb5-admin-server restart
service apache2 restart

# Keep the container running
tail -f /dev/null
