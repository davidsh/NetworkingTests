FROM ubuntu:18.04

COPY kadm5.acl /etc/krb5kdc/
COPY kdc.conf /etc/krb5kdc/
COPY krb5.conf /etc/

WORKDIR /setup
COPY *.sh ./
RUN chmod +x *.sh

# Prevents dialog prompting when installing packages
ARG DEBIAN_FRONTEND=noninteractive

# Install KDC and diagnostic tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends krb5-kdc krb5-admin-server iputils-ping dnsutils nano

RUN ./setup-kdc.sh

EXPOSE 88/tcp
EXPOSE 88/udp

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
