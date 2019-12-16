FROM ubuntu:18.04

COPY kadm5.acl /etc/krb5kdc/
COPY kdc.conf /etc/krb5kdc/
COPY krb5.conf /etc/

WORKDIR /setup
COPY *.sh ./
RUN chmod +x *.sh

# Prevents dialog prompting when installing packages
ARG DEBIAN_FRONTEND=noninteractive

# Install KDC, apache2 and diagnostic tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        krb5-kdc krb5-admin-server \
        apache2 libapache2-mod-auth-kerb \
        iputils-ping dnsutils nano curl

RUN ./setup-kdc.sh

EXPOSE 88/tcp
EXPOSE 88/udp
EXPOSE 80

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
