FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc/krb5kdc
COPY ./kdc/kdc.conf .

WORKDIR /etc
COPY ./common/krb5.conf .

WORKDIR /setup
COPY ./kdc/setup-kdc.sh .
RUN chmod +x setup-kdc.sh
RUN ./setup-kdc.sh

COPY ./kdc/run.sh .
RUN chmod +x run.sh

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]