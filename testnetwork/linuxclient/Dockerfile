FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc
COPY ./common/krb5.conf .

WORKDIR /setup
COPY ./linuxclient/setup-client.sh .
RUN chmod +x setup-client.sh
RUN ./setup-client.sh

COPY ./linuxclient/run.sh .
RUN chmod +x run.sh

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
