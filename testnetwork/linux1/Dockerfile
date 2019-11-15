FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc
COPY krb5.conf .

WORKDIR /setup
COPY setup-client.sh .
RUN chmod +x setup-client.sh
RUN ./setup-client.sh

COPY run.sh .
RUN chmod +x run.sh

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
