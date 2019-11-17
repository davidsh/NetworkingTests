FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

# environment variables
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /etc
COPY ./common/krb5.conf .

WORKDIR /setup
COPY ./linuxclient/*.sh ./
RUN chmod +x *.sh

RUN ./setup-client.sh

RUN mkdir /patch

COPY ./EnterpriseTests/*.* /EnterpriseTests/
COPY ./testclients/negclient/*.* /negclient/
COPY ./testclients/httpclient/*.* /httpclient/

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
