FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

# environment variables
ENV DEBIAN_FRONTEND noninteractive

COPY ./common/krb5.conf /etc/

WORKDIR /setup
COPY ./linuxweb/*.sh ./
RUN chmod +x *.sh

RUN ./setup-web.sh

#COPY ./linuxweb/ntlm_user_file .
#ENV NTLM_USER_FILE=/setup/ntlm_user_file

RUN mkdir /patch

COPY ./testservers/webserver/*.* /webserver/
COPY ./testservers/negserver/*.* /negserver/

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
