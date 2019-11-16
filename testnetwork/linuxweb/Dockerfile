FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

# environment variables
ENV DEBIAN_FRONTEND noninteractive

COPY ./common/krb5.conf /etc/

WORKDIR /setup
#COPY ./linuxweb/ntlm_user_file .
COPY ./linuxweb/setup-web.sh /setup/
RUN chmod +x setup-web.sh
RUN ./setup-web.sh

#ENV NTLM_USER_FILE=/setup/ntlm_user_file

COPY ./linuxweb/run.sh /setup/
RUN chmod +x run.sh

RUN mkdir /patch

COPY ./common/webserver/*.* /webserver/

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
