FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc
COPY ./common/krb5.conf .

WORKDIR /setup
COPY ./linuxweb/ntlm_user_file .
COPY ./linuxweb/setup-web.sh .
RUN chmod +x setup-web.sh
RUN ./setup-web.sh

ENV NTLM_USER_FILE=/setup/ntlm_user_file

COPY ./linuxweb/run.sh .
RUN chmod +x run.sh

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]
