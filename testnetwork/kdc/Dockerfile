FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc/krb5kdc
COPY kdc.conf .

WORKDIR /etc
COPY krb5.conf .

WORKDIR /setup
COPY ntlm_user_file .
COPY setup-kdc.sh .
RUN chmod +x setup-kdc.sh
RUN ./setup-kdc.sh

ENV NTLM_USER_FILE=/setup/ntlm_user_file

COPY run.sh .
RUN chmod +x run.sh

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/setup/run.sh"]