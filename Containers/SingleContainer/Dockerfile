FROM mcr.microsoft.com/dotnet/core/sdk:3.0.100-bionic

WORKDIR /etc/krb5kdc
COPY kdc.conf .

WORKDIR /etc
COPY krb5.conf .

WORKDIR /app
COPY ntlm_user_file .
COPY setup-kdc.sh .
RUN chmod +x setup-kdc.sh
RUN ./setup-kdc.sh

COPY EnterpriseTests /app/EnterpriseTests

ENV NTLM_USER_FILE=/app/ntlm_user_file
ENV KRB5_TRACE=/dev/stdout
ENV GSSNTLMSSP_DEBUG=/dev/stdout

COPY run.sh .

RUN mkdir /patch

ENTRYPOINT ["/bin/bash", "/app/run.sh"]
