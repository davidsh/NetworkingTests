#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "client.h"
#include "ntlmtest.h"
#include "spnegotest.h"

int main(int argc, char *argv[])
{
    //setenv("KRB5_TRACE", "/dev/stdout", 0);
    //setenv("GSSNTLMSSP_DEBUG", "/dev/stdout", 0);
    setenv("NTLM_USER_FILE", "/var/tmp/ntlm_user_file", 0);

    PrintMechanisms();
    printf("NTLM installed: %s\n\n", IsNtlmInstalled() ? "yes" : "no");

    printf("\nNTLM test: %s\n", TestNtlmLoop("ntlm_user", "ntlm_password") ? "PASS" : "FAIL");
    printf("\nSPNEGO test with kerberos credential: %s\n", TestSpnegoLoop("krb_user", "password") ? "PASS" : "FAIL");
    printf("\nSPNEGO test with ntlm credential: %s\n", TestSpnegoLoop("ntlm_user", "ntlm_password") ? "PASS" : "FAIL");
    printf("\nClient test: %s\n", ClientTest(0, "krb_user", "password") ? "PASS" : "FAIL");

    return 0;
}
