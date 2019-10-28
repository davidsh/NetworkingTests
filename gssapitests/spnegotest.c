#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "spnegotest.h"

uint32_t TestSpnegoLoop(char* userName, char* password, char* spnTarget)
{
    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;

    char* host = ConvertToHostBasedServiceFormat(spnTarget); // TODO: free this string
    gss_name_t gssNameSpnNt = NULL;
    if (!CreateNameObject(host, GSS_C_NT_HOSTBASED_SERVICE, &gssNameSpnNt)) return FAIL;

    gss_name_t gssNameSpn = NULL;
    if (!CreateNameObject(spnTarget, GSS_KRB5_NT_PRINCIPAL_NAME, &gssNameSpn)) return FAIL;

    uint32_t reqFlags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    uint32_t retFlags;

    gss_buffer_desc clientToken = { 0 };
    gss_buffer_desc serverToken = { 0 };
    gss_ctx_id_t clientContextHandle = GSS_C_NO_CONTEXT;

    // Build client credential.
    gss_cred_id_t clientCredential = NULL;
    if (userName == NULL)
    {
        if (!CreateClientDefaultCredential(&clientCredential)) return FAIL;
    }
    else
    {
        if (!CreateClientCredential(userName, password, 0, &clientCredential)) return FAIL;
    }
    

    gss_ctx_id_t serverContextHandle = GSS_C_NO_CONTEXT;
    gss_name_t gssClientName = gssNameSpn;

    // Build server credential. The NTLM provider requires a non-null credential.
    gss_cred_id_t serverCredential = GSS_C_NO_CREDENTIAL;
    majorStatus = gss_acquire_cred(&minorStatus,
                                   GSS_C_NO_NAME,
                                   GSS_C_INDEFINITE,
                                   GSS_C_NO_OID_SET,
                                   GSS_C_ACCEPT,
                                   &serverCredential,
                                   NULL,
                                   NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_acquire_cred", majorStatus, minorStatus);
        return FAIL;
    }

    gss_OID actualClientMech = GSS_C_NO_OID;
    gss_OID actualServerMech = GSS_C_NO_OID;
    uint32_t clientDone = 0;
    uint32_t serverDone = 0;
    uint32_t clientRetryCount = 0;
    while (!clientDone || !serverDone)
    {
        if (!clientDone)
        {
            retryInitSec:
            majorStatus = gss_init_sec_context(&minorStatus,
                                               //(userName == NULL) ? GSS_C_NO_CREDENTIAL : clientCredential,
                                               clientCredential,
                                               &clientContextHandle,
                                               gssClientName,
                                               &GSS_SPNEGO_MECHANISM,
                                               reqFlags,
                                               0,
                                               GSS_C_NO_CHANNEL_BINDINGS,
                                               &serverToken,
                                               &actualClientMech,
                                               &clientToken,
                                               &retFlags,
                                               NULL);
            if (majorStatus == GSS_S_COMPLETE)
            {
                clientDone = 1;
            }
            else if (majorStatus != GSS_S_CONTINUE_NEEDED)
            {
                if (clientContextHandle == GSS_C_NO_CONTEXT && !clientRetryCount)
                {
                    // Attempt SPNEGO NTLM fallback by using GSS_C_NT_HOSTBASED_SERVICE
                    // format of SPN target name.
                    clientRetryCount++;
                    gssClientName = gssNameSpnNt;
                    goto retryInitSec;
                }

                DisplayStatus("gss_init_sec_context", majorStatus, minorStatus);
                return FAIL;
            }
        }

        if (!serverDone)
        {
            retryAcceptSec:
            majorStatus = gss_accept_sec_context(&minorStatus,
                                                 &serverContextHandle,
                                                 serverCredential,
                                                 &clientToken,
                                                 GSS_C_NO_CHANNEL_BINDINGS,
                                                 NULL,
                                                 &actualServerMech,
                                                 &serverToken,
                                                 &retFlags,
                                                 NULL,
                                                 NULL);
            if (majorStatus == GSS_S_COMPLETE)
            {
                serverDone = 1;
            }
            else if (majorStatus != GSS_S_CONTINUE_NEEDED)
            {
                DisplayStatus("gss_accept_sec_context", majorStatus, minorStatus);
                return FAIL;
            }
        }
    }

    PrintContext(clientContextHandle);
    printf("Client Mechanism:");
    PrintMechanism(actualClientMech);
    PrintContext(serverContextHandle);
    printf("Server Mechanism:");
    PrintMechanism(actualServerMech);

    // Cleanup.
    majorStatus = gss_release_cred(&minorStatus, &clientCredential);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_release_cred", majorStatus, minorStatus);
        return FAIL;
    }
    majorStatus = gss_release_cred(&minorStatus, &serverCredential);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_release_cred", majorStatus, minorStatus);
        return FAIL;
    }

    return PASS;
}
