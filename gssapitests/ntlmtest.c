#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "ntlmtest.h"

uint32_t TestNtlmLoop(char* userName, char* password)
{
    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;

    gss_name_t gssNameClientRequest = NULL;
    if (!CreateNameObject("HTTP@clientRequestedHost", GSS_C_NT_HOSTBASED_SERVICE, &gssNameClientRequest)) return FAIL;

    uint32_t reqFlags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    uint32_t retFlags;

    gss_buffer_desc clientToken = { 0 };
    gss_buffer_desc serverToken = { 0 };

    // Build client credential.
    gss_cred_id_t clientCredential = NULL;
    if (userName != NULL)
    {
        if (!CreateClientCredential(userName, password, 1, &clientCredential)) return FAIL;
    }

    // Build server credential. The NTLM provider requires a non-null credential.
    gss_cred_id_t serverCredential = NULL;
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

    gss_ctx_id_t clientContext = GSS_C_NO_CONTEXT;
    gss_ctx_id_t serverContext = GSS_C_NO_CONTEXT;

    gss_OID actualClientMech = GSS_C_NO_OID;
    gss_OID actualServerMech = GSS_C_NO_OID;
    while (1)
    {
        majorStatus = gss_init_sec_context(&minorStatus,
                                           clientCredential,
                                           &clientContext,
                                           gssNameClientRequest,
                                           &GSS_NTLM_MECHANISM,
                                           reqFlags,
                                           0,
                                           GSS_C_NO_CHANNEL_BINDINGS,
                                           &serverToken,
                                           &actualClientMech,
                                           &clientToken,
                                           &retFlags,
                                           NULL);
        if (majorStatus != GSS_S_CONTINUE_NEEDED && majorStatus != GSS_S_COMPLETE)
        {
            DisplayStatus("gss_init_sec_context", majorStatus, minorStatus);
            return FAIL;
        }

        majorStatus = gss_accept_sec_context(&minorStatus,
                                            &serverContext,
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
            break;
        }

        if (majorStatus != GSS_S_CONTINUE_NEEDED)
        {
            DisplayStatus("gss_accept_sec_context", majorStatus, minorStatus);
            return FAIL;
        }
    }

    PrintContext(clientContext);
    printf("Client Mechanism:");
    PrintMechanism(actualClientMech);
    PrintContext(serverContext);
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
