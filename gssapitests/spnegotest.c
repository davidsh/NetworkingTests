#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "spnegotest.h"

uint32_t TestSpnegoLoop(char* userName, char* password)
{
    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;
    char* hostServer = "TESTHOST@testfqdn.test.corefx.net";
    char* targetServer = "TESTHOST/testfqdn.test.corefx.net";

    gss_buffer_desc gssBuffer = {.length = strlen(hostServer), .value = hostServer};
    gss_name_t gssNameSpnNt = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_C_NT_HOSTBASED_SERVICE, &gssNameSpnNt);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }
    gssBuffer.length = strlen(targetServer);
    gssBuffer.value = targetServer;
    gss_name_t gssNameSpn = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_KRB5_NT_PRINCIPAL_NAME, &gssNameSpn);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    uint32_t reqFlags = GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    uint32_t retFlags;

    gss_buffer_desc clientToken = { 0 };
    gss_buffer_desc serverToken = { 0 };
    gss_OID_desc* outmech;
    gss_OID_desc oidMechNtlm = { .length = ARRAY_SIZE(gss_ntlm_oid_value) - 1, .elements = gss_ntlm_oid_value };
    gss_OID_desc oidMechSpnego = { .length = ARRAY_SIZE(gss_spnego_oid_value) - 1, .elements = gss_spnego_oid_value };
    gss_ctx_id_t clientContextHandle = GSS_C_NO_CONTEXT;

    // Build a set of 2 oids.
    gss_OID_set mechSetBoth = NULL;
    majorStatus = gss_create_empty_oid_set(&minorStatus, &mechSetBoth);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }
    majorStatus = gss_add_oid_set_member(&minorStatus, &oidMechSpnego, &mechSetBoth);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }
    majorStatus = gss_add_oid_set_member(&minorStatus, &oidMechNtlm, &mechSetBoth);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Build client credential.
    gss_cred_id_t clientCredential = NULL;
    if (!CreateClientCredential(userName, password, &clientCredential)) return FAIL;

    gss_OID_set_desc mechSetNtlm = {.count = 1, .elements = &oidMechNtlm};
    gss_OID_set_desc mechSetSpnego = {.count = 1, .elements = &oidMechSpnego};

    // Client builds the first token.
    gss_name_t gssClientName = gssNameSpn;
    retryInitSec: majorStatus = gss_init_sec_context(&minorStatus,
                                       clientCredential,
                                       &clientContextHandle,
                                       gssClientName,
                                       &oidMechSpnego,
                                       reqFlags,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &serverToken,
                                       &outmech,
                                       &clientToken,
                                       &retFlags,
                                       NULL);
    if (majorStatus == GSS_S_BAD_NAMETYPE)
    {
        gssClientName = gssNameSpnNt;
        goto retryInitSec;
    }
    else if (majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Build server credential.
    gss_cred_id_t serverCredentialSpn = NULL;
    gss_OID_set actualMech = NULL;
    majorStatus = gss_acquire_cred(&minorStatus, gssNameSpn, GSS_C_INDEFINITE,
                           &mechSetSpnego, GSS_C_ACCEPT, &serverCredentialSpn,
                           &actualMech, NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }
    gss_cred_id_t serverCredentialSpnNt = NULL;
    actualMech = NULL;
    majorStatus = gss_acquire_cred(&minorStatus, gssNameSpnNt, GSS_C_INDEFINITE,
                           mechSetBoth, GSS_C_ACCEPT, &serverCredentialSpnNt,
                           &actualMech, NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Server accepts inital client token and generates a token for the client.
    gss_cred_id_t serverCredential = serverCredentialSpn;
    gss_ctx_id_t serverContextHandle = GSS_C_NO_CONTEXT;
    gss_OID mechType = GSS_C_NO_OID;
    retryAcceptSec: majorStatus = gss_accept_sec_context(&minorStatus,
                                         &serverContextHandle,
                                         serverCredential,
                                         &clientToken,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         NULL,
                                         &mechType,
                                         &serverToken,
                                         &retFlags,
                                         NULL,
                                         NULL);
    if (majorStatus == GSS_S_BAD_MECH || majorStatus == GSS_S_NO_CRED)
    {
        serverCredential = serverCredentialSpnNt;
        goto retryAcceptSec;
    }
    else if (majorStatus == GSS_S_COMPLETE)
    {
        goto done;
    }
    else if (majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Client processes server token (again) and generates a response.
    majorStatus = gss_init_sec_context(&minorStatus,
                                       clientCredential,
                                       &clientContextHandle,
                                       gssClientName,
                                       &oidMechSpnego,
                                       reqFlags,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &serverToken,
                                       &outmech,
                                       &clientToken,
                                       &retFlags,
                                       NULL);
    if (majorStatus != GSS_S_COMPLETE && majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Server receives final client token and determines whether server is done with handshake.
    mechType = GSS_C_NO_OID;
    majorStatus = gss_accept_sec_context(&minorStatus,
                                         &serverContextHandle,
                                         serverCredential,
                                         &clientToken,
                                         GSS_C_NO_CHANNEL_BINDINGS,
                                         NULL,
                                         &mechType,
                                         &serverToken,
                                         &retFlags,
                                         NULL,
                                         NULL);
    if (majorStatus == GSS_S_CONTINUE_NEEDED)
    {
        // Client processes server token (again) and generates a response.
        majorStatus = gss_init_sec_context(&minorStatus,
                                        clientCredential,
                                        &clientContextHandle,
                                        gssClientName,
                                        &oidMechSpnego,
                                        reqFlags,
                                        0,
                                        GSS_C_NO_CHANNEL_BINDINGS,
                                        &serverToken,
                                        &outmech,
                                        &clientToken,
                                        &retFlags,
                                        NULL);
        if (majorStatus != GSS_S_COMPLETE)
        {
            DisplayStatus(majorStatus, minorStatus);
            return FAIL;
        }

        // Server receives final client token and determines whether server is done with handshake.
        mechType = GSS_C_NO_OID;
        majorStatus = gss_accept_sec_context(&minorStatus,
                                            &serverContextHandle,
                                            serverCredential,
                                            &clientToken,
                                            GSS_C_NO_CHANNEL_BINDINGS,
                                            NULL,
                                            &mechType,
                                            &serverToken,
                                            &retFlags,
                                            NULL,
                                            NULL);
        if (majorStatus !=  GSS_S_COMPLETE)
        {
            DisplayStatus(majorStatus, minorStatus);
            return FAIL;
        }
    }
    else if (majorStatus !=  GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    done: PrintContext(serverContextHandle);

    return PASS;
}
