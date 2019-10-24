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
    char* hostServer = "HTTP@testhost";
    int len = strlen(hostServer);

    gss_buffer_desc gssBuffer = {.length = len, .value = hostServer};
    gss_name_t gssNameSpnNt = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_C_NT_HOSTBASED_SERVICE, &gssNameSpnNt);
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
    majorStatus = gss_init_sec_context(&minorStatus,
                                       clientCredential,
                                       &clientContextHandle,
                                       gssNameSpnNt,
                                       &oidMechNtlm,
                                       reqFlags,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &serverToken,
                                       &outmech,
                                       &clientToken,
                                       &retFlags,
                                       NULL);
    if (majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Build server credential.
    gss_cred_id_t serverCredential = NULL;
    gss_OID_set actualMech = NULL;
    majorStatus = gss_acquire_cred(&minorStatus, gssNameSpnNt, GSS_C_INDEFINITE,
                           mechSetBoth, GSS_C_ACCEPT, &serverCredential,
                           &actualMech, NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Server accepts inital client token and generates a token for the client.
    gss_ctx_id_t serverContextHandle = GSS_C_NO_CONTEXT;
    gss_OID mechType = GSS_C_NO_OID;
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
    if (majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    // Client processes server token (again) and generates a response.
    majorStatus = gss_init_sec_context(&minorStatus,
                                       clientCredential,
                                       &clientContextHandle,
                                       gssNameSpnNt,
                                       &oidMechNtlm,
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

    PrintContext(serverContextHandle);

    return PASS;
}
