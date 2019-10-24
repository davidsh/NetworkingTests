#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "client.h"

uint32_t ClientTest(int useKerb, char* userName, char* password)
{
    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;
    char* targetKerb = "TESTHOST/testfqdn.test.corefx.net";
    char* targetNt = "TESTHOST@testfqdn.test.corefx.net";

    gss_buffer_desc gssBuffer = {.length = strlen(targetNt), .value = targetNt};
    gss_name_t gssNameTargetNt = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_C_NT_HOSTBASED_SERVICE, &gssNameTargetNt);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }
    gssBuffer.length = strlen(targetKerb);
    gssBuffer.value = targetKerb;
    gss_name_t gssNameTargetKerb = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_KRB5_NT_PRINCIPAL_NAME, &gssNameTargetKerb);
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

    // Client builds the first token.
    gss_name_t gssClientName;
    gssClientName = useKerb ? gssNameTargetKerb : gssNameTargetNt;
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
        gssClientName = gssNameTargetNt;
        goto retryInitSec;
    }
    else if (majorStatus != GSS_S_CONTINUE_NEEDED)
    {
        DisplayStatus(majorStatus, minorStatus);
        return FAIL;
    }

    return PASS;
}
