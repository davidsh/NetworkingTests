#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"

void DisplayStatus(char* title, uint32_t majorError, uint32_t minorError)
{
    uint32_t majorStatus;
    uint32_t minorStatus;

    uint32_t majorMessageContext = 0; // Must initialize to 0 before calling gss_display_status.
    gss_buffer_desc majorErrorBuffer = {.length = 0, .value = NULL};
    uint32_t minorMessageContext = 0; // Must initialize to 0 before calling gss_display_status.
    gss_buffer_desc minorErrorBuffer = {.length = 0, .value = NULL};

    majorStatus = gss_display_status(&minorStatus, majorError,  GSS_C_GSS_CODE, GSS_C_NO_OID, &majorMessageContext, &majorErrorBuffer);
    if (majorStatus == GSS_S_COMPLETE)
    {
        printf("%s:  \"%.*s (%u)", title, (int)majorErrorBuffer.length, (char *)majorErrorBuffer.value, majorError);
        majorStatus = gss_release_buffer(&minorStatus, &majorErrorBuffer);
    }

    if (minorError != GSS_S_COMPLETE)
    {
        // TODO: We need to pass in the proper OID to get mechanism specific minor error text.
        majorStatus = gss_display_status(&minorStatus, minorError, GSS_C_MECH_CODE, GSS_C_NO_OID, &minorMessageContext, &minorErrorBuffer);
        if (majorStatus == GSS_S_COMPLETE)
        {        
            printf(" (%.*s (%u))", (int)minorErrorBuffer.length, (char *)minorErrorBuffer.value, minorError);
            majorStatus = gss_release_buffer(&minorStatus, &minorErrorBuffer);        
        }
    }

    printf("\"\n");
}

uint32_t IsNtlmInstalled()
{
    uint32_t majorStatus;
    uint32_t minorStatus;
    gss_OID_set mechSet;
    gss_OID_desc oid;
    uint32_t foundNtlm = 0;

    majorStatus = gss_indicate_mechs(&minorStatus, &mechSet);
    if (majorStatus == GSS_S_COMPLETE)
    {
        for (size_t i = 0; i < mechSet->count; i++)
        {
            oid = mechSet->elements[i];
            if ((oid.length == GSS_NTLM_MECHANISM.length) && (memcmp(oid.elements, GSS_NTLM_MECHANISM.elements, oid.length) == 0))
            {
                foundNtlm = 1;
                break;
            }
        }

        gss_release_oid_set(&minorStatus, &mechSet);
    }

    return foundNtlm;
}

void PrintMechanism(gss_OID oid)
{
    for (int i = 0; i < ARRAY_SIZE(MechList); i++)
    {
        if ((oid->length == MechList[i].oid->length) && (memcmp(oid->elements, MechList[i].oid->elements, oid->length) == 0))
        {
            printf("  %s\n", MechList[i].oidDescription);
            return;
        }
    }

    printf("  Unknown mechanism\n");
}

void PrintMechanisms()
{
    uint32_t majorStatus;
    uint32_t minorStatus;
    gss_OID_set mechSet;

    majorStatus = gss_indicate_mechs(&minorStatus, &mechSet);
    if (majorStatus != GSS_S_COMPLETE)
    {
        printf("ERROR: gss_indicate_mechs majorStatus=%d, minorStatus=%d\n", majorStatus, minorStatus);
        return;
    }

    printf("Installed GSSAPI mechanisms: \n");
    for (size_t i = 0; i < mechSet->count; i++)
    {
        PrintMechanism(&mechSet->elements[i]);
    }

    printf("\n");

    // TODO: Release mechSet
}

void PrintContext(gss_ctx_id_t context)
{
    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;

    gss_name_t clientName = GSS_C_NO_NAME;
    gss_name_t serverName = GSS_C_NO_NAME;

    int contextCompleted = 0;
    majorStatus = gss_inquire_context(&minorStatus,
                                      context,
                                      &clientName,
                                      &serverName,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &contextCompleted);
    if (majorStatus !=  GSS_S_COMPLETE)
    {
        DisplayStatus("gss_inquire_context", majorStatus, minorStatus);
        return;
    }

    gss_buffer_desc gssTempBuffer = {.length = 0, .value = NULL};
    majorStatus = gss_display_name(&minorStatus, clientName, &gssTempBuffer, NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_display_name", majorStatus, minorStatus);
        return;
    }
    printf("Client=%s\n", (char *)gssTempBuffer.value);

    majorStatus = gss_display_name(&minorStatus, serverName, &gssTempBuffer, NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_display_name", majorStatus, minorStatus);
        return;
    }
    printf("Server=%s\n", (char *)gssTempBuffer.value);   
}

uint32_t CreateClientDefaultCredential(gss_cred_id_t* clientCredential)
{
    *clientCredential = GSS_C_NO_CREDENTIAL;

    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;

    //gss_OID_set_desc mechSetSpnego = { .count = 1, .elements = &GSS_SPNEGO_MECHANISM };
    gss_OID_set_desc mechSetKrb5 = { .count = 1, .elements = &GSS_KRB5_MECHANISM };

    majorStatus = gss_acquire_cred(&minorStatus,
                                   GSS_C_NO_NAME, // TODO: This is bad. We need to inherit the username of the kinit'd ticket if present.
                                   0,
                                   &mechSetKrb5,
                                   GSS_C_INITIATE,
                                   clientCredential,
                                   NULL,
                                   NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_acquire_cred", majorStatus, minorStatus);
        return 0;
    }

    return 1;
}

uint32_t CreateClientCredential(char* userName, char* password, uint32_t isNtlm, gss_cred_id_t* clientCredential)
{
    *clientCredential = GSS_C_NO_CREDENTIAL;

    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;
    gss_buffer_desc gssBuffer = { 0 };

    gssBuffer.length = strlen(userName);
    gssBuffer.value = userName;
    gss_name_t gssUserName = NULL;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_C_NT_USER_NAME, &gssUserName);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_import_name", majorStatus, minorStatus);
        return 0;
    }

    gss_OID_set_desc mechSetNtlm = { .count = 1, .elements = &GSS_NTLM_MECHANISM };
    gss_OID_set_desc mechSetSpnego = { .count = 1, .elements = &GSS_SPNEGO_MECHANISM };
    gssBuffer.length = strlen(password);
    gssBuffer.value = password;

    majorStatus = gss_acquire_cred_with_password(&minorStatus,
                                                 gssUserName,
                                                 &gssBuffer,
                                                 GSS_C_INDEFINITE,
                                                 isNtlm ? &mechSetNtlm : &mechSetSpnego,
                                                 GSS_C_INITIATE,
                                                 clientCredential,
                                                 NULL,
                                                 NULL);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_acquire_cred_with_password", majorStatus, minorStatus);
        return 0;
    }

    return 1;
}

char* ConvertToHostBasedServiceFormat(char * spn)
{
    // Principal name will usually be in the form SERVICE/HOST which is GSS_KRB5_NT_PRINCIPAL_NAME format.
    // But SPNEGO protocol prefers GSS_C_NT_HOSTBASED_SERVICE format. That format uses '@' separator instead
    // of '/' between service name and host name. So convert input string into that format.
    size_t length = strlen(spn);
    char* ptrSlash = memchr(spn, '/', length);
    char* spnCopy = NULL;
    if (ptrSlash != NULL)
    {
        spnCopy = (char*) malloc(length + 1);
        if (spnCopy != NULL)
        {
            memcpy(spnCopy, spn, length);
            spnCopy[ptrSlash - spn] = '@';
            spnCopy[length] = '\0';
        }
    }

    return spnCopy;
}

uint32_t CreateNameObject(char* name, gss_OID type, gss_name_t* gssName)
{
    *gssName = GSS_C_NO_NAME;

    uint32_t majorStatus = 0;
    uint32_t minorStatus = 0;

    gss_buffer_desc gssBuffer = { .length = strlen(name), .value = name };
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, type, gssName);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus("gss_import_name", majorStatus, minorStatus);
        return 0;
    }

    return 1;
}
