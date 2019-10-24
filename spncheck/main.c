#include <stdlib.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <string.h>
#include <stdio.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
static char gss_mskrb5_oid_value[] = "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02";

// 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
static char gss_krb5_oid_value[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";

// 1.3.6.1.5.2.5  (Legacy Kerberos 5)
static char gss_krb5legacy_oid_value[] = "\x2b\x06\x01\x05\x02\x05";

// 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation)
// RFC 4178
static char gss_spnego_oid_value[] = "\x2b\x06\x01\x05\x05\x02";

// 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
// https://msdn.microsoft.com/en-us/library/cc236636.aspx
static char gss_ntlm_oid_value[] = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";

typedef struct _mechitem {
    char* oidValue;
    size_t oidLength;
    char* oidDescription;
} MechItem;

static MechItem MechList[] = 
{
    { gss_mskrb5_oid_value, ARRAY_SIZE(gss_mskrb5_oid_value) - 1, "MS KRB5 - Microsoft Kerberos 5 (1.2.840.48018.1.2.2)" },
    { gss_krb5_oid_value, ARRAY_SIZE(gss_krb5_oid_value) - 1, "KRB5 - Kerberos 5 (1.2.840.113554.1.2.2)" },
    { gss_krb5legacy_oid_value, ARRAY_SIZE(gss_krb5legacy_oid_value) - 1, "Legacy Kerberos 5 (1.3.6.1.5.2.5)" },
    { gss_spnego_oid_value, ARRAY_SIZE(gss_spnego_oid_value) - 1, "SPNEGO - Simple Protected Negotiation (1.3.6.1.5.5.2)" },
    { gss_ntlm_oid_value, ARRAY_SIZE(gss_ntlm_oid_value) - 1, "NTLMSSP - Microsoft NTLM Security Support Provider (1.3.6.1.4.1.311.2.2.10)" }
};


void DisplayStatus(uint32_t majorError, uint32_t minorError)
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
        printf("  \"%.*s", (int)majorErrorBuffer.length, (char *)majorErrorBuffer.value);
        majorStatus = gss_release_buffer(&minorStatus, &majorErrorBuffer);        
    }

    if (minorError != GSS_S_COMPLETE)
    {
        majorStatus = gss_display_status(&minorStatus, minorError, GSS_C_MECH_CODE, GSS_C_NO_OID, &minorMessageContext, &minorErrorBuffer);
        if (majorStatus == GSS_S_COMPLETE)
        {        
            printf(" %.*s", (int)minorErrorBuffer.length, (char *)minorErrorBuffer.value);
            majorStatus = gss_release_buffer(&minorStatus, &minorErrorBuffer);        
        }
    }

    printf("\"\n");
}

void PrintMechanism(char* oidValue, size_t oidLength)
{
    for (int i = 0; i < ARRAY_SIZE(MechList); i++)
    {
        if ((oidLength == MechList[i].oidLength) && (memcmp(oidValue, MechList[i].oidValue, oidLength) == 0))
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
        gss_OID_desc oid = mechSet->elements[i];
        PrintMechanism(oid.elements, oid.length);
    }

    printf("\n");

    // TODO: Release mechSet
}

void TestInitSecContext(gss_name_t targetName)
{
    uint32_t reqFlags = 0; // TODO?
    uint32_t retFlags;
    uint32_t majorStatus;
    uint32_t minorStatus;

    gss_buffer_desc inputToken = {.length = 0, .value = NULL};
    gss_buffer_desc outputToken = {.length = 0, .value = NULL};
    gss_OID_desc* outmech;
    gss_OID_desc oidSpnego = {.length = ARRAY_SIZE(gss_spnego_oid_value) - 1, .elements = gss_spnego_oid_value};
    gss_ctx_id_t contextHandle = GSS_C_NO_CONTEXT;

    majorStatus = gss_init_sec_context(&minorStatus,
                                       GSS_C_NO_CREDENTIAL,
                                       &contextHandle,
                                       targetName,
                                       &oidSpnego,
                                       reqFlags,
                                       0,
                                       GSS_C_NO_CHANNEL_BINDINGS,
                                       &inputToken,
                                       &outmech,
                                       &outputToken,
                                       &retFlags,
                                       NULL);
    if (majorStatus == GSS_S_CONTINUE_NEEDED)
    {
        majorStatus = gss_delete_sec_context(&minorStatus, &contextHandle, GSS_C_NO_BUFFER);                                     
        if (majorStatus != GSS_S_COMPLETE) DisplayStatus(majorStatus, minorStatus);
    }
    else
    {
        DisplayStatus(majorStatus, minorStatus);
    }
}

void TestSpn(char* spn)
{
    // Input principal name will be in the form SERVICE/HOST. But SPNEGO protocol prefers
    // GSS_C_NT_HOSTBASED_SERVICE format. That format uses '@' separator instead of '/' between
    // service name and host name. So convert input string into that format.
    int len = strlen(spn);
    char* ptrSlash = memchr(spn, '/', len);
    char* spnNt = (char*) malloc(len) + 1;

    memcpy(spnNt, spn, len);
    spnNt[ptrSlash - spn] = '@';
    spnNt[len] = '\0';

    gss_name_t gssNameSpn = NULL;
    gss_name_t gssNameSpnNt = NULL;

    uint32_t majorStatus;
    uint32_t minorStatus;
    gss_buffer_desc gssBuffer = {.length = len, .value = spn};
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_KRB5_NT_PRINCIPAL_NAME, &gssNameSpn);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return;
    }

    gssBuffer.value = spnNt;
    majorStatus = gss_import_name(&minorStatus, &gssBuffer, GSS_C_NT_HOSTBASED_SERVICE, &gssNameSpnNt);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return;
    }

    printf("Testing SPN using GSS_KRB5_NT_PRINCIPAL_NAME format: %s\n", spn);
    TestInitSecContext(gssNameSpn);
    majorStatus = gss_release_name(&minorStatus, &gssNameSpn);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return;
    }

    printf("\n");

    printf("Testing SPN using GSS_C_NT_HOSTBASED_SERVICE format: %s\n", spnNt);
    TestInitSecContext(gssNameSpnNt);
    majorStatus = gss_release_name(&minorStatus, &gssNameSpnNt);
    if (majorStatus != GSS_S_COMPLETE)
    {
        DisplayStatus(majorStatus, minorStatus);
        return;
    }    
}

int main(int argc, char *argv[])
{
    char* spn = NULL;

    if (argc > 1)
    {
        spn = argv[1];
        int len = strlen(spn);

        // Validate format.
        char* ptrSlash = memchr(spn, '/', len);
        char* ptrAt = memchr(spn, '@', len);
        if (ptrSlash == NULL || ptrAt != NULL)
        {
            printf("ERROR: SPN format should be SERVICE/HOST\n");
            return 1;
        }
    }
    else
    {
        printf("Usage: spncheck SPN\n");
        printf("  example: 'spncheck HTTP/webserver.contoso.com'\n");
        printf("\n");
    }

    PrintMechanisms();

    if (spn != NULL)
    {
        putenv("KRB5_TRACE=/dev/stdout");
        TestSpn(spn);
    }

    return 0;
}
