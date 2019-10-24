#pragma once

#include <stdlib.h>
#include <stdint.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define PASS 1
#define FAIL 0

typedef struct _mechitem
{
    char* oidValue;
    size_t oidLength;
    char* oidDescription;
} MechItem;

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

static MechItem MechList[] = 
{
    { gss_mskrb5_oid_value, ARRAY_SIZE(gss_mskrb5_oid_value) - 1, "MS KRB5 - Microsoft Kerberos 5 (1.2.840.48018.1.2.2)" },
    { gss_krb5_oid_value, ARRAY_SIZE(gss_krb5_oid_value) - 1, "KRB5 - Kerberos 5 (1.2.840.113554.1.2.2)" },
    { gss_krb5legacy_oid_value, ARRAY_SIZE(gss_krb5legacy_oid_value) - 1, "Legacy Kerberos 5 (1.3.6.1.5.2.5)" },
    { gss_spnego_oid_value, ARRAY_SIZE(gss_spnego_oid_value) - 1, "SPNEGO - Simple Protected Negotiation (1.3.6.1.5.5.2)" },
    { gss_ntlm_oid_value, ARRAY_SIZE(gss_ntlm_oid_value) - 1, "NTLMSSP - Microsoft NTLM Security Support Provider (1.3.6.1.4.1.311.2.2.10)" }
};

void DisplayStatus(uint32_t majorError, uint32_t minorError);
uint32_t IsNtlmInstalled();
void PrintMechanisms();
void PrintContext(gss_ctx_id_t context);
uint32_t CreateClientCredential(char* userName, char* password, gss_cred_id_t* clientCredential);
