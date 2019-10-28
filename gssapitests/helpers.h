#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#define PASS 1
#define FAIL 0

// 1.2.840.48018.1.2.2 (MS KRB5 - Microsoft Kerberos 5)
static gss_OID_desc GSS_MSKRB5_MECHANISM = { .length = 9, .elements = "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02" };

// 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5)
static gss_OID_desc GSS_KRB5_MECHANISM = { .length = 9, .elements = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02" };

// 1.3.6.1.5.2.5  (Legacy Kerberos 5)
static gss_OID_desc GSS_KRB5_LEGACY_MECHANISM = { .length = 6, .elements = "\x2b\x06\x01\x05\x02\x05" };

// 1.3.6.1.5.5.2 (SPNEGO - Simple Protected Negotiation)
// RFC 4178
static gss_OID_desc GSS_SPNEGO_MECHANISM = { .length = 6, .elements = "\x2b\x06\x01\x05\x05\x02" };

// 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)
// https://msdn.microsoft.com/en-us/library/cc236636.aspx
static gss_OID_desc GSS_NTLM_MECHANISM = { .length = 10, .elements = "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" };

typedef struct _mechitem
{
    gss_OID oid;
    char* oidDescription;
} MechItem;

static MechItem MechList[] = 
{
    { &GSS_MSKRB5_MECHANISM, "MS KRB5 - Microsoft Kerberos 5 (1.2.840.48018.1.2.2)" },
    { &GSS_KRB5_MECHANISM, "KRB5 - Kerberos 5 (1.2.840.113554.1.2.2)" },
    { &GSS_KRB5_LEGACY_MECHANISM, "Legacy Kerberos 5 (1.3.6.1.5.2.5)" },
    { &GSS_SPNEGO_MECHANISM, "SPNEGO - Simple Protected Negotiation (1.3.6.1.5.5.2)" },
    { &GSS_NTLM_MECHANISM, "NTLMSSP - Microsoft NTLM Security Support Provider (1.3.6.1.4.1.311.2.2.10)" }
};

void DisplayStatus(char* title, uint32_t majorError, uint32_t minorError);
uint32_t IsNtlmInstalled();
void PrintMechanism(gss_OID oid);
void PrintMechanisms();
void PrintContext(gss_ctx_id_t context);
uint32_t CreateClientCredential(char* userName, char* password, uint32_t isNtlm, gss_cred_id_t* clientCredential);
uint32_t CreateClientDefaultCredential(gss_cred_id_t* clientCredential);
char* ConvertToHostBasedServiceFormat(char * spn);
uint32_t CreateNameObject(char* name, gss_OID type, gss_name_t* gssName);
