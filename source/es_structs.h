#pragma once
#include "common.h"

typedef enum SignatureType: uint32_t {
    SIG_RSA4096_SHA1 = 0x00010000,
    SIG_RSA2048_SHA1 = 0x00010001,
    SIG_ECC233_SHA1  = 0x00010002,
} SignatureType;

typedef enum KeyType: uint32_t {
    KEY_RSA2048 = 0x00000001,
    KEY_ECC233  = 0x00000002,
} KeyType;

typedef struct {
    SignatureType   type;
    uint8_t         signature[0x200];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureRSA4096;
CHECK_STRUCT_SIZE(SignatureRSA4096, 0x280);

typedef struct {
    SignatureType   type;
    uint8_t         signature[0x100];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureRSA2048;
CHECK_STRUCT_SIZE(SignatureRSA2048, 0x180);

typedef struct {
    SignatureType   type;
    uint8_t         r[30], s[30];
    uint8_t         padding[0x40];
    char            issuer[0x40] __attribute__((aligned(0x40)));
} SignatureECC;
CHECK_STRUCT_SIZE(SignatureECC, 0xC0);

typedef struct {
    KeyType  type;
    char     name[0x40];
    uint32_t keyid;
} CertHeader;

typedef struct {
    uint8_t modulus[0x100];
    uint8_t exponent[4];
} KeyRSA2048;

typedef struct {
    uint8_t x[30], y[30];
} KeyECC;

typedef struct {
    SignatureRSA4096 signature;
    CertHeader       header;
    KeyRSA2048       key;
} CertRSA4096RSA2048, CACert;
CHECK_STRUCT_SIZE(CertRSA4096RSA2048, 0x400);

typedef struct {
    SignatureRSA2048 signature;
    CertHeader       header;
    KeyRSA2048       key;
} CertRSA2048RSA2048, SignerCert, CPCert, XSCert;
CHECK_STRUCT_SIZE(CertRSA2048RSA2048, 0x300);

typedef struct {
    SignatureRSA2048 signature;
    CertHeader       header;
    KeyECC           key;
} CertRSA2048ECC, MSCert;
CHECK_STRUCT_SIZE(CertRSA2048ECC, 0x240);

typedef struct {
    SignatureECC signature;
    CertHeader   header;
    KeyECC       key;
} CertECC, NGCert, DeviceCert, APCert;
CHECK_STRUCT_SIZE(CertECC, 0x180);

typedef struct {
    uint32_t type;
    uint32_t max;
} TicketLimit;

typedef struct {
    SignatureRSA2048 signature;
    KeyECC   ecdh_public_key;
    uint8_t  verison;
    uint8_t  reserved[2];
    uint8_t  title_key[16];
    uint8_t  padding;
    uint64_t ticket_id;
    uint32_t console_id;
    uint64_t title_id;
    uint8_t  access_mask[2];
    uint8_t  padding2[2];
    uint32_t permitted_title_mask;
    uint32_t permitted_title;
    uint8_t  reserved2;
    uint8_t  common_key_index;
    uint8_t  reserved3[0x2F];
    uint8_t  reserved4;
    uint8_t  content_access_permissions[0x40];
    uint8_t  padding3[2];
    TicketLimit limits[8];
} __attribute__((packed, aligned(4))) Ticket;
CHECK_STRUCT_SIZE(Ticket, 0x2A4);

typedef struct {
    uint32_t cid;
    uint16_t index;
    uint16_t type;
    uint64_t size;
    uint8_t  hash[20];
} __attribute__((packed)) TitleMetadataContent, TMDContent;
CHECK_STRUCT_SIZE(TitleMetadataContent, 0x24);

typedef struct {
    SignatureRSA2048 signature;
    uint8_t  version;
    uint8_t  reserved[2];
    uint8_t  vwii_title;
    uint64_t sys_version;
    uint64_t title_id;
    uint32_t title_type;
    uint16_t group_id;
    uint8_t  reserved2[2];
    uint16_t region;
    uint8_t  ratings[16];
    uint8_t  reserved3[12];
    uint8_t  ipc_mask[12];
    uint8_t  reserved4[18];
    uint32_t access_rights;
    uint16_t title_version;
    uint16_t num_contents;
    uint16_t boot_index;
    uint16_t minor_version;
    TitleMetadataContent contents[];
} __attribute__((packed)) TitleMetadata, TMD;
CHECK_STRUCT_SIZE(TitleMetadata, 0x1E4);
#define S_TMD_SIZE(x) (offsetof(TitleMetadata, contents[((TitleMetadata *)(x))->num_contents]))

/*
MSCert MS00000002 = {
    .signature = {
        .type = 0x00010001,
        .signature =
        {   0x5c, 0x92, 0x59, 0x18, 0xb7, 0x0a, 0x82, 0x01, 0x7e, 0xe0, 0x2c, 0x7e, 0x45, 0x38, 0x1a, 0x4f,
            0x9c, 0x13, 0x0f, 0x65, 0x5b, 0xaa, 0xdf, 0xf7, 0xae, 0xe5, 0xf5, 0xba, 0xb9, 0xfc, 0x47, 0xfc,
            0x09, 0x94, 0x1e, 0xc9, 0x56, 0x2b, 0x82, 0xe1, 0x76, 0x41, 0x7e, 0xa7, 0xcd, 0xed, 0x33, 0x63,
            0xbd, 0xc1, 0xac, 0x2a, 0x90, 0xc2, 0x5d, 0x61, 0x8e, 0xe1, 0x52, 0x97, 0x53, 0x3e, 0xf3, 0xf4,
            0x1e, 0xaa, 0x29, 0x07, 0x76, 0x3e, 0xac, 0xda, 0x16, 0x14, 0x68, 0xc2, 0xd4, 0x70, 0xcc, 0xd6,
            0x07, 0xf4, 0x02, 0xa2, 0x6e, 0xe4, 0xed, 0x17, 0x56, 0xeb, 0x62, 0x70, 0xd9, 0xff, 0x56, 0x77,
            0xb7, 0x82, 0x7f, 0x0f, 0xea, 0x00, 0x04, 0xc8, 0xa3, 0x96, 0x59, 0x7a, 0x9b, 0x42, 0xc0, 0x02,
            0x59, 0x8c, 0xce, 0x87, 0x3c, 0x71, 0x78, 0x26, 0x0e, 0xc3, 0x8f, 0x49, 0x0f, 0x08, 0xd1, 0xe7,
            0x9b, 0xac, 0x8e, 0x0d, 0x0c, 0xae, 0x0f, 0x55, 0xe1, 0x0a, 0xa9, 0x77, 0x53, 0xbe, 0x2b, 0x7c,
            0x1b, 0xbb, 0xfc, 0xec, 0x6b, 0x55, 0x4e, 0x8f, 0xe7, 0xeb, 0x73, 0x24, 0xb1, 0x9a, 0x56, 0xbe,
            0x32, 0x58, 0x08, 0xe4, 0x01, 0xd6, 0x48, 0x1a, 0x14, 0x34, 0x85, 0x2b, 0x3c, 0x43, 0x6e, 0x3f,
            0xc6, 0x63, 0xbb, 0x68, 0xa5, 0xc9, 0xeb, 0xb5, 0x8a, 0xa1, 0xe3, 0x86, 0x50, 0x6c, 0xf2, 0x37,
            0x2e, 0xea, 0xd9, 0xba, 0x28, 0x05, 0xb4, 0xfe, 0xef, 0xab, 0xcd, 0x7e, 0xc6, 0x29, 0x82, 0xf7,
            0x7d, 0x6f, 0x8e, 0x7f, 0xe5, 0x60, 0x1a, 0x9f, 0x2f, 0x5f, 0xaa, 0x65, 0xdf, 0x34, 0x0f, 0xf8,
            0x78, 0x0c, 0xfc, 0xb2, 0x77, 0x55, 0x4b, 0x07, 0x30, 0xe5, 0xb8, 0xaa, 0xf5, 0xdd, 0xf4, 0x8e,
            0x61, 0xce, 0x1b, 0x21, 0x41, 0xe3, 0xa5, 0xd1, 0xc8, 0xb3, 0x67, 0x50, 0x7d, 0x61, 0x7b, 0xf9  },
        .issuer = "Root-CA00000001"
    },
    .header = {
        .type = 0x00000002,
        .name = "MS00000002",
        .keyid = 0xF2A1F812,
    },
    .key = {
        .x = {  0x00, 0xfd, 0x56, 0x04, 0x18, 0x2c, 0xf1, 0x75, 0x09, 0x21, 0x00, 0xc3, 0x08, 0xae, 0x48,
                0x39, 0x91, 0x1b, 0x6f, 0x9f, 0xa1, 0xd5, 0x3a, 0x95, 0xaf, 0x08, 0x33, 0x49, 0x47, 0x2b },
        .y = {  0x00, 0x01, 0x71, 0x31, 0x69, 0xb5, 0x91, 0xff, 0xd3, 0x0c, 0xbf, 0x73, 0xda, 0x76, 0x64,
                0xba, 0x8d, 0x0d, 0xf9, 0x5b, 0x4d, 0x11, 0x04, 0x44, 0x64, 0x35, 0xc0, 0xed, 0xa4, 0x2f },
    }
};
*/
