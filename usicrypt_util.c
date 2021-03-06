/*
 * usicrypt, a unified simple interface crypto library wrapper
 *
 * (c) 2017 Andreas Steinmetz
 *
 * Any OSI approved license of your choice applies, see the file LICENSE
 * for details.
 *
 */

/******************************************************************************/
/*                                 Testing                                    */
/******************************************************************************/

#ifdef USICRYPT_TEST
#undef USICRYPT_TEST
#ifndef USICRYPT_UTIL
#define USICRYPT_UTIL
#endif
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#include "usicrypt_internal.h"
#include "usicrypt.h"

/******************************************************************************/
/*                              Utility Functions                             */
/******************************************************************************/

struct util_lfsr
{
	int mode;
	int bytes;
	union
	{
		unsigned int p32;
		unsigned long long p64;
	} poly;
	union
	{
		unsigned int v32;
		unsigned long long v64;
		unsigned long long v128[2];
	} value;
};

static const struct
{
	const int mode;
	const unsigned long long poly;
} util_lfsr[16]=
{
	{0,0x00000000000000d4ULL},
	{0,0x000000000000fc00ULL},
	{0,0x0000000000e10000ULL},
	{0,0x00000000f5000000ULL},
	{1,0x000000eb00000000ULL},
	{1,0x0000ed0000000000ULL},
	{1,0x00d9800000000000ULL},
	{1,0xd800000000000000ULL},
	{2,0x00000000000000faULL},
	{2,0x000000000000f500ULL},
	{2,0x0000000000dc8000ULL},
	{2,0x00000000fe800000ULL},
	{2,0x000000fa60000000ULL},
	{2,0x0000f28000000000ULL},
	{2,0x00f0a00000000000ULL},
	{2,0xe100000000000000ULL}
};

#ifndef USICRYPT_NO_RSA

static const char util_rsap8hdr[19]=
{
	0x02,0x01,0x00,0x30,0x0d,0x06,0x09,0x2a,
	0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
	0x05,0x00,0x04
};

#endif
#ifndef USICRYPT_NO_DH

static const unsigned char usicrypt_dh_1024_160[268]=
{
	0x30,0x82,0x01,0x08,0x02,0x81,0x81,0x00,
	0xb1,0x0b,0x8f,0x96,0xa0,0x80,0xe0,0x1d,
	0xde,0x92,0xde,0x5e,0xae,0x5d,0x54,0xec,
	0x52,0xc9,0x9f,0xbc,0xfb,0x06,0xa3,0xc6,
	0x9a,0x6a,0x9d,0xca,0x52,0xd2,0x3b,0x61,
	0x60,0x73,0xe2,0x86,0x75,0xa2,0x3d,0x18,
	0x98,0x38,0xef,0x1e,0x2e,0xe6,0x52,0xc0,
	0x13,0xec,0xb4,0xae,0xa9,0x06,0x11,0x23,
	0x24,0x97,0x5c,0x3c,0xd4,0x9b,0x83,0xbf,
	0xac,0xcb,0xdd,0x7d,0x90,0xc4,0xbd,0x70,
	0x98,0x48,0x8e,0x9c,0x21,0x9a,0x73,0x72,
	0x4e,0xff,0xd6,0xfa,0xe5,0x64,0x47,0x38,
	0xfa,0xa3,0x1a,0x4f,0xf5,0x5b,0xcc,0xc0,
	0xa1,0x51,0xaf,0x5f,0x0d,0xc8,0xb4,0xbd,
	0x45,0xbf,0x37,0xdf,0x36,0x5c,0x1a,0x65,
	0xe6,0x8c,0xfd,0xa7,0x6d,0x4d,0xa7,0x08,
	0xdf,0x1f,0xb2,0xbc,0x2e,0x4a,0x43,0x71,
	0x02,0x81,0x81,0x00,0xa4,0xd1,0xcb,0xd5,
	0xc3,0xfd,0x34,0x12,0x67,0x65,0xa4,0x42,
	0xef,0xb9,0x99,0x05,0xf8,0x10,0x4d,0xd2,
	0x58,0xac,0x50,0x7f,0xd6,0x40,0x6c,0xff,
	0x14,0x26,0x6d,0x31,0x26,0x6f,0xea,0x1e,
	0x5c,0x41,0x56,0x4b,0x77,0x7e,0x69,0x0f,
	0x55,0x04,0xf2,0x13,0x16,0x02,0x17,0xb4,
	0xb0,0x1b,0x88,0x6a,0x5e,0x91,0x54,0x7f,
	0x9e,0x27,0x49,0xf4,0xd7,0xfb,0xd7,0xd3,
	0xb9,0xa9,0x2e,0xe1,0x90,0x9d,0x0d,0x22,
	0x63,0xf8,0x0a,0x76,0xa6,0xa2,0x4c,0x08,
	0x7a,0x09,0x1f,0x53,0x1d,0xbf,0x0a,0x01,
	0x69,0xb6,0xa2,0x8a,0xd6,0x62,0xa4,0xd1,
	0x8e,0x73,0xaf,0xa3,0x2d,0x77,0x9d,0x59,
	0x18,0xd0,0x8b,0xc8,0x85,0x8f,0x4d,0xce,
	0xf9,0x7c,0x2a,0x24,0x85,0x5e,0x6e,0xeb,
	0x22,0xb3,0xb2,0xe5
};

static const unsigned char usicrypt_dh_2048_224[526]=
{
	0x30,0x82,0x02,0x0a,0x02,0x82,0x01,0x01,
	0x00,0xad,0x10,0x7e,0x1e,0x91,0x23,0xa9,
	0xd0,0xd6,0x60,0xfa,0xa7,0x95,0x59,0xc5,
	0x1f,0xa2,0x0d,0x64,0xe5,0x68,0x3b,0x9f,
	0xd1,0xb5,0x4b,0x15,0x97,0xb6,0x1d,0x0a,
	0x75,0xe6,0xfa,0x14,0x1d,0xf9,0x5a,0x56,
	0xdb,0xaf,0x9a,0x3c,0x40,0x7b,0xa1,0xdf,
	0x15,0xeb,0x3d,0x68,0x8a,0x30,0x9c,0x18,
	0x0e,0x1d,0xe6,0xb8,0x5a,0x12,0x74,0xa0,
	0xa6,0x6d,0x3f,0x81,0x52,0xad,0x6a,0xc2,
	0x12,0x90,0x37,0xc9,0xed,0xef,0xda,0x4d,
	0xf8,0xd9,0x1e,0x8f,0xef,0x55,0xb7,0x39,
	0x4b,0x7a,0xd5,0xb7,0xd0,0xb6,0xc1,0x22,
	0x07,0xc9,0xf9,0x8d,0x11,0xed,0x34,0xdb,
	0xf6,0xc6,0xba,0x0b,0x2c,0x8b,0xbc,0x27,
	0xbe,0x6a,0x00,0xe0,0xa0,0xb9,0xc4,0x97,
	0x08,0xb3,0xbf,0x8a,0x31,0x70,0x91,0x88,
	0x36,0x81,0x28,0x61,0x30,0xbc,0x89,0x85,
	0xdb,0x16,0x02,0xe7,0x14,0x41,0x5d,0x93,
	0x30,0x27,0x82,0x73,0xc7,0xde,0x31,0xef,
	0xdc,0x73,0x10,0xf7,0x12,0x1f,0xd5,0xa0,
	0x74,0x15,0x98,0x7d,0x9a,0xdc,0x0a,0x48,
	0x6d,0xcd,0xf9,0x3a,0xcc,0x44,0x32,0x83,
	0x87,0x31,0x5d,0x75,0xe1,0x98,0xc6,0x41,
	0xa4,0x80,0xcd,0x86,0xa1,0xb9,0xe5,0x87,
	0xe8,0xbe,0x60,0xe6,0x9c,0xc9,0x28,0xb2,
	0xb9,0xc5,0x21,0x72,0xe4,0x13,0x04,0x2e,
	0x9b,0x23,0xf1,0x0b,0x0e,0x16,0xe7,0x97,
	0x63,0xc9,0xb5,0x3d,0xcf,0x4b,0xa8,0x0a,
	0x29,0xe3,0xfb,0x73,0xc1,0x6b,0x8e,0x75,
	0xb9,0x7e,0xf3,0x63,0xe2,0xff,0xa3,0x1f,
	0x71,0xcf,0x9d,0xe5,0x38,0x4e,0x71,0xb8,
	0x1c,0x0a,0xc4,0xdf,0xfe,0x0c,0x10,0xe6,
	0x4f,0x02,0x82,0x01,0x01,0x00,0xac,0x40,
	0x32,0xef,0x4f,0x2d,0x9a,0xe3,0x9d,0xf3,
	0x0b,0x5c,0x8f,0xfd,0xac,0x50,0x6c,0xde,
	0xbe,0x7b,0x89,0x99,0x8c,0xaf,0x74,0x86,
	0x6a,0x08,0xcf,0xe4,0xff,0xe3,0xa6,0x82,
	0x4a,0x4e,0x10,0xb9,0xa6,0xf0,0xdd,0x92,
	0x1f,0x01,0xa7,0x0c,0x4a,0xfa,0xab,0x73,
	0x9d,0x77,0x00,0xc2,0x9f,0x52,0xc5,0x7d,
	0xb1,0x7c,0x62,0x0a,0x86,0x52,0xbe,0x5e,
	0x90,0x01,0xa8,0xd6,0x6a,0xd7,0xc1,0x76,
	0x69,0x10,0x19,0x99,0x02,0x4a,0xf4,0xd0,
	0x27,0x27,0x5a,0xc1,0x34,0x8b,0xb8,0xa7,
	0x62,0xd0,0x52,0x1b,0xc9,0x8a,0xe2,0x47,
	0x15,0x04,0x22,0xea,0x1e,0xd4,0x09,0x93,
	0x9d,0x54,0xda,0x74,0x60,0xcd,0xb5,0xf6,
	0xc6,0xb2,0x50,0x71,0x7c,0xbe,0xf1,0x80,
	0xeb,0x34,0x11,0x8e,0x98,0xd1,0x19,0x52,
	0x9a,0x45,0xd6,0xf8,0x34,0x56,0x6e,0x30,
	0x25,0xe3,0x16,0xa3,0x30,0xef,0xbb,0x77,
	0xa8,0x6f,0x0c,0x1a,0xb1,0x5b,0x05,0x1a,
	0xe3,0xd4,0x28,0xc8,0xf8,0xac,0xb7,0x0a,
	0x81,0x37,0x15,0x0b,0x8e,0xeb,0x10,0xe1,
	0x83,0xed,0xd1,0x99,0x63,0xdd,0xd9,0xe2,
	0x63,0xe4,0x77,0x05,0x89,0xef,0x6a,0xa2,
	0x1e,0x7f,0x5f,0x2f,0xf3,0x81,0xb5,0x39,
	0xcc,0xe3,0x40,0x9d,0x13,0xcd,0x56,0x6a,
	0xfb,0xb4,0x8d,0x6c,0x01,0x91,0x81,0xe1,
	0xbc,0xfe,0x94,0xb3,0x02,0x69,0xed,0xfe,
	0x72,0xfe,0x9b,0x6a,0xa4,0xbd,0x7b,0x5a,
	0x0f,0x1c,0x71,0xcf,0xff,0x4c,0x19,0xc4,
	0x18,0xe1,0xf6,0xec,0x01,0x79,0x81,0xbc,
	0x08,0x7f,0x2a,0x70,0x65,0xb3,0x84,0xb8,
	0x90,0xd3,0x19,0x1f,0x2b,0xfa
};

static const unsigned char usicrypt_dh_2048_256[526]=
{
	0x30,0x82,0x02,0x0a,0x02,0x82,0x01,0x01,
	0x00,0x87,0xa8,0xe6,0x1d,0xb4,0xb6,0x66,
	0x3c,0xff,0xbb,0xd1,0x9c,0x65,0x19,0x59,
	0x99,0x8c,0xee,0xf6,0x08,0x66,0x0d,0xd0,
	0xf2,0x5d,0x2c,0xee,0xd4,0x43,0x5e,0x3b,
	0x00,0xe0,0x0d,0xf8,0xf1,0xd6,0x19,0x57,
	0xd4,0xfa,0xf7,0xdf,0x45,0x61,0xb2,0xaa,
	0x30,0x16,0xc3,0xd9,0x11,0x34,0x09,0x6f,
	0xaa,0x3b,0xf4,0x29,0x6d,0x83,0x0e,0x9a,
	0x7c,0x20,0x9e,0x0c,0x64,0x97,0x51,0x7a,
	0xbd,0x5a,0x8a,0x9d,0x30,0x6b,0xcf,0x67,
	0xed,0x91,0xf9,0xe6,0x72,0x5b,0x47,0x58,
	0xc0,0x22,0xe0,0xb1,0xef,0x42,0x75,0xbf,
	0x7b,0x6c,0x5b,0xfc,0x11,0xd4,0x5f,0x90,
	0x88,0xb9,0x41,0xf5,0x4e,0xb1,0xe5,0x9b,
	0xb8,0xbc,0x39,0xa0,0xbf,0x12,0x30,0x7f,
	0x5c,0x4f,0xdb,0x70,0xc5,0x81,0xb2,0x3f,
	0x76,0xb6,0x3a,0xca,0xe1,0xca,0xa6,0xb7,
	0x90,0x2d,0x52,0x52,0x67,0x35,0x48,0x8a,
	0x0e,0xf1,0x3c,0x6d,0x9a,0x51,0xbf,0xa4,
	0xab,0x3a,0xd8,0x34,0x77,0x96,0x52,0x4d,
	0x8e,0xf6,0xa1,0x67,0xb5,0xa4,0x18,0x25,
	0xd9,0x67,0xe1,0x44,0xe5,0x14,0x05,0x64,
	0x25,0x1c,0xca,0xcb,0x83,0xe6,0xb4,0x86,
	0xf6,0xb3,0xca,0x3f,0x79,0x71,0x50,0x60,
	0x26,0xc0,0xb8,0x57,0xf6,0x89,0x96,0x28,
	0x56,0xde,0xd4,0x01,0x0a,0xbd,0x0b,0xe6,
	0x21,0xc3,0xa3,0x96,0x0a,0x54,0xe7,0x10,
	0xc3,0x75,0xf2,0x63,0x75,0xd7,0x01,0x41,
	0x03,0xa4,0xb5,0x43,0x30,0xc1,0x98,0xaf,
	0x12,0x61,0x16,0xd2,0x27,0x6e,0x11,0x71,
	0x5f,0x69,0x38,0x77,0xfa,0xd7,0xef,0x09,
	0xca,0xdb,0x09,0x4a,0xe9,0x1e,0x1a,0x15,
	0x97,0x02,0x82,0x01,0x01,0x00,0x3f,0xb3,
	0x2c,0x9b,0x73,0x13,0x4d,0x0b,0x2e,0x77,
	0x50,0x66,0x60,0xed,0xbd,0x48,0x4c,0xa7,
	0xb1,0x8f,0x21,0xef,0x20,0x54,0x07,0xf4,
	0x79,0x3a,0x1a,0x0b,0xa1,0x25,0x10,0xdb,
	0xc1,0x50,0x77,0xbe,0x46,0x3f,0xff,0x4f,
	0xed,0x4a,0xac,0x0b,0xb5,0x55,0xbe,0x3a,
	0x6c,0x1b,0x0c,0x6b,0x47,0xb1,0xbc,0x37,
	0x73,0xbf,0x7e,0x8c,0x6f,0x62,0x90,0x12,
	0x28,0xf8,0xc2,0x8c,0xbb,0x18,0xa5,0x5a,
	0xe3,0x13,0x41,0x00,0x0a,0x65,0x01,0x96,
	0xf9,0x31,0xc7,0x7a,0x57,0xf2,0xdd,0xf4,
	0x63,0xe5,0xe9,0xec,0x14,0x4b,0x77,0x7d,
	0xe6,0x2a,0xaa,0xb8,0xa8,0x62,0x8a,0xc3,
	0x76,0xd2,0x82,0xd6,0xed,0x38,0x64,0xe6,
	0x79,0x82,0x42,0x8e,0xbc,0x83,0x1d,0x14,
	0x34,0x8f,0x6f,0x2f,0x91,0x93,0xb5,0x04,
	0x5a,0xf2,0x76,0x71,0x64,0xe1,0xdf,0xc9,
	0x67,0xc1,0xfb,0x3f,0x2e,0x55,0xa4,0xbd,
	0x1b,0xff,0xe8,0x3b,0x9c,0x80,0xd0,0x52,
	0xb9,0x85,0xd1,0x82,0xea,0x0a,0xdb,0x2a,
	0x3b,0x73,0x13,0xd3,0xfe,0x14,0xc8,0x48,
	0x4b,0x1e,0x05,0x25,0x88,0xb9,0xb7,0xd2,
	0xbb,0xd2,0xdf,0x01,0x61,0x99,0xec,0xd0,
	0x6e,0x15,0x57,0xcd,0x09,0x15,0xb3,0x35,
	0x3b,0xbb,0x64,0xe0,0xec,0x37,0x7f,0xd0,
	0x28,0x37,0x0d,0xf9,0x2b,0x52,0xc7,0x89,
	0x14,0x28,0xcd,0xc6,0x7e,0xb6,0x18,0x4b,
	0x52,0x3d,0x1d,0xb2,0x46,0xc3,0x2f,0x63,
	0x07,0x84,0x90,0xf0,0x0e,0xf8,0xd6,0x47,
	0xd1,0x48,0xd4,0x79,0x54,0x51,0x5e,0x23,
	0x27,0xcf,0xef,0x98,0xc5,0x82,0x66,0x4b,
	0x4c,0x0f,0x6c,0xc4,0x16,0x59
};

static const char util_dh_oid[11]=
{
	0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x03,0x01
};

#endif
#ifndef USICRYPT_NO_EC

static const char util_ecp8_hdr[14]=
{
	0x02,0x01,0x00,0x30,0x09,0x06,0x07,0x2a,
	0x86,0x48,0xce,0x3d,0x02,0x01
};

#endif
#ifndef USICRYPT_NO_PBKDF2

static const unsigned char util_pbes2_oid[9]=
{
        0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

#endif

static const struct
{
	const unsigned char oid[9];
	const int oidlen;
	const int type;
	const int sub;
	const int key;
} util_oids[]=
{
#ifndef USICRYPT_NO_RSA
	{
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01},
		9,USICRYPT_RSA,0,USICRYPT_RSA
	},
#endif
#ifndef USICRYPT_NO_DH
	{
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x03,0x01},
		9,USICRYPT_DH,0,-1
	},
#endif
#ifndef USICRYPT_NO_EC
	{
		{0x2a,0x86,0x48,0xce,0x3d,0x02,0x01},
		7,-1,-1,-1
	},
	{
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d},
		9,-1,USICRYPT_BRAINPOOLP512R1,USICRYPT_BRAINPOOLP512R1
	},
	{
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b},
		9,-1,USICRYPT_BRAINPOOLP384R1,USICRYPT_BRAINPOOLP384R1
	},
	{
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07},
		9,-1,USICRYPT_BRAINPOOLP256R1,USICRYPT_BRAINPOOLP256R1
	},
	{
		{0x2b,0x81,0x04,0x00,0x23},
		5,-1,USICRYPT_SECP521R1,USICRYPT_SECP521R1
	},
	{
		{0x2b,0x81,0x04,0x00,0x22},
		5,-1,USICRYPT_SECP384R1,USICRYPT_SECP384R1
	},
	{
		{0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07},
		8,-1,USICRYPT_SECP256R1,USICRYPT_SECP256R1
	},
#endif
#ifndef USICRYPT_NO_X25519
	{
		{0x2b,0x65,0x6e},
		3,USICRYPT_X25519,0,USICRYPT_X25519
	},
#endif
#ifndef USICRYPT_NO_X448
	{
		{0x2b,0x65,0x6f},
		3,USICRYPT_X448,0,USICRYPT_X448
	},
#endif
#ifndef USICRYPT_NO_ED25519
	{
		{0x2b,0x65,0x70},
		3,USICRYPT_ED25519,0,USICRYPT_ED25519
	},
#endif
#ifndef USICRYPT_NO_ED448
	{
		{0x2b,0x65,0x71},
		3,USICRYPT_ED448,0,USICRYPT_ED448
	},
#endif
	{
		{},
		0,0,0,0
	}
};

static int util_asn_next(unsigned char *prm,int len,unsigned char id,
	int *hlen,int *dlen)
{
	int n;

	*hlen=2;
	if(U(len<=1))goto err1;
	if(U(prm[0]!=id))goto err1;
	if(prm[1]&0x80)
	{
		*hlen=prm[1]&0x7f;
		if(U(*hlen<1)||U(*hlen>3))goto err1;
		if(U(len<*hlen+2))goto err1;
		*dlen=0;
		n=2;
		switch(*hlen)
		{
		case 3: *dlen=prm[n++];
		case 2: *dlen<<=8;
			*dlen|=prm[n++];
		case 1: *dlen<<=8;
			*dlen|=prm[n++];
		}
		*hlen+=2;
	}
	else *dlen=prm[1];
	if(U(*hlen+*dlen>len))goto err1;
	return 0;

err1:	return -1;
}

#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC)

static int util_asn_length(unsigned char *ptr,int len)
{
	int n=1;

	if(len>=0x100)
	{
		n=3;
		if(ptr)
		{
			*ptr++=0x82;
			*ptr++=(unsigned char)(len>>8);
			*ptr=(unsigned char)len;
		}
	}
	else if(len>=0x80)
	{
		n=2;
		if(ptr)
		{
			*ptr++=0x81;
			*ptr=(unsigned char)len;
		}
	}
	else if(ptr)*ptr=(unsigned char)len;
	return n;
}

#endif

void usicrypt_lfsr_next(void *ctx,void *out)
{
	unsigned char *ptr=out;
	struct util_lfsr *p=(struct util_lfsr *)ctx;
	union
	{
		unsigned int v32;
		unsigned long long v64;
	} r;

	switch(p->mode)
	{
	case 0:	if(p->value.v32&1)
		{
			p->value.v32>>=1;
			p->value.v32^=p->poly.p32;
		}
		else p->value.v32>>=1;
		ptr+=p->bytes;
		r.v32=p->value.v32;
		switch(p->bytes)
		{
		case 3:	*ptr--=(unsigned char)r.v32;
			r.v32>>=8;
		case 2:	*ptr--=(unsigned char)r.v32;
			r.v32>>=8;
		case 1:	*ptr--=(unsigned char)r.v32;
			r.v32>>=8;
		case 0:	*ptr=(unsigned char)r.v32;
		}
		break;

	case 1:	if(p->value.v64&1)
		{
			p->value.v64>>=1;
			p->value.v64^=p->poly.p64;
		}
		else p->value.v64>>=1;
		ptr+=p->bytes;
		r.v64=p->value.v64;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		switch(p->bytes)
		{
		case 7:	*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 6:	*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 5:	*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 4:	*ptr=(unsigned char)r.v64;
		}
		break;

	case 2:	if(p->value.v128[0]&1)
		{
			p->value.v128[0]>>=1;
			if(p->value.v128[1]&1)
				p->value.v128[0]|=0x8000000000000000ULL;
			p->value.v128[1]>>=1;
			p->value.v128[1]^=p->poly.p64;
		}
		else
		{
			p->value.v128[0]>>=1;
			if(p->value.v128[1]&1)
				p->value.v128[0]|=0x8000000000000000ULL;
			p->value.v128[1]>>=1;
		}
		ptr+=p->bytes;
		r.v64=p->value.v128[0];
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64>>=8;
		*ptr--=(unsigned char)r.v64;
		r.v64=p->value.v128[1];
		switch(p->bytes)
		{
		case 15:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 14:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 13:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 12:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 11:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 10:*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 9:	*ptr--=(unsigned char)r.v64;
			r.v64>>=8;
		case 8:	*ptr=(unsigned char)r.v64;
		}
		break;
	}
}

void *usicrypt_lfsr_init(void *ctx,int bits,void *preset)
{
	unsigned char *ptr=preset;
	struct util_lfsr *p;

	if(U(bits&7)||U(bits<8)||U(bits>128))goto err1;
	if(U(!(p=malloc(sizeof(struct util_lfsr)))))goto err1;
	p->bytes=(bits>>3)-1;
	p->mode=util_lfsr[p->bytes].mode;
	if(p->mode)p->poly.p64=util_lfsr[p->bytes].poly;
	else p->poly.p32=(unsigned int)util_lfsr[p->bytes].poly;
	if(ptr)switch(p->mode)
	{
	case 0:	p->value.v32=0;
		switch(p->bytes)
		{
		case 3:	p->value.v32|=*ptr++;
			p->value.v32<<=8;
		case 2:	p->value.v32|=*ptr++;
			p->value.v32<<=8;
		case 1:	p->value.v32|=*ptr++;
			p->value.v32<<=8;
		case 0:	p->value.v32|=*ptr;
		}
		if(!p->value.v32)goto err2;
		break;

	case 1:	p->value.v64=*ptr++;
		p->value.v64<<=8;
		p->value.v64|=*ptr++;
		p->value.v64<<=8;
		p->value.v64|=*ptr++;
		p->value.v64<<=8;
		p->value.v64|=*ptr++;
		p->value.v64<<=8;
		switch(p->bytes)
		{
		case 7:	p->value.v64|=*ptr++;
			p->value.v64<<=8;
		case 6:	p->value.v64|=*ptr++;
			p->value.v64<<=8;
		case 5:	p->value.v64|=*ptr++;
			p->value.v64<<=8;
		case 4:	p->value.v64|=*ptr;
		}
		if(!p->value.v64)goto err2;
		break;

	case 2:	p->value.v128[1]=0ULL;
		switch(p->bytes)
		{
		case 15:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 14:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 13:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 12:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 11:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 10:p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 9:	p->value.v128[1]|=*ptr++;
			p->value.v128[1]<<=8;
		case 8:	p->value.v128[1]|=*ptr++;
		}
		p->value.v128[0]=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr++;
		p->value.v128[0]<<=8;
		p->value.v128[0]|=*ptr;
		if(!p->value.v128[1]&&!p->value.v128[0])goto err2;
		break;
	}
	else do
	{
		if(U(USICRYPT(random)(ctx,(unsigned char *)(&p->value),
			sizeof(p->value))))goto err2;
		switch(p->mode)
		{
		case 0:	if(p->bytes!=3)p->value.v32&=(1<<bits)-1;
			if(!p->value.v32)continue;
			break;

		case 1:	if(p->bytes!=7)p->value.v64&=(1ULL<<bits)-1ULL;
			if(!p->value.v64)continue;
			break;

		case 2:	if(p->bytes!=15)p->value.v128[1]&=
				(1ULL<<(bits-64))-1ULL;
			if(!p->value.v128[0]&&!p->value.v128[1])continue;
			break;
		}
		break;
	} while(1);
	return p;

err2:	free(p);
err1:	return NULL;
}

void usicrypt_lfsr_exit(void *ctx)
{
	free(ctx);
}

void usicrypt_memclear(void *ctx,void *data,int len)
{
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
}

int usicrypt_cipher_padding_add(void *ctx,void *data,int len)
{
	int i;
	int pad=0x10-(len&0xf);

	if(data)
	{
		for(i=0;i<pad;i++)
			((unsigned char *)data)[len+i]=(unsigned char)pad;
	}
	return pad;
}

int usicrypt_cipher_padding_get(void *ctx,void *data,int len)
{
	int i;
	int pad;

	if(U(len<1)||U((pad=((unsigned char *)data)[len-1])>len))return -1;
	if(U(pad<1)||U(pad>16))return -1;
	for(i=len-pad;i<len-1;i++)
		if(U(((unsigned char *)data)[i]!=pad))return -1;
	return pad;
}

void *usicrypt_dh_params(void *ctx,int which,int *len)
{
	switch(which)
	{
#ifndef USICRYPT_NO_DH
	case USICRYPT_RFC5114_1024_160:
		*len=268;
		return (void *)usicrypt_dh_1024_160;
	case USICRYPT_RFC5114_2048_224:
		*len=526;
		return (void *)usicrypt_dh_2048_224;
	case USICRYPT_RFC5114_2048_256:
		*len=526;
		return (void *)usicrypt_dh_2048_256;
#endif
	default:return NULL;
	}
}

void *usicrypt_dh_get_pub(void *ctx,void *pub,int publen,void *params,int plen,
	int *len)
{
#ifndef USICRYPT_NO_DH
	int pubadd;
	int len1;
	int len2;
	int len3;
	int len4;
	unsigned char *data;
	unsigned char *ptr;

	if(*((unsigned char *)pub)&0x80)pubadd=1;
	else pubadd=0;

	len1=util_asn_length(NULL,publen+pubadd)+1;
	len2=util_asn_length(NULL,publen+pubadd+len1)+2;
	len3=util_asn_length(NULL,plen+sizeof(util_dh_oid))+1;
	len4=util_asn_length(NULL,publen+pubadd+len1+len2+plen+
		sizeof(util_dh_oid)+len3)+1;

	*len=publen+pubadd+len1+len2+plen+sizeof(util_dh_oid)+len3+len4;

	if(U(!(ptr=data=malloc(*len))))goto err1;

	*ptr++=0x30;
	ptr+=util_asn_length(ptr,publen+pubadd+len1+len2+plen+
		sizeof(util_dh_oid)+len3);

	*ptr++=0x30;
	ptr+=util_asn_length(ptr,plen+sizeof(util_dh_oid));
	memcpy(ptr,util_dh_oid,sizeof(util_dh_oid));
	ptr+=sizeof(util_dh_oid);
	memcpy(ptr,params,plen);
	ptr+=plen;

	*ptr++=0x03;
	ptr+=util_asn_length(ptr,publen+pubadd+len1+1);
	*ptr++=0x00;

	*ptr++=0x02;
	ptr+=util_asn_length(ptr,publen+pubadd);
	if(pubadd)*ptr++=0x00;
	memcpy(ptr,pub,publen);

err1:	return data;
#else
	return NULL;
#endif
}

void *usicrypt_dh_set_pub(void *ctx,void *data,int dlen,void **params,int *plen,
	int *len)
{
#ifndef USICRYPT_NO_DH
	int h;
	int l;
	unsigned char *d=data;
	unsigned char *pmem;
	unsigned char *pub;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	if(U(l<=sizeof(util_dh_oid)))goto err1;
	if(U(memcmp(d+h,util_dh_oid,sizeof(util_dh_oid))))goto err1;
	pmem=d+h+sizeof(util_dh_oid);
	*plen=l-sizeof(util_dh_oid);
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0x03,&h,&l)))goto err1;
	if(U(!l)||U(d[h]))goto err1;
	d+=h+1;
	dlen-=h+1;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err1;
	for(d+=h;l&&!*d;d++,l--);
	if(!l)goto err1;
	*len=l;

	if(U(!(*params=malloc(*plen))))goto err1;
	memcpy(*params,pmem,*plen);

	if(U(!(pub=malloc(*len))))goto err2;
	memcpy(pub,d,*len);

	d=pmem;
	dlen=*plen;
	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err3;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err3;
	for(d+=h;l&&!*d;d++,l--);
	if(U(!l))goto err3;
	d+=l;
	dlen-=l;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err3;
	for(d+=h;l&&!*d;d++,l--);
	if(U(!l))goto err3;

	return pub;

err3:	free(pub);
err2:	free(*params);
err1:	return NULL;
#else
	return NULL;
#endif
}

int usicrypt_dh_cmp_params(void *ctx,void *p1,int p1len,void *p2,int p2len)
{
#ifndef USICRYPT_NO_DH
	int h;
	int l;
	int pxl;
	int gxl;
	int pyl;
	int gyl;
	unsigned char *p;
	unsigned char *px;
	unsigned char *gx;
	unsigned char *py;
	unsigned char *gy;

	p=p1;
	if(U(util_asn_next(p,p1len,0x30,&h,&l)))goto err1;
	p+=h;
	p1len-=h;

	if(U(util_asn_next(p,p1len,0x02,&h,&l)))goto err1;
	for(p+=h;l&&!*p;p++,l--);
	if(!l)goto err1;
	px=p;
	pxl=l;
	p+=l;
	p1len-=l;

	if(U(util_asn_next(p,p1len,0x02,&h,&l)))goto err1;
	for(p+=h;l&&!*p;p++,l--);
	if(U(!l))goto err1;
	gx=p;
	gxl=l;

	p=p2;
	if(U(util_asn_next(p,p2len,0x30,&h,&l)))goto err1;
	p+=h;
	p2len-=h;

	if(U(util_asn_next(p,p2len,0x02,&h,&l)))goto err1;
	for(p+=h;l&&!*p;p++,l--);
	if(U(!l))goto err1;
	py=p;
	pyl=l;
	p+=l;
	p2len-=l;

	if(U(util_asn_next(p,p2len,0x02,&h,&l)))goto err1;
	for(p+=h;l&&!*p;p++,l--);
	if(U(!l))goto err1;
	gy=p;
	gyl=l;

	if(pxl!=pyl||memcmp(px,py,pxl))goto err1;
	if(gxl!=gyl||memcmp(gx,gy,gxl))goto err1;

	return 0;

err1:	return -1;
#else
	return -1;
#endif
}

int usicrypt_pub_type_from_p8(void *ctx,void *data,int dlen)
{
	int h;
	int l;
	int i;
	int sub;
	unsigned char *d=data;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x06,&h,&l)))goto err1;
	d+=h;

	for(i=0,sub=0;util_oids[i].oidlen;i++)if(util_oids[i].type<0&&
		util_oids[i].oidlen==l&&!memcmp(d,util_oids[i].oid,l))
	{
		sub=util_oids[i].type;
		d+=l;
		dlen-=h+l;
		if(U(util_asn_next(d,dlen,0x06,&h,&l)))goto err1;
		d+=h;
		break;
	}

	for(i=0;util_oids[i].oidlen;i++)
	{
		if(util_oids[i].sub<0)continue;
		if(sub<0&&sub==util_oids[i].type&&util_oids[i].oidlen==l&&
			!memcmp(d,util_oids[i].oid,l))return util_oids[i].sub;
		if(!sub&&util_oids[i].oidlen==l&&!memcmp(d,util_oids[i].oid,l))
			return util_oids[i].type;
	}

err1:	return -1;
}

int usicrypt_key_type_from_p8(void *ctx,void *data,int dlen)
{
	int h;
	int l;
	int i;
	int sub;
	int pbes2=0;
	unsigned char *d=data;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(util_asn_next(d,dlen,0x02,&h,&l))
	{
		if(U(!dlen)||U(*d!=0x30))goto err1;
		pbes2=1;
	}
	else
	{
		if(U(l!=1)||U(d[h]))goto err1;
		d+=h+l;
		dlen-=h+l;
	}

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x06,&h,&l)))goto err1;
	d+=h;

	if(pbes2)
	{
#ifndef USICRYPT_NO_PBKDF2
		if(L(l==sizeof(util_pbes2_oid))&&L(!memcmp(d,util_pbes2_oid,l)))
			return USICRYPT_PBES2;
#endif
		goto err1;
	}

	for(i=0,sub=0;util_oids[i].oidlen;i++)if(util_oids[i].type<0&&
		util_oids[i].oidlen==l&&!memcmp(d,util_oids[i].oid,l))
	{
		sub=util_oids[i].type;
		d+=l;
		dlen-=h+l;
		if(U(util_asn_next(d,dlen,0x06,&h,&l)))goto err1;
		d+=h;
		break;
	}

	for(i=0;util_oids[i].oidlen;i++)
	{
		if(util_oids[i].sub<0)continue;
		if(sub<0&&sub==util_oids[i].type&&util_oids[i].oidlen==l&&
			!memcmp(d,util_oids[i].oid,l))return util_oids[i].key;
		if(!sub&&util_oids[i].oidlen==l&&!memcmp(d,util_oids[i].oid,l))
			return util_oids[i].key;
	}

err1:	return -1;
}

void *usicrypt_rsa_key_to_p8(void *ctx,void *data,int dlen,int *p8len)
{
#ifndef USICRYPT_NO_RSA
	int len1;
	int len2;
	unsigned char *r;
	unsigned char *ptr;

	len1=util_asn_length(NULL,dlen)+sizeof(util_rsap8hdr);
	len2=util_asn_length(NULL,len1+dlen)+1;
	*p8len=len1+len2+dlen;
	if(U(!(ptr=r=malloc(*p8len))))goto err1;
	*ptr++=0x30;
	ptr+=util_asn_length(ptr,len1+dlen);
	memcpy(ptr,util_rsap8hdr,sizeof(util_rsap8hdr));
	ptr+=sizeof(util_rsap8hdr);
	ptr+=util_asn_length(ptr,dlen);
	memcpy(ptr,data,dlen);
err1:	return r;
#else
	return NULL;
#endif
}

void *usicrypt_p8_to_rsa_key(void *ctx,void *data,int dlen,int *klen)
{
#ifndef USICRYPT_NO_RSA
	int h;
	int l;
	unsigned char *d=data;
	unsigned char *r=NULL;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(dlen<sizeof(util_rsap8hdr))||
		U(memcmp(d,util_rsap8hdr,sizeof(util_rsap8hdr))))goto err1;
	d+=sizeof(util_rsap8hdr)-1;
	dlen-=sizeof(util_rsap8hdr)-1;

	if(U(util_asn_next(d,dlen,0x04,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(!(r=malloc(dlen))))goto err1;
	memcpy(r,d,dlen);
	*klen=dlen;
err1:	return r;
#else
	return NULL;
#endif
}

void *usicrypt_ec_key_to_p8(void *ctx,void *data,int dlen,int *p8len)
{
#ifndef USICRYPT_NO_EC
	int h;
	int l;
	int len1;
	int len2;
	int len3;
	int keylen;
	int oidlen;
	int publen;
	unsigned char *d=data;
	unsigned char *r=NULL;
	unsigned char *ptr;
	unsigned char *key;
	unsigned char *oid;
	unsigned char *pub;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err1;
	if(U(l!=1)||U(d[h]!=0x01))goto err1;
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0x04,&h,&l)))goto err1;
	key=d;
	keylen=h+l;
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0xa0,&h,&l)))goto err1;
	if(U(l>0x76))goto err1;
	oid=d+h;
	oidlen=l;
	d+=h+l;
	dlen-=h+l;

	if(!util_asn_next(d,dlen,0xa1,&h,&l))
	{
		pub=d;
		publen=h+l;
	}
	else
	{
		pub=NULL;
		publen=0;
	}

	len1=util_asn_length(NULL,keylen+publen+3)+1;
	len2=util_asn_length(NULL,keylen+publen+3+len1)+1;
	len3=util_asn_length(NULL,keylen+publen+3+len1+len2+
		oidlen+sizeof(util_ecp8_hdr))+1;
	*p8len=len1+len2+len3+keylen+publen+3+oidlen+sizeof(util_ecp8_hdr);
	if(U(!(ptr=r=malloc(*p8len))))goto err1;
	*ptr++=0x30;
	ptr+=util_asn_length(ptr,keylen+publen+3+len1+len2+oidlen+
		sizeof(util_ecp8_hdr));
	memcpy(ptr,util_ecp8_hdr,sizeof(util_ecp8_hdr));
	ptr[4]+=(unsigned char)oidlen;
	ptr+=sizeof(util_ecp8_hdr);
	memcpy(ptr,oid,oidlen);
	ptr+=oidlen;
	*ptr++=0x04;
	ptr+=util_asn_length(ptr,keylen+publen+3+len1);
	*ptr++=0x30;
	ptr+=util_asn_length(ptr,keylen+publen+3);
	*ptr++=0x02;
	*ptr++=0x01;
	*ptr++=0x01;
	memcpy(ptr,key,keylen);
	ptr+=keylen;
	if(pub)memcpy(ptr,pub,publen);
err1:	return r;
#else
	return NULL;
#endif
}

void *usicrypt_p8_to_ec_key(void *ctx,void *data,int dlen,int *klen)
{
#ifndef USICRYPT_NO_EC
	int h;
	int l;
	int len1;
	int oidlen;
	int keylen;
	int publen;
	unsigned char *d=data;
	unsigned char *r=NULL;
	unsigned char *ptr;
	unsigned char *oid;
	unsigned char *key;
	unsigned char *pub;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err1;
	if(U(l!=1)||U(d[h]))goto err1;
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(dlen<sizeof(util_ecp8_hdr)-5)||
		U(memcmp(d,util_ecp8_hdr+5,sizeof(util_ecp8_hdr)-5)))goto err1;
	d+=sizeof(util_ecp8_hdr)-5;
	dlen-=sizeof(util_ecp8_hdr)-5;

	if(U(util_asn_next(d,dlen,0x06,&h,&l)))goto err1;
	if(U(h+l>0x7d))goto err1;
	oid=d;
	oidlen=h+l;
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0x04,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x30,&h,&l)))goto err1;
	d+=h;
	dlen-=h;

	if(U(util_asn_next(d,dlen,0x02,&h,&l)))goto err1;
	if(U(l!=1)||U(d[h]!=0x01))goto err1;
	d+=h+l;
	dlen-=h+l;

	if(U(util_asn_next(d,dlen,0x04,&h,&l)))goto err1;
	key=d;
	keylen=h+l;
	d+=h+l;
	dlen-=h+l;

	if(!util_asn_next(d,dlen,0xa1,&h,&l))
	{
		pub=d;
		publen=h+l;
	}
	else
	{
		pub=NULL;
		publen=0;
	}

	len1=util_asn_length(NULL,publen+oidlen+2+keylen+3)+1;
	*klen=publen+oidlen+2+keylen+3+len1;
	if(U(!(ptr=r=malloc(*klen))))goto err1;
	*ptr++=0x30;
	ptr+=util_asn_length(ptr,publen+oidlen+2+keylen+3);
	*ptr++=0x02;
	*ptr++=0x01;
	*ptr++=0x01;
	memcpy(ptr,key,keylen);
	ptr+=keylen;
	*ptr++=0xa0;
	*ptr++=(unsigned char)oidlen;
	memcpy(ptr,oid,oidlen);
	ptr+=oidlen;
	if(pub)memcpy(ptr,pub,publen);
err1:	return r;
#else
	return NULL;
#endif
}
