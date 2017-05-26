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
#ifndef USICRYPT_GCRY
#define USICRYPT_GCRY
#endif
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#if defined(USICRYPT_GCRY)

#include <gcrypt.h>
#include <stdint.h>

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) gcry_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

/******************************************************************************/
/*                                Libgcrypt                                   */
/******************************************************************************/

struct gcry_rsa
{
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
	gcry_mpi_t p;
	gcry_mpi_t q;
	gcry_mpi_t e1;
	gcry_mpi_t e2;
	gcry_mpi_t c;
};

struct gcry_dh
{
	gcry_mpi_t p;
	gcry_mpi_t g;
	gcry_mpi_t key;
};

struct gcry_ec
{
	int curve;
	gcry_mpi_t key;
	gcry_mpi_t pub;
};

struct gcry_x25519
{
	gcry_mpi_t pub;
	gcry_mpi_t key;
};

struct gcry_cipher
{
	struct usicrypt_cipher cipher;
	gcry_cipher_hd_t h;
	unsigned char extra[0];
};

struct gcry_cipher_cfb8
{
	struct usicrypt_cipher cipher;
	gcry_cipher_hd_t hd;
	struct usicrypt_global *global;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct gcry_cipher_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	gcry_cipher_hd_t ed;
	gcry_cipher_hd_t tw;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct gcry_cipher_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	gcry_cipher_hd_t h;
	gcry_cipher_hd_t aux;
	unsigned char iv[16];
};

struct gcry_aes_xcm
{
	struct usicrypt_aeadcipher cipher;
	gcry_cipher_hd_t ctx;
	int ilen;
	int tlen;
};

struct gcry_chacha_poly
{
	struct usicrypt_aeadcipher cipher;
	gcry_cipher_hd_t ctx;
};

#ifndef USICRYPT_NO_BASE64

static const unsigned char const gcry_b64enc[64]=
{
	0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,
	0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,
	0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,
	0x59,0x5a,0x61,0x62,0x63,0x64,0x65,0x66,
	0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
	0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,
	0x77,0x78,0x79,0x7a,0x30,0x31,0x32,0x33,
	0x34,0x35,0x36,0x37,0x38,0x39,0x2b,0x2f
};

static const unsigned char const gcry_b64dec[256]=
{
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0x3e,0xff,0xff,0xff,0x3f,
	0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,
	0x3c,0x3d,0xff,0xff,0xff,0x40,0xff,0xff,
	0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,
	0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,
	0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,
	0x17,0x18,0x19,0xff,0xff,0xff,0xff,0xff,
	0xff,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
	0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
	0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,
	0x31,0x32,0x33,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

#endif
#ifndef USICRYPT_NO_PBKDF2

static const unsigned char const gcry_pbes2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

static const unsigned char const gcry_pbkdf2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c
};

static const struct
{
	const int const digest;
	const int const oidlen;
	const unsigned char const oid[0x08];

} const gcry_digest_asn[4]=
{
	{
#ifndef USICRYPT_NO_SHA1
		USICRYPT_SHA1,0x08,
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x07},
#endif
	},
	{
#ifndef USICRYPT_NO_SHA256
		USICRYPT_SHA256,0x08,
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x09},
#endif
	},
	{
#ifndef USICRYPT_NO_SHA384
		USICRYPT_SHA384,0x08,
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x0a},
#endif
	},
	{
#ifndef USICRYPT_NO_SHA512
		USICRYPT_SHA512,0x08,
		{0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x0b},
#endif
	},
};

static const struct
{
	const unsigned int const cipher:9;
	const unsigned int const mode:4;
	const unsigned int const pad:1;
	const unsigned int const bits:9;
	const unsigned int const ivlen:5;
	const unsigned int const oidlen:4;
	const unsigned char const oid[0x0b];
} const gcry_cipher_asn[24]=
{
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_ECB)
		USICRYPT_AES,USICRYPT_ECB,1,128,0,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x01},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CBC)
		USICRYPT_AES,USICRYPT_CBC,1,128,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x02},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CFB)
		USICRYPT_AES,USICRYPT_CFB,0,128,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x04},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_OFB)
		USICRYPT_AES,USICRYPT_OFB,0,128,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x03},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_ECB)
		USICRYPT_AES,USICRYPT_ECB,1,192,0,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x15},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CBC)
		USICRYPT_AES,USICRYPT_CBC,1,192,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x16},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CFB)
		USICRYPT_AES,USICRYPT_CFB,0,192,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x18},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_OFB)
		USICRYPT_AES,USICRYPT_OFB,0,192,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x17},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_ECB)
		USICRYPT_AES,USICRYPT_ECB,1,256,0,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x29},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CBC)
		USICRYPT_AES,USICRYPT_CBC,1,256,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2a},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_CFB)
		USICRYPT_AES,USICRYPT_CFB,0,256,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2c},
#endif
	},
	{
#if !defined(USICRYPT_NO_AES) && !defined(USICRYPT_NO_OFB)
		USICRYPT_AES,USICRYPT_OFB,0,256,16,0x09,
		{0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x01,0x2b},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_ECB)
		USICRYPT_CAMELLIA,USICRYPT_ECB,1,128,0,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x01},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CBC)
		USICRYPT_CAMELLIA,USICRYPT_CBC,1,128,16,0x0b,
		{0x2a,0x83,0x08,0x8c,0x9a,0x4b,0x3d,0x01,0x01,0x01,0x02},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CFB)
		USICRYPT_CAMELLIA,USICRYPT_CFB,0,128,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x04},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_OFB)
		USICRYPT_CAMELLIA,USICRYPT_OFB,0,128,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x03},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_ECB)
		USICRYPT_CAMELLIA,USICRYPT_ECB,1,192,0,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x15},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CBC)
		USICRYPT_CAMELLIA,USICRYPT_CBC,1,192,16,0x0b,
		{0x2a,0x83,0x08,0x8c,0x9a,0x4b,0x3d,0x01,0x01,0x01,0x03},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CFB)
		USICRYPT_CAMELLIA,USICRYPT_CFB,0,192,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x18},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_OFB)
		USICRYPT_CAMELLIA,USICRYPT_OFB,0,192,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x17},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_ECB)
		USICRYPT_CAMELLIA,USICRYPT_ECB,1,256,0,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x29},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CBC)
		USICRYPT_CAMELLIA,USICRYPT_CBC,1,256,16,0x0b,
		{0x2a,0x83,0x08,0x8c,0x9a,0x4b,0x3d,0x01,0x01,0x01,0x04},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_CFB)
		USICRYPT_CAMELLIA,USICRYPT_CFB,0,256,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x2c},
#endif
	},
	{
#if !defined(USICRYPT_NO_CAMELLIA) && !defined(USICRYPT_NO_OFB)
		USICRYPT_CAMELLIA,USICRYPT_OFB,0,256,16,0x08,
		{0x03,0xa2,0x31,0x05,0x03,0x01,0x09,0x2b},
#endif
	},
};

#endif
#ifndef USICRYPT_NO_RSA

static const unsigned char const gcry_rsa_pub_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01
};

#endif
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH)

static const int const gcry_primes[171]=
{
	0x0003,0x0005,0x0007,0x000b,0x000d,0x0011,0x0013,0x0017,
	0x001d,0x001f,0x0025,0x0029,0x002b,0x002f,0x0035,0x003b,
	0x003d,0x0043,0x0047,0x0049,0x004f,0x0053,0x0059,0x0061,
	0x0065,0x0067,0x006b,0x006d,0x0071,0x007f,0x0083,0x0089,
	0x008b,0x0095,0x0097,0x009d,0x00a3,0x00a7,0x00ad,0x00b3,
	0x00b5,0x00bf,0x00c1,0x00c5,0x00c7,0x00d3,0x00df,0x00e3,
	0x00e5,0x00e9,0x00ef,0x00f1,0x00fb,0x0101,0x0107,0x010d,
	0x010f,0x0115,0x0119,0x011b,0x0125,0x0133,0x0137,0x0139,
	0x013d,0x014b,0x0151,0x015b,0x015d,0x0161,0x0167,0x016f,
	0x0175,0x017b,0x017f,0x0185,0x018d,0x0191,0x0199,0x01a3,
	0x01a5,0x01af,0x01b1,0x01b7,0x01bb,0x01c1,0x01c9,0x01cd,
	0x01cf,0x01d3,0x01df,0x01e7,0x01eb,0x01f3,0x01f7,0x01fd,
	0x0209,0x020b,0x021d,0x0223,0x022d,0x0233,0x0239,0x023b,
	0x0241,0x024b,0x0251,0x0257,0x0259,0x025f,0x0265,0x0269,
	0x026b,0x0277,0x0281,0x0283,0x0287,0x028d,0x0293,0x0295,
	0x02a1,0x02a5,0x02ab,0x02b3,0x02bd,0x02c5,0x02cf,0x02d7,
	0x02dd,0x02e3,0x02e7,0x02ef,0x02f5,0x02f9,0x0301,0x0305,
	0x0313,0x031d,0x0329,0x032b,0x0335,0x0337,0x033b,0x033d,
	0x0347,0x0355,0x0359,0x035b,0x035f,0x036d,0x0371,0x0373,
	0x0377,0x038b,0x038f,0x0397,0x03a1,0x03a9,0x03ad,0x03b3,
	0x03b9,0x03c7,0x03cb,0x03d1,0x03d7,0x03df,0x03e5,0x03f1,
	0x03f5,0x03fb,0x03fd
};

static const struct
{
	const int const bits;
	const int const iter;
} const gcry_mr_tab[11]=
{
	{1300,2},
	{850,3},
	{650,4},
	{550,5},
	{450,6},
	{400,7},
	{350,8},
	{250,12},
	{200,15},
	{150,18},
	{0,27}
};

#endif
#ifndef USICRYPT_NO_EC

static const unsigned char const gcry_ansi_pubkey_type[7]=
{
	0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
};

static const unsigned char const gcry_ec_k1h1[4]=
{
	0x02,0x01,0x01,0x04
};

static const struct
{       
	const char *const gcry_name;
	const int publen;
	const int kmax;
	const int xylen;
	const int phdrlen;
	const int k1h2len;
	const unsigned char oidlen;
	const unsigned char const oid[9];
	const unsigned char const phdr[29];
	const unsigned char const k1h2[20];
} const gcry_ec_map[USICRYPT_TOT_EC_CURVES]=
{
	{
		"brainpoolP512r1",
		158,0x40,0x81,0x1d,20,0x09,
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0d},
		{
			0x30,0x81,0x9b,0x30,0x14,0x06,0x07,0x2a,
			0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x09,
			0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,
			0x0d,0x03,0x81,0x82,0x00
		},
		{
			0xa0,0x0b,0x06,0x09,0x2b,0x24,0x03,0x03,
			0x02,0x08,0x01,0x01,0x0d,0xa1,0x81,0x85,
			0x03,0x81,0x82,0x00
		}
	},
	{
		"brainpoolP384r1",
		124,0x30,0x61,0x1b,18,0x09,
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b},
		{
			0x30,0x7a,0x30,0x14,0x06,0x07,0x2a,0x86,
			0x48,0xce,0x3d,0x02,0x01,0x06,0x09,0x2b,
			0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0b,
			0x03,0x62,0x00
		},
		{
			0xa0,0x0b,0x06,0x09,0x2b,0x24,0x03,0x03,
			0x02,0x08,0x01,0x01,0x0b,0xa1,0x64,0x03,
			0x62,0x00
		}
	},
	{
		"brainpoolP256r1",
		92,0x20,0x41,0x1b,18,0x09,
		{0x2b,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07},
		{
			0x30,0x5a,0x30,0x14,0x06,0x07,0x2a,0x86,
			0x48,0xce,0x3d,0x02,0x01,0x06,0x09,0x2b,
			0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07,
			0x03,0x42,0x00
		},
		{
			0xa0,0x0b,0x06,0x09,0x2b,0x24,0x03,0x03,
			0x02,0x08,0x01,0x01,0x07,0xa1,0x44,0x03,
			0x42,0x00
		}
	},
	{
		"NIST P-521",
		158,0x42,0x85,0x19,16,0x05,
		{0x2b,0x81,0x04,0x00,0x23},
		{
			0x30,0x81,0x9b,0x30,0x10,0x06,0x07,0x2a,
			0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,
			0x2b,0x81,0x04,0x00,0x23,0x03,0x81,0x86,
			0x00
		},
		{
			0xa0,0x07,0x06,0x05,0x2b,0x81,0x04,0x00,
			0x23,0xa1,0x81,0x89,0x03,0x81,0x86,0x00
		}
	},
	{
		"NIST P-384",
		120,0x30,0x61,0x17,14,0x05,
		{0x2b,0x81,0x04,0x00,0x22},
		{
			0x30,0x76,0x30,0x10,0x06,0x07,0x2a,0x86,
			0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2b,
			0x81,0x04,0x00,0x22,0x03,0x62,0x00
		},
		{
			0xa0,0x07,0x06,0x05,0x2b,0x81,0x04,0x00,
			0x22,0xa1,0x64,0x03,0x62,0x00
		}
	},
	{
		"NIST P-256",
		91,0x20,0x41,0x1a,17,0x08,
		{0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07},
		{
			0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,
			0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,
			0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,
			0x42,0x00
		},
		{
			0xa0,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,
			0x3d,0x03,0x01,0x07,0xa1,0x44,0x03,0x42,
			0x00
		}
	}
};

#endif
#ifndef USICRYPT_NO_X25519

static const unsigned char const gcry_x25519_asn1_pub[12]=
{       
	0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6e,0x03,0x21,0x00
};

static const unsigned char const gcry_x25519_asn1_key[16]=
{
	0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20
};

#endif

static int gcry_reseed(void *ctx)
{
	int r=-1;
	unsigned char bfr[32];

	if(((struct usicrypt_thread *)ctx)->global->rng_seed(bfr,sizeof(bfr)))
		goto err1;
	if(gcry_random_add_bytes(bfr,sizeof(bfr),100))goto err1;
	r=0;
err1:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return r;
}

#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC) || !defined(USICRYPT_NO_PBKDF2)

static int gcry_asn_next(unsigned char *prm,int len,unsigned char id,
	int *hlen,int *dlen)
{       
	int n;
	
	*hlen=2;
	if(len<=1)goto err1;
	if(prm[0]!=id)goto err1;
	if(prm[1]&0x80)
	{       
		*hlen=prm[1]&0x7f;
		if(*hlen<1||*hlen>3)goto err1;
		if(len<*hlen+2)goto err1;
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
	if(*hlen+*dlen>len)goto err1;
	return 0;

err1:	return -1;
}

#endif
#ifndef USICRYPT_NO_PBKDF2

static int gcry_asn_length(unsigned char *ptr,int len)
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
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH)

static int gcry_rsa_dh_mpi_test_primes(gcry_mpi_t *prime,int bits)
{
	int r=-1;
	int i;
	gcry_mpi_t n;

	if(!(n=gcry_mpi_new(bits)))goto err1;
	for(i=0;i<171;i++)
	{
		gcry_mpi_set_ui(n,gcry_primes[i]);
		gcry_mpi_mod(n,*prime,n);
		if(!gcry_mpi_cmp_ui(n,0))break;
	}
	if(i==171)r=0;
	gcry_mpi_release(n);
err1:	return r;
}

static int gcry_rsa_dh_mpi_miller_rabin(gcry_mpi_t *prime,int bits)
{
	int res=-1;
	int i;
	int n;
	int x;
	int c;
	int iter;
	gcry_mpi_t w;
	gcry_mpi_t r;
	gcry_mpi_t a;

	if(!(w=gcry_mpi_new(bits)))goto err1;
	if(!(r=gcry_mpi_new(bits)))goto err2;
	if(!(a=gcry_mpi_new(bits)))goto err3;

	bits=gcry_mpi_get_nbits(*prime);

	for(i=0;bits<gcry_mr_tab[i].bits;i++);
	iter=gcry_mr_tab[i].iter;

	gcry_mpi_sub_ui(w,*prime,1);
	for(x=0;x<bits;x++)if(gcry_mpi_test_bit(w,x))break;
	gcry_mpi_rshift(r,w,x);

	for(i=0,c=32;i<iter;i++,c=32)
	{
		do
		{
			if(!c--)goto err4;
			gcry_mpi_randomize(a,bits,GCRY_STRONG_RANDOM);
			if(gcry_mpi_test_bit(a,bits-1))
				gcry_mpi_set_highbit(a,bits-1);
				else gcry_mpi_clear_highbit(a,bits-1);
			n=gcry_mpi_get_nbits(a)-gcry_mpi_get_nbits(w);
			if(n>0)gcry_mpi_rshift(a,a,n);
		} while(gcry_mpi_cmp(a,w)>=0||gcry_mpi_cmp_ui(a,2)<0);

		gcry_mpi_powm(a,a,r,*prime);
		if(!gcry_mpi_cmp(a,w)||!gcry_mpi_cmp_ui(a,1))continue;

		for(n=1;n<x&&gcry_mpi_cmp(a,w);n++)
		{
			gcry_mpi_mulm(a,a,a,*prime);
			if(!gcry_mpi_cmp_ui(a,1))goto err4;
		}
		if(gcry_mpi_cmp(a,w))goto err4;
	}
	res=0;

err4:	gcry_mpi_release(a);
err3:	gcry_mpi_release(r);
err2:	gcry_mpi_release(w);
err1:	return res;
}

#endif
#ifndef USICRYPT_NO_RSA

static int gcry_rsa_mpi_gen_prime(gcry_mpi_t *prime,int bits)
{
	int r=-1;
	gcry_mpi_t p;

	if(!(p=gcry_mpi_new(bits)))goto err1;

	do
	{
		gcry_mpi_randomize(p,bits,GCRY_STRONG_RANDOM);
		gcry_mpi_set_highbit(p,bits-1);
		gcry_mpi_set_bit(p,0);
		while(1)
		{
			while(gcry_rsa_dh_mpi_test_primes(&p,bits)||
				gcry_rsa_dh_mpi_miller_rabin(&p,bits))
					gcry_mpi_add_ui(p,p,2);
			if(gcry_prime_check(p,0))gcry_mpi_add_ui(p,p,2);
			else break;
		}
	} while(gcry_mpi_get_nbits(p)!=bits);

	gcry_mpi_set(*prime,p);
	r=0;

	gcry_mpi_release(p);
err1:	return r;
}

static struct gcry_rsa *gcry_rsa_mpi_generate(int bits,unsigned long exp)
{
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
	gcry_mpi_t p;
	gcry_mpi_t q;
	gcry_mpi_t e1;
	gcry_mpi_t e2;
	gcry_mpi_t c;
	gcry_mpi_t tmp1;
	gcry_mpi_t tmp2;
	gcry_mpi_t phi;
	gcry_mpi_t g;
	gcry_mpi_t f;
	struct gcry_rsa *rsa;

	if((bits&1)||!(exp&1))goto err1;
	if(!(n=gcry_mpi_new(bits)))goto err1;
	if(!(e=gcry_mpi_new(sizeof(exp)<<3)))goto err2;
	if(!(p=gcry_mpi_snew(bits)))goto err3;
	if(!(q=gcry_mpi_snew(bits)))goto err4;
	if(!(tmp1=gcry_mpi_snew(bits>>1)))goto err5;
	if(!(tmp2=gcry_mpi_snew(bits>>1)))goto err6;
	if(!(phi=gcry_mpi_snew(bits)))goto err7;
	if(!(g=gcry_mpi_snew(bits)))goto err8;
	if(!(f=gcry_mpi_snew(bits)))goto err9;
	if(!(d=gcry_mpi_snew(bits)))goto err10;
	if(!(e1=gcry_mpi_snew(bits>>2)))goto err11;
	if(!(e2=gcry_mpi_snew(bits>>2)))goto err12;
	if(!(c=gcry_mpi_snew(bits>>2)))goto err13;
	gcry_mpi_set_ui(e,exp);
	do
	{
		do
		{
			do
			{
				if(gcry_rsa_mpi_gen_prime(&p,bits>>1)||
					gcry_rsa_mpi_gen_prime(&q,bits>>1))
						goto err14;
			} while(!gcry_mpi_cmp(p,q));
			if(gcry_mpi_cmp(p,q)>0)gcry_mpi_swap(p,q);
			gcry_mpi_mul(n,p,q);
		} while(gcry_mpi_get_nbits(n)!=bits);
		gcry_mpi_sub_ui(tmp1,p,1);
		gcry_mpi_sub_ui(tmp2,q,1);
		gcry_mpi_mul(phi,tmp1,tmp2);
		gcry_mpi_gcd(g,tmp1,tmp2);
	} while(!gcry_mpi_gcd(f,e,phi));
	gcry_mpi_div(f,NULL,phi,g,-1);
	if(!gcry_mpi_invm(d,e,f))goto err14;
	gcry_mpi_mod(e1,d,tmp1);
	gcry_mpi_mod(e2,d,tmp2);
	if(!gcry_mpi_invm(c,q,p))goto err14;
	if(!(rsa=malloc(sizeof(struct gcry_rsa))))goto err14;
	rsa->n=n;
	rsa->e=e;
	rsa->d=d;
	rsa->p=p;
	rsa->q=q;
	rsa->e1=e1;
	rsa->e2=e2;
	rsa->c=c;
	gcry_mpi_release(f);
	gcry_mpi_release(g);
	gcry_mpi_release(phi);
	gcry_mpi_release(tmp2);
	gcry_mpi_release(tmp1);
	return rsa;

err14:	gcry_mpi_release(c);
err13:	gcry_mpi_release(e2);
err12:	gcry_mpi_release(e1);
err11:	gcry_mpi_release(d);
err10:	gcry_mpi_release(f);
err9:	gcry_mpi_release(g);
err8:	gcry_mpi_release(phi);
err7:	gcry_mpi_release(tmp2);
err6:	gcry_mpi_release(tmp1);
err5:	gcry_mpi_release(p);
err4:	gcry_mpi_release(q);
err3:	gcry_mpi_release(e);
err2:	gcry_mpi_release(n);
err1:	return NULL;
}

static int gcry_rsa_mpi_check(gcry_mpi_t n,gcry_mpi_t e,gcry_mpi_t d,
	gcry_mpi_t p,gcry_mpi_t q,gcry_mpi_t e1,gcry_mpi_t e2,gcry_mpi_t c)
{
	int r=-1;
	int b;
	gcry_mpi_t p1;
	gcry_mpi_t q1;
	gcry_mpi_t tmp1;
	gcry_mpi_t tmp2;

	if(!gcry_mpi_cmp_ui(d,0)||!gcry_mpi_cmp_ui(p,0)||!gcry_mpi_cmp_ui(q,0))
		goto err1;
	b=gcry_mpi_get_nbits(n);
	if(!(p1=gcry_mpi_snew(b)))goto err1;
	if(!(q1=gcry_mpi_snew(b)))goto err2;
	if(!(tmp1=gcry_mpi_snew(b)))goto err3;
	if(!(tmp2=gcry_mpi_snew(b)))goto err4;
	if(!gcry_mpi_invm(tmp1,q,p))goto err5;
	if(gcry_mpi_cmp(tmp1,c))goto err5;
	gcry_mpi_mul(tmp1,p,q);
	if(gcry_mpi_cmp(tmp1,n))goto err5;
	gcry_mpi_sub_ui(p1,p,1);
	gcry_mpi_mod(tmp1,d,p1);
	if(gcry_mpi_cmp(tmp1,e1))goto err5;
	gcry_mpi_sub_ui(q1,q,1);
	gcry_mpi_mod(tmp1,d,q1);
	if(gcry_mpi_cmp(tmp1,e2))goto err5;
	gcry_mpi_mul(tmp2,p1,q1);
	if(!gcry_mpi_gcd(tmp1,e,tmp2))goto err5;
	gcry_mpi_gcd(tmp1,p1,q1);
	gcry_mpi_div(tmp1,tmp2,tmp2,tmp1,0);
	if(gcry_mpi_cmp_ui(tmp2,0))goto err5;
	gcry_mpi_mul(tmp2,d,e);
	gcry_mpi_mod(tmp2,tmp2,tmp1);
	if(gcry_mpi_cmp_ui(tmp2,1))goto err5;
	r=0;

err5:	gcry_mpi_release(tmp2);
err4:	gcry_mpi_release(tmp1);
err3:	gcry_mpi_release(q1);
err2:	gcry_mpi_release(p1);
err1:	return r;
}

static int gcry_rsa_mpi_write_hdr(unsigned char id,unsigned char *ptr,int len)
{
	int rl=2;

	*ptr++=id;
	if(len>=0x100)
	{
		*ptr++=0x82;
		*ptr++=(unsigned char)(len>>8);
		*ptr++=(unsigned char)(len);
		rl=4;
	}
	else if(len>=0x80)
	{
		*ptr++=0x81;
		*ptr++=(unsigned char)(len);
		rl=3;
	}
	else *ptr++=(unsigned char)(len);
	return rl;
}

static int gcry_rsa_mpi_write_int(unsigned char *ptr,gcry_mpi_t val)
{
	int bits;
	int len;
	int rl;
	size_t n;

	bits=gcry_mpi_get_nbits(val);
	len=((bits+7)>>3)+((!(bits&7))?1:0);
	ptr+=(rl=gcry_rsa_mpi_write_hdr(0x02,ptr,len));
	rl+=len;
	if(!(bits&7))*ptr++=0x00;
	len=(bits+7)>>3;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,ptr,len,&n,val)||n!=len)return -1;
	return rl;
}

static int gcry_rsa_mpi_hdr_add(int len)
{
	if(len>=0x100)len+=4;
	else if(len>=0x80)len+=3;
	else len+=2;
	return len;
}

static int gcry_rsa_mpi_int_size(gcry_mpi_t val)
{
	int bits;
	int len;

	bits=gcry_mpi_get_nbits(val);
	len=((bits+7)>>3)+((!(bits&7))?1:0);
	return gcry_rsa_mpi_hdr_add(len);
}

static gcry_mpi_t gcry_rsa_mpi_read_int(void *ctx,unsigned char *ptr,int len,
	int secure)
{
	size_t n;
	gcry_mpi_t val=NULL;
	unsigned char *tmp;

	if(!len)goto err1;
	if(!*ptr)
	{
		ptr++;
		if(!--len)goto err1;
	}
	if(secure)
	{
		if(!(tmp=gcry_malloc_secure(len)))goto err1;
		memcpy(tmp,ptr,len);
		ptr=tmp;
	}
	if(gcry_mpi_scan(&val,GCRYMPI_FMT_USG,ptr,len,&n)||n!=len)goto err2;
	if(secure)
	{
		((struct usicrypt_thread *)ctx)->global->memclear(ptr,len);
		gcry_free(ptr);
	}
	return val;

err2:	if(secure)
	{
		((struct usicrypt_thread *)ctx)->global->memclear(ptr,len);
		gcry_free(ptr);
	}
	if(val)gcry_mpi_release(val);
err1:	return NULL;
}

static int gcry_rsa_mpi_public(unsigned char *in,int ilen,unsigned char *out,
	int *olen,struct gcry_rsa *rsa)
{
	int len;
	int r=-1;
	size_t n;
	gcry_mpi_t ival=NULL;
	gcry_mpi_t oval;

	if(gcry_mpi_scan(&ival,GCRYMPI_FMT_USG,in,ilen,&n)||n!=ilen)goto err1;
	if(mpi_cmp(ival,rsa->n)>=0)goto err1;
	*olen=gcry_mpi_get_nbits(rsa->n);
	if(!(oval=gcry_mpi_new(*olen)))goto err1;
	*olen=(*olen+7)>>3;
	gcry_mpi_powm(oval,ival,rsa->e,rsa->n);
	len=(gcry_mpi_get_nbits(oval)+7)>>3;
	if(len>*olen)goto err2;
	if(len<*olen)memset(out,0,*olen-len);
	if(len)if(gcry_mpi_print(GCRYMPI_FMT_USG,out+*olen-len,len,&n,oval)||
		n!=len)goto err2;
	r=0;

err2:	gcry_mpi_release(oval);
err1:	if(ival)gcry_mpi_release(ival);
	return r;
}

static int gcry_rsa_mpi_private(unsigned char *in,int ilen,unsigned char *out,
	int *olen,struct gcry_rsa *rsa)
{
	int len;
	int r=-1;
	size_t n;
	gcry_mpi_t ival=NULL;
	gcry_mpi_t oval;

	if(gcry_mpi_scan(&ival,GCRYMPI_FMT_USG,in,ilen,&n)||n!=ilen)goto err1;
	if(mpi_cmp(ival,rsa->n)>=0)goto err1;
	*olen=gcry_mpi_get_nbits(rsa->n);
	if(!(oval=gcry_mpi_snew(*olen)))goto err1;
	*olen=(*olen+7)>>3;
	gcry_mpi_powm(oval,ival,rsa->d,rsa->n);
	len=(gcry_mpi_get_nbits(oval)+7)>>3;
	if(len>*olen)goto err2;
	if(len<*olen)memset(out,0,*olen-len);
	if(len)if(gcry_mpi_print(GCRYMPI_FMT_USG,out+*olen-len,len,&n,oval)||
		n!=len)goto err2;
	r=0;

err2:	gcry_mpi_release(oval);
err1:	if(ival)gcry_mpi_release(ival);
	return r;
}

static int gcry_mgf1(unsigned char *mask,int len,unsigned char *seed,int slen,
	int md)
{
	int i;
	int mdlen;
	int olen=0;
	int r=-1;
	gcry_md_hd_t h;
	unsigned char bfr[4];

	if(gcry_md_open(&h,md,0))goto err1;
	if((mdlen=gcry_md_get_algo_dlen(md))<=0)goto err2;
	for(i=0;olen<len;i++)
	{
		bfr[0]=(unsigned char)(i>>24);
		bfr[1]=(unsigned char)(i>>16);
		bfr[2]=(unsigned char)(i>>8);
		bfr[3]=(unsigned char)i;
		gcry_md_reset(h);
		gcry_md_write(h,seed,slen);
		gcry_md_write(h,bfr,sizeof(bfr));
		if(olen+mdlen<=len)
		{
			memcpy(mask+olen,gcry_md_read(h,md),mdlen);
			olen+=mdlen;
		}
		else
		{
			memcpy(mask+olen,gcry_md_read(h,md),len-olen);
			olen=len;
		}
	}
	r=0;

err2:	gcry_md_close(h);
err1:	return r;
}

static int gcry_add_oaep_mgf1(void *ctx,unsigned char *dst,int dlen,
	unsigned char *src,int slen,unsigned char *p,int plen,int md)
{
	int i;
	int mdlen;
	unsigned char *dm;
	unsigned char sm[64];

	if((mdlen=gcry_md_get_algo_dlen(md))<=0)goto err1;
	if(dlen-1<2*mdlen+1)goto err1;
	dst[0]=0x00;
	gcry_randomize(dst+1,mdlen,GCRY_STRONG_RANDOM);
	gcry_md_hash_buffer(md,dst+mdlen+1,p,plen);
	memset(dst+2*mdlen+1,0,dlen-slen-2*mdlen-2);
	dst[dlen-slen-1]=0x01;
	memcpy(dst+dlen-slen,src,slen);
	if(!(dm=malloc(dlen-mdlen-1)))goto err1;
	if(gcry_mgf1(dm,dlen-mdlen-1,dst+1,mdlen,md))goto err2;
	for(i=0;i<dlen-mdlen-1;i++)dst[i+mdlen+1]^=dm[i];
	if(gcry_mgf1(sm,mdlen,dst+mdlen+1,dlen-mdlen-1,md))goto err3;
	for(i=0;i<mdlen;i++)dst[i+1]^=sm[i];
	((struct usicrypt_thread *)ctx)->global->memclear(sm,sizeof(sm));
	((struct usicrypt_thread *)ctx)->global->memclear(dm,dlen-mdlen-1);
	free(dm);
	return 0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(sm,sizeof(sm));
err2:	((struct usicrypt_thread *)ctx)->global->memclear(dm,dlen-mdlen-1);
	free(dm);
err1:	return -1;
}

static int gcry_check_oaep_mgf1(void *ctx,unsigned char *dst,int dlen,
	unsigned char *src,int slen,int n,unsigned char *p,int plen,int md)
{
	int i;
	int l;
	int mdlen;
	unsigned char *mem;
	unsigned char wrk[64];

	if((mdlen=gcry_md_get_algo_dlen(md))<=0)goto err1;
	if(n<2*mdlen+2||n-1<slen)goto err1;
	if(!(mem=malloc(2*n-mdlen-2)))goto err1;
	memset(mem+n-mdlen-1,0,n-slen-1);
	memcpy(mem+2*n-slen-mdlen-2,src,slen);
	if(gcry_mgf1(wrk,mdlen,mem+n-1,n-mdlen-1,md))goto err2;
	for(i=0;i<mdlen;i++)wrk[i]^=mem[i+n-mdlen-1];
	if(gcry_mgf1(mem,n-mdlen-1,wrk,mdlen,md))goto err2;
	for(i=0;i<n-mdlen-1;i++)mem[i]^=mem[i+n-1];
	gcry_md_hash_buffer(md,wrk,p,plen);
	if(memcmp(mem,wrk,mdlen))goto err2;
	for(i=mdlen;i<n-mdlen-1;i++)if(mem[i])break;
	if(i==n-mdlen-1||mem[i]!=0x01)goto err2;
	if(dlen<(l=n-i-mdlen-2))goto err2;
	memcpy(dst,mem+i+1,l);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(mem,2*n-mdlen-2);
	free(mem);
	return l;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(mem,2*n-mdlen-2);
	free(mem);
err1:	return -1;
}

static int gcry_rsa_mpi_add_pss(void *ctx,struct gcry_rsa *rsa,
	unsigned char *out,unsigned char *in,int md)
{
	int i;
	int r=-1;
	int slen;
	int mdlen;
	int bits;
	int bytes;
	unsigned long long zero=0ULL;
	unsigned char *salt;
	unsigned char *p;
	gcry_md_hd_t h;

	if(gcry_md_open(&h,md,0))goto err1;
	if((mdlen=gcry_md_get_algo_dlen(md))<=0)goto err2;
	bits=(gcry_mpi_get_nbits(rsa->n)-1)&0x7; 
	bytes=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	slen=bytes-mdlen-2-(bits?0:1);
	if(slen-mdlen<0)goto err2;
	if(!bits)
	{
		*out++=0x00;
		bytes--;
	}       
	if(slen)
	{
		if(!(salt=malloc(slen)))goto err2;
		gcry_randomize(salt,slen,GCRY_STRONG_RANDOM);
	}
	else salt=NULL;
	gcry_md_write(h,&zero,sizeof(zero));
	gcry_md_write(h,in,mdlen);
	gcry_md_write(h,salt,slen);
	memcpy(out+bytes-mdlen-1,gcry_md_read(h,md),mdlen);
	if(gcry_mgf1(out,bytes-mdlen-1,out+bytes-mdlen-1,mdlen,md))goto err3;
	p=out+bytes-slen-mdlen-2;
	*p++^=0x01;
	for(i=0;i<slen;i++)*p++^=salt[i];
	if(bits)out[0]&=0xff>>(8-bits);
	out[bytes-1]=0xbc;
	r=0;

err3:	if(salt)
	{
		((struct usicrypt_thread *)ctx)->global->memclear(salt,slen);
		free(salt);
	}
err2:	gcry_md_close(h);
err1:	return r;
}

static int gcry_rsa_mpi_check_pss(void *ctx,struct gcry_rsa *rsa,
	unsigned char *hash,unsigned char *sig,int md)
{       
	int i;
	int r=-1;
	int mdlen;
	int bits;
	int bytes;
	unsigned long long zero=0ULL;
	unsigned char *wrk;
	gcry_md_hd_t h;
	
	if(gcry_md_open(&h,md,0))goto err1;
	if((mdlen=gcry_md_get_algo_dlen(md))<=0)goto err2;
	bits=(gcry_mpi_get_nbits(rsa->n)-1)&0x7;
	bytes=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(bytes-2*mdlen-2-(bits?0:1)<0)goto err2;
	if(*sig&(0xff<<bits))goto err2;
	if(!bits)
	{       
		sig++;
		bytes--;
	}
	if(bytes<mdlen)goto err2;
	if(sig[bytes-1]!=0xbc)goto err2;
	if(!(wrk=malloc(bytes-mdlen-1)))goto err2;
	if(gcry_mgf1(wrk,bytes-mdlen-1,sig+bytes-mdlen-1,mdlen,md))goto err3;
	for(i=0;i<bytes-mdlen-1;i++)wrk[i]^=sig[i];
	if(bits)wrk[0]&=0xff>>(8-bits);
	for(i=0;!wrk[i]&&i<bytes-mdlen-2;i++);
	if(wrk[i++]!=0x01)goto err3;
	gcry_md_write(h,&zero,sizeof(zero));
	gcry_md_write(h,hash,mdlen);
	gcry_md_write(h,wrk+i,bytes-mdlen-i-1);
	if(!memcmp(gcry_md_read(h,md),sig+bytes-mdlen-1,mdlen))r=0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,bytes-mdlen-1);
	free(wrk);
err2:	gcry_md_close(h);
err1:	return r;
}

static int gcry_rsa_mpi_add_type1(unsigned char *out,int olen,
	unsigned char *in,int ilen)
{
	if(ilen>olen-11)return -1;
	*out++=0x00;
	*out++=0x01;
	memset(out,0xff,olen-ilen-3);
	out+=olen-ilen-3;
	*out++=0x00;
	memcpy(out,in,ilen);
	return 0;
}

static int gcry_rsa_mpi_check_type1(unsigned char *out,int olen,
	unsigned char *in,int ilen)
{
	int i;

	if(*in++!=0x00||*in++!=0x01)return -1;
	for(ilen-=2,i=0;i<ilen;i++,in++)if(*in!=0xff)
	{
		if(*in)return -1;
		in++;
		break;
	}
	if(i<8||i==ilen)return -1;
	ilen-=i+1;
	if(ilen>olen)return -1;
	memcpy(out,in,ilen);
	return ilen;
}

static int gcry_rsa_mpi_add_type2(unsigned char *out,int olen,
	unsigned char *in,int ilen)
{
	int i;

	if(ilen>olen-11)return -1;
	*out++=0x00;
	*out++=0x02;
	gcry_randomize(out,olen-ilen-3,GCRY_STRONG_RANDOM);
	for(i=0;i<olen-ilen-3;i++)if(!out[i])out[i]=0x01;
	out+=olen-ilen-3;
	*out++=0x00;
	memcpy(out,in,ilen);
	return 0;
}

static int gcry_rsa_mpi_check_type2(unsigned char *out,int olen,
	unsigned char *in,int ilen)
{
	int i;

	if(*in++!=0x00||*in++!=0x02)return -1;
	for(ilen-=2,i=0;i<ilen;i++,in++)if(!*in)
	{
		in++;
		break;
	}
	if(i<8||i==ilen)return -1;
	ilen-=i+1;
	if(ilen>olen)return -1;
	memcpy(out,in,ilen);
	return ilen;
}

static void *gcry_rsa_do_sign_v15(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int l;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *sig=NULL;
	struct usicrypt_iov *iov=data;
	gcry_md_hd_t h;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_md_open(&h,type,GCRY_MD_FLAG_SECURE))goto err1;
	if(!mode)gcry_md_write(h,data,dlen);
	else for(l=0;l<dlen;l++)gcry_md_write(h,iov[l].data,iov[l].length);
	memcpy(hash,gcry_md_read(h,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(h);

	*slen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(!(tmp=malloc(*slen)))goto err1;
	if(!(sig=malloc(*slen)))goto err2;
	if(gcry_rsa_mpi_add_type1(tmp,*slen,hash,gcry_md_get_algo_dlen(type)))
		goto err3;
	if(!gcry_rsa_mpi_private(tmp,*slen,sig,&l,rsa)&&l==*slen)goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
	free(sig);
	sig=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*slen);
	free(tmp);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return sig;
}

static int gcry_rsa_do_verify_v15(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int r=-1;
	int l;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	struct usicrypt_iov *iov=data;
	gcry_md_hd_t h;
	unsigned char hash[64];
	unsigned char cmp[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_md_open(&h,type,GCRY_MD_FLAG_SECURE))goto err1;
	if(!mode)gcry_md_write(h,data,dlen);
	else for(l=0;l<dlen;l++)gcry_md_write(h,iov[l].data,iov[l].length);
	memcpy(hash,gcry_md_read(h,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(h);

	if(slen!=((gcry_mpi_get_nbits(rsa->n)+7)>>3))goto err1;
	if(!(tmp=malloc(slen)))goto err1;
	if(gcry_rsa_mpi_public(sig,slen,tmp,&l,rsa)||l!=slen)goto err2;
	if(gcry_rsa_mpi_check_type1(cmp,gcry_md_get_algo_dlen(type),tmp,slen)
		!=gcry_md_get_algo_dlen(type))goto err2;
	if(memcmp(hash,cmp,gcry_md_get_algo_dlen(type)))goto err2;
	r=0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,slen);
	free(tmp);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	((struct usicrypt_thread *)ctx)->global->memclear(cmp,sizeof(cmp));
	return r;
}

static void *gcry_rsa_do_sign_pss(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int l;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *sig=NULL;
	struct usicrypt_iov *iov=data;
	gcry_md_hd_t h;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_reseed(ctx))goto err1;

	if(gcry_md_open(&h,type,GCRY_MD_FLAG_SECURE))goto err1;
	if(!mode)gcry_md_write(h,data,dlen);
	else for(l=0;l<dlen;l++)gcry_md_write(h,iov[l].data,iov[l].length);
	memcpy(hash,gcry_md_read(h,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(h);

	*slen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(!(tmp=malloc(*slen)))goto err2;
	if(!(sig=malloc(*slen)))goto err3;
	if(gcry_rsa_mpi_add_pss(ctx,rsa,tmp,hash,type))goto err5;
	if(!gcry_rsa_mpi_private(tmp,*slen,sig,&l,rsa)&&l==*slen)goto err4;

	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
err5:	free(sig);
	sig=NULL;
err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*slen);
err3:	free(tmp);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return sig;
}

static int gcry_rsa_do_verify_pss(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int r=-1;
	int l;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	struct usicrypt_iov *iov=data;
	gcry_md_hd_t h;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_md_open(&h,type,GCRY_MD_FLAG_SECURE))goto err1;
	if(!mode)gcry_md_write(h,data,dlen);
	else for(l=0;l<dlen;l++)gcry_md_write(h,iov[l].data,iov[l].length);
	memcpy(hash,gcry_md_read(h,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(h);

	if(slen!=((gcry_mpi_get_nbits(rsa->n)+7)>>3))goto err2;
	if(!(tmp=malloc(slen)))goto err2;
	if(gcry_rsa_mpi_public(sig,slen,tmp,&l,rsa)||l!=slen)goto err3;
	if(gcry_rsa_mpi_check_pss(ctx,rsa,hash,tmp,type))goto err3;
	r=0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,slen);
	free(tmp);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return r;
}

#endif
#ifndef USICRYPT_NO_DH

static int gcry_dh_mpi_is_prime(gcry_mpi_t *prime1,gcry_mpi_t *prime2,int bits)
{
	if(gcry_rsa_dh_mpi_test_primes(prime1,bits))return -1;
	if(gcry_rsa_dh_mpi_test_primes(prime2,bits))return -1;
	if(gcry_rsa_dh_mpi_miller_rabin(prime1,bits))return -1;
	if(gcry_rsa_dh_mpi_miller_rabin(prime2,bits))return -1;
	return 0;
}

static int gcry_dh_mpi_gen_prime(gcry_mpi_t *prime,int bits)
{
	int r=-1;
	gcry_mpi_t p;
	gcry_mpi_t n;

	if(!(p=gcry_mpi_new(bits)))goto err1;
	if(!(n=gcry_mpi_new(bits)))goto err2;

	do
	{
		gcry_mpi_randomize(p,bits,GCRY_STRONG_RANDOM);
		gcry_mpi_set_highbit(p,bits-1);
		gcry_mpi_set_bit(p,0);
		gcry_mpi_set_bit(p,1);

		gcry_mpi_set_ui(n,3);
		gcry_mpi_mod(n,p,n);
		if(!gcry_mpi_cmp_ui(n,0))gcry_mpi_add_ui(p,p,8);
		else if(!gcry_mpi_cmp_ui(n,1))gcry_mpi_add_ui(p,p,4);

		gcry_mpi_rshift(n,p,1);

		while(1)
		{
			while(gcry_dh_mpi_is_prime(&p,&n,bits))
			{
				gcry_mpi_add_ui(p,p,12);
				gcry_mpi_add_ui(n,n,6);
			}
			if(gcry_prime_check(p,0)||gcry_prime_check(n,0))
			{
				gcry_mpi_add_ui(p,p,12);
				gcry_mpi_add_ui(n,n,6);
			}
			else break;
		}
	} while(gcry_mpi_get_nbits(p)!=bits);

	gcry_mpi_set(*prime,p);
	r=0;

	gcry_mpi_release(n);
err2:	gcry_mpi_release(p);
err1:	return r;
}

static int gcry_dh_mpi_parse_param(unsigned char *prm,int len,gcry_mpi_t *pval,
	gcry_mpi_t *gval)
{
	int h;
	int l;
	int plen;
	int glen;
	unsigned char *p;
	unsigned char *g;
	gcry_mpi_t tmp;

	if(gcry_asn_next(prm,len,0x30,&h,&l))goto err1;
	prm+=h;
	len-=h;

	if(gcry_asn_next(prm,len,0x02,&h,&l))goto err1;
	p=prm+h;
	plen=l;
	prm+=h+l;
	len-=h+l;

	if(gcry_asn_next(prm,len,0x02,&h,&l))goto err1;
	g=prm+h;
	glen=l;

	if(!plen||!glen||(*p&0x80)||(*g&0x80))goto err1;

	*pval=NULL;
	*gval=NULL;

	if(gcry_mpi_scan(pval,GCRYMPI_FMT_USG,p,plen,NULL))goto err2;
	if(gcry_mpi_scan(gval,GCRYMPI_FMT_USG,g,glen,NULL))goto err3;

	h=gcry_mpi_get_nbits(*pval);
	if(h<USICRYPT_DH_BITS_MIN||h>USICRYPT_DH_BITS_MAX)goto err3;
	if(!(tmp=gcry_mpi_new(h)))goto err3;
	if(gcry_mpi_cmp_ui(*pval,3)<0||gcry_mpi_cmp_ui(*gval,1)<=0||
		gcry_prime_check(*pval,0))goto err4;
	if(!gcry_mpi_cmp_ui(*gval,2))
	{
		gcry_mpi_set_ui(tmp,24);
		gcry_mpi_mod(tmp,*pval,tmp);
		if(gcry_mpi_cmp_ui(tmp,11))goto err4;
	}
	else if(!gcry_mpi_cmp_ui(*gval,3))
	{
		gcry_mpi_set_ui(tmp,12);
		gcry_mpi_mod(tmp,*pval,tmp);
		if(gcry_mpi_cmp_ui(tmp,5))goto err4;
	}
	else if(!gcry_mpi_cmp_ui(*gval,5))
	{
		gcry_mpi_set_ui(tmp,10);
		gcry_mpi_mod(tmp,*pval,tmp);
		if(gcry_mpi_cmp_ui(tmp,3)&&gcry_mpi_cmp_ui(tmp,7))goto err4;
	}
	gcry_mpi_release(tmp);
	return 0;

err4:	gcry_mpi_release(tmp);
err3:	if(*gval)gcry_mpi_release(*gval);
err2:	if(*pval)gcry_mpi_release(*pval);
err1:	return -1;
}

static gcry_mpi_t gcry_dh_mpi_generate(gcry_mpi_t pval)
{
	int bits;
	gcry_mpi_t key;

	if((bits=gcry_mpi_get_nbits(pval)-1)<=0)return NULL;
	if(!(key=gcry_mpi_snew(bits)))return NULL;
	gcry_mpi_randomize(key,bits,GCRY_STRONG_RANDOM);
	gcry_mpi_set_bit(key,bits-1);
	return key;
}

static gcry_mpi_t gcry_dh_mpi_pub_from_key(gcry_mpi_t key,gcry_mpi_t pval,
	gcry_mpi_t gval)

{
	int bits;
	gcry_mpi_t pub;

	if((bits=gcry_mpi_get_nbits(pval))<=0)return NULL;
	if(!(pub=gcry_mpi_new(bits)))return NULL;
	gcry_mpi_powm(pub,gval,key,pval);
	return pub;
}

static gcry_mpi_t gcry_dh_mpi_derive(gcry_mpi_t key,gcry_mpi_t pub,
	gcry_mpi_t pval)
{
	int bits;
	gcry_mpi_t sec;

	if(gcry_mpi_cmp_ui(pub,2)<0)return NULL;
	if((bits=gcry_mpi_get_nbits(pval))<=0)return NULL;
	if(!(sec=gcry_mpi_snew(bits)))return NULL;
	gcry_mpi_sub_ui(sec,pval,2);
	if(gcry_mpi_cmp(pub,sec)>0)
	{
		gcry_mpi_release(sec);
		sec=NULL;
	}
	else gcry_mpi_powm(sec,pub,key,pval);
	return sec;
}

static unsigned char *gcry_dh_mpi_get_val(void *ctx,gcry_mpi_t val,int *len)
{
	int bits;
	size_t l;
	unsigned char *data;

	if((bits=gcry_mpi_get_nbits(val))<0)goto err1;
	else if(!bits)
	{
		l=1;
		if(!(data=malloc(l)))goto err1;
		*data=0x00;
	}
	else
	{
		l=(bits+7)>>3;
		if(!(data=malloc(l)))goto err1;
		if(gcry_mpi_print(GCRYMPI_FMT_USG,data,l,&l,val))goto err2;
	}
	*len=l;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,l);
	free(data);
err1:	return NULL;
}

static gcry_mpi_t gcry_dh_mpi_set_pub(void *pub,int len)
{
	gcry_mpi_t p=NULL;

	if(len<0)goto err1;
	else if(!len)
	{
		if(!(p=gcry_mpi_new(0)))goto err1;
	}
	else if(gcry_mpi_scan(&p,GCRYMPI_FMT_USG,pub,len,NULL))goto err1;
	return p;

err1:	if(p)gcry_mpi_release(p);
	return NULL;
}

#endif
#ifndef USICRYPT_NO_EC

static int gcry_ec_mpi_check_pub(void *ctx,gcry_mpi_t pub,int id)
{
	int r=-1;
	int bytes;
	size_t n;
	gcry_ctx_t c;
	gcry_mpi_t x=NULL;
	gcry_mpi_t y=NULL;
	gcry_mpi_t z;
	gcry_mpi_point_t g;
	unsigned char *wrk;

	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if((n=gcry_mpi_get_nbits(pub))<=0)goto err2;
	bytes=(n+7)>>3;
	if(!(bytes&1)||bytes<3)goto err2;
	if(!(wrk=malloc(bytes)))goto err2;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,wrk,bytes,&n,pub)||n!=bytes)goto err3;
	if(*wrk!=0x04)goto err3;
	if(gcry_mpi_scan(&x,GCRYMPI_FMT_USG,wrk+1,(bytes-1)>>1,&n)||
		n!=((bytes-1)>>1))goto err4;
	if(gcry_mpi_scan(&y,GCRYMPI_FMT_USG,wrk+1+((bytes-1)>>1),
		(bytes-1)>>1,&n)||n!=((bytes-1)>>1))goto err5;
	if(!(z=gcry_mpi_new(1)))goto err5;
	gcry_mpi_set_ui(z,1);
	if(!(g=gcry_mpi_point_new(0)))goto err6;
	gcry_mpi_point_set(g,x,y,z);
	if(!(gcry_mpi_ec_curve_point(g,c)))goto err7;
	r=0;
err7:	gcry_mpi_point_release(g);
err6:	gcry_mpi_release(z);
err5:	if(y)gcry_mpi_release(y);
err4:	if(x)gcry_mpi_release(x);
err3:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,bytes);
	free(wrk);
err2:	gcry_ctx_release(c);
err1:	return r;
}

static gcry_mpi_t gcry_ec_mpi_generate(int id)
{
	int bits;
	gcry_ctx_t ctx;
	gcry_mpi_t key;
	gcry_mpi_t n;

	if(gcry_mpi_ec_new(&ctx,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if(!(n=gcry_mpi_ec_get_mpi("n",ctx,0)))goto err2;
	if((bits=gcry_mpi_get_nbits(n))<=0)goto err2;
	if(!(key=gcry_mpi_snew(bits)))goto err2;
	do
	{
		gcry_mpi_randomize(key,bits,GCRY_STRONG_RANDOM);
		if(mpi_test_bit(key,bits-1))mpi_set_highbit(key,bits-1);
		else
		{
			mpi_set_highbit(key,bits-1);
			mpi_clear_bit(key,bits-1);
		}
	} while(mpi_cmp_ui(key,0)<=0||mpi_cmp(key,n)>=0);
	gcry_ctx_release(ctx);
	return key;

err2:	gcry_ctx_release(ctx);
err1:	return NULL;
}

static gcry_mpi_t gcry_ec_mpi_pub_from_key(void *ctx,gcry_mpi_t key,int id)
{
	int bits;
	int bytes;
	int l;
	size_t n;
	gcry_ctx_t c;
	gcry_mpi_t p;
	gcry_mpi_t x;
	gcry_mpi_t y;
	gcry_mpi_point_t q;
	gcry_mpi_point_t g;
	gcry_mpi_t pub=NULL;
	unsigned char *wrk;

	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if(!(p=gcry_mpi_ec_get_mpi("p",c,0)))goto err2;
	if((bits=gcry_mpi_get_nbits(p))<=0)goto err2;
	bytes=(bits+7)>>3;
	if(!(q=gcry_mpi_point_new(0)))goto err2;
	if(!(g=gcry_mpi_ec_get_point("g",c,1)))goto err3;
	gcry_mpi_ec_mul(q,key,g,c);
	if(!(x=mpi_new(bits)))goto err4;
	if(!(y=mpi_new(bits)))goto err5;
	if(gcry_mpi_ec_get_affine(x,y,q,c))goto err6;
	if(!(wrk=malloc((bytes<<1)+1)))goto err6;
	memset(wrk+1,0,bytes<<1);
	wrk[0]=0x04;
	l=(gcry_mpi_get_nbits(x)+7)>>3;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,wrk+1+bytes-l,l,&n,x)||l!=n)
		goto err7;
	l=(gcry_mpi_get_nbits(y)+7)>>3;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,wrk+1+(bytes<<1)-l,l,&n,y)||l!=n)
		goto err7;
	if(gcry_mpi_scan(&pub,GCRYMPI_FMT_USG,wrk,(bytes<<1)+1,&n)||
		n!=(bytes<<1)+1)
	{
		if(pub)gcry_mpi_release(pub);
		pub=NULL;
	}
err7:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,(bytes<<1)+1);
	free(wrk);
err6:	gcry_mpi_release(y);
err5:	gcry_mpi_release(x);
err4:	gcry_mpi_point_release(g);
err3:	gcry_mpi_point_release(q);
err2:	gcry_ctx_release(c);
err1:	return pub;
}

static unsigned char *gcry_ec_mpi_derive(void *ctx,gcry_mpi_t key,
	gcry_mpi_t pub,int *slen,int id)
{
	int val;
	int bytes;
	size_t n;
	gcry_ctx_t c;
	gcry_mpi_t x=NULL;
	gcry_mpi_t y=NULL;
	gcry_mpi_t z;
	gcry_mpi_t p;
	gcry_mpi_t s;
	gcry_mpi_point_t g;
	gcry_mpi_point_t r;
	unsigned char *wrk;
	unsigned char *data=NULL;

	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if((val=gcry_mpi_get_nbits(pub))<=0)goto err2;
	bytes=(val+7)>>3;
	if(!(bytes&1)||bytes<3)goto err2;
	if(!(wrk=malloc(bytes)))goto err2;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,wrk,bytes,&n,pub)||n!=bytes)goto err3;
	if(*wrk!=0x04)goto err3;
	if(gcry_mpi_scan(&x,GCRYMPI_FMT_USG,wrk+1,(bytes-1)>>1,&n)||
		n!=((bytes-1)>>1))goto err4;
	if(gcry_mpi_scan(&y,GCRYMPI_FMT_USG,wrk+1+((bytes-1)>>1),
		(bytes-1)>>1,&n)||n!=((bytes-1)>>1))goto err5;
	if(!(z=gcry_mpi_new(1)))goto err5;
	gcry_mpi_set_ui(z,1);
	if(!(g=gcry_mpi_point_new(0)))goto err6;
	gcry_mpi_point_set(g,x,y,z);
	if(!(gcry_mpi_ec_curve_point(g,c)))goto err7;
	if(!(r=gcry_mpi_point_new(0)))goto err7;
	gcry_mpi_ec_mul(r,key,g,c);
	if(!(p=gcry_mpi_ec_get_mpi("p",c,0)))goto err8;
	if((val=gcry_mpi_get_nbits(p))<=0)goto err8;
	if(!(s=gcry_mpi_snew(val)))goto err8;
	if(gcry_mpi_ec_get_affine(s,NULL,r,c))goto err9;
	*slen=(val+7)>>3;
	if(!(data=malloc(*slen)))goto err9;
	if((val=gcry_mpi_get_nbits(s))<=0)goto err10;
	val=(val+7)>>3;
	if(val!=*slen)memset(data,0,*slen-val);
	if(val)if(gcry_mpi_print(GCRYMPI_FMT_USG,data+*slen-val,val,&n,s)||
		n!=val)goto err10;
	goto err9;

err10:	((struct usicrypt_thread *)ctx)->global->memclear(data,*slen);
	free(data);
	data=NULL;
err9:	gcry_mpi_release(s);
err8:	gcry_mpi_point_release(r);
err7:	gcry_mpi_point_release(g);
err6:	gcry_mpi_release(z);
err5:	if(y)gcry_mpi_release(y);
err4:	if(x)gcry_mpi_release(x);
err3:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,bytes);
	free(wrk);
err2:	gcry_ctx_release(c);
err1:	return data;
}

static unsigned char *gcry_ec_mpi_get_pub(void *ctx,gcry_mpi_t pub,int *len,
	int id)
{
	int l;
	size_t n;
	unsigned char *data;

	if(((gcry_mpi_get_nbits(pub)+7)>>3)!=gcry_ec_map[id].xylen)goto err1;
	*len=gcry_ec_map[id].publen;
	l=gcry_ec_map[id].phdrlen;
	if(!(data=malloc(*len)))goto err1;
	memcpy(data,gcry_ec_map[id].phdr,l);
	if(gcry_mpi_print(GCRYMPI_FMT_USG,data+l,*len-l,&n,pub)||n!=*len-l)
		goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
}

static gcry_mpi_t gcry_ec_mpi_set_pub(void *ctx,unsigned char *pub,int len,
	int *id)
{
	int idx;
	int h;
	int l;
	int plen;
	size_t n;
	gcry_mpi_t pval=NULL;
	unsigned char *pptr;

	if(gcry_asn_next(pub,len,0x30,&h,&l))goto err1;
	pub+=h;
	len-=h;

	if(gcry_asn_next(pub,len,0x30,&h,&l))goto err1;
	pptr=pub+h+l;
	plen=len-h-l;
	pub+=h;
	len=l;

	if(gcry_asn_next(pub,len,0x06,&h,&l))goto err1;
	if(l!=7||memcmp(pub+h,gcry_ansi_pubkey_type,7))goto err1;
	pub+=h+l;
	len-=h+l;

	if(gcry_asn_next(pub,len,0x06,&h,&l))goto err1;
	for(idx=0;idx<USICRYPT_TOT_EC_CURVES;idx++)
		if(gcry_ec_map[idx].oidlen==l&&
			!memcmp(pub+h,gcry_ec_map[idx].oid,l))break;
	if(idx==USICRYPT_TOT_EC_CURVES)goto err1;

	if(gcry_asn_next(pptr,plen,0x03,&h,&l))goto err1;
	if(l-1!=gcry_ec_map[idx].xylen||pptr[h]||pptr[h+1]!=0x04)goto err1;
	if(gcry_mpi_scan(&pval,GCRYMPI_FMT_USG,pptr+h+1,l-1,&n)||n!=l-1)
		goto err2;
	if(gcry_ec_mpi_check_pub(ctx,pval,idx))goto err2;
	*id=idx;
	return pval;

err2:	if(pval)gcry_mpi_release(pval);
err1:	return NULL;
}

static unsigned char *gcry_ec_mpi_get_key(void *ctx,gcry_mpi_t key,
	gcry_mpi_t pub,int *len,int id)
{
	int dlen;
	int klen;
	int plen;
	size_t n;
	unsigned char *ptr;
	unsigned char *data;

	klen=(gcry_mpi_get_nbits(key)+7)>>3;
	plen=(gcry_mpi_get_nbits(pub)+7)>>3;
	if(klen>gcry_ec_map[id].kmax||plen!=gcry_ec_map[id].xylen)goto err1;
	dlen=gcry_ec_map[id].xylen+gcry_ec_map[id].k1h2len+klen+1+
		sizeof(gcry_ec_k1h1);
	*len=dlen+2;
	if(dlen>=0x80)*len+=1;
	if(dlen>=0x100)*len+=1;
	if(!(ptr=data=malloc(*len)))goto err1;
	*ptr++=0x30;
	if(dlen<0x80)*ptr++=(unsigned char)dlen;
	else if(dlen<0x100)
	{
		*ptr++=0x81;
		*ptr++=(unsigned char)dlen;
	}
	else
	{
		*ptr++=0x82;
		*ptr++=(unsigned char)(dlen>>8);
		*ptr++=(unsigned char)dlen;
	}
	memcpy(ptr,gcry_ec_k1h1,sizeof(gcry_ec_k1h1));
	ptr+=sizeof(gcry_ec_k1h1);
	*ptr++=(unsigned char)klen;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,ptr,klen,&n,key)||n!=klen)goto err2;
	ptr+=klen;
	memcpy(ptr,gcry_ec_map[id].k1h2,gcry_ec_map[id].k1h2len);
	ptr+=gcry_ec_map[id].k1h2len;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,ptr,plen,&n,pub)||n!=plen)goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
}

static gcry_mpi_t gcry_ec_mpi_set_key(void *ctx,unsigned char *key,int len,
	int *id,gcry_mpi_t *pub)
{
	int h;
	int l;
	int idx;
	int klen;
	size_t n;
	gcry_ctx_t c;
	gcry_mpi_t pval=NULL;
	gcry_mpi_t kval=NULL;
	gcry_mpi_t nn;
	unsigned char *kptr;
	unsigned char *tmp;

	if(gcry_asn_next(key,len,0x30,&h,&l))goto err1;
	key+=h;
	len-=h;

	if(gcry_asn_next(key,len,0x02,&h,&l))goto err1;
	if(l!=1||key[h]!=0x01)goto err1;
	key+=h+l;
	len-=h+l;

	if(gcry_asn_next(key,len,0x04,&h,&l))goto err1;
	kptr=key+h;
	klen=l;
	key+=h+l;
	len-=h+l;

	if(gcry_asn_next(key,len,0xa0,&h,&l))goto err1;
	key+=h;
	len-=h;

	if(gcry_asn_next(key,len,0x06,&h,&l))goto err1;
	for(idx=0;idx<USICRYPT_TOT_EC_CURVES;idx++)
		if(gcry_ec_map[idx].oidlen==l&&
			!memcmp(key+h,gcry_ec_map[idx].oid,l))break;
	if(idx==USICRYPT_TOT_EC_CURVES)goto err1;
	key+=h+l;
	len-=h+l;

	if(!gcry_asn_next(key,len,0xa1,&h,&l))
	{
		key+=h;
		len-=h;
		if(gcry_asn_next(key,len,0x03,&h,&l))goto err1;
		if(l-1!=gcry_ec_map[idx].xylen||key[h]||key[h+1]!=0x04)
			goto err1;
		if(gcry_mpi_scan(&pval,GCRYMPI_FMT_USG,key+h+1,l-1,&n)||n!=l-1)
			goto err2;
	}

	if(!(tmp=gcry_malloc_secure(klen)))goto err2;
	memcpy(tmp,kptr,klen);
	if(gcry_mpi_scan(&kval,GCRYMPI_FMT_USG,tmp,klen,&n)||n!=klen)
	{
		((struct usicrypt_thread *)ctx)->global->memclear(tmp,klen);
		gcry_free(tmp);
		goto err3;
	}
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,klen);
	gcry_free(tmp);

	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[idx].gcry_name))goto err3;
	if(!(nn=gcry_mpi_ec_get_mpi("n",c,0)))goto err4;
	if(mpi_cmp_ui(kval,0)<=0||mpi_cmp(kval,nn)>=0)goto err4;
	gcry_ctx_release(c);

	if(!pval)
	{
		if(!(pval=gcry_ec_mpi_pub_from_key(ctx,kval,idx)))goto err3;
	}
	else if(gcry_ec_mpi_check_pub(ctx,pval,idx))goto err3;
	else
	{
		if(!(nn=gcry_ec_mpi_pub_from_key(ctx,kval,idx)))goto err3;
		n=gcry_mpi_cmp(nn,pval);
		gcry_mpi_release(nn);
		if(n)goto err3;
	}

	*id=idx;
	*pub=pval;
	return kval;

err4:	gcry_ctx_release(c);
err3:	if(kval)gcry_mpi_release(kval);
err2:	if(pval)gcry_mpi_release(pval);
err1:	return NULL;
}

static unsigned char *gcry_ec_mpi_sign(void *ctx,gcry_mpi_t key,
	unsigned char *data,int dlen,int *slen,int id,int md,int mode)
{
	int bits;
	int len;
	int type;
	size_t nn;
	gcry_mpi_t h=NULL;
	gcry_mpi_t k=NULL;
	gcry_mpi_t n;
	gcry_mpi_t x;
	gcry_mpi_t r;
	gcry_mpi_t s;
	gcry_mpi_t dr;
	gcry_mpi_t sum;
	gcry_mpi_t k1;
	gcry_mpi_point_t g;
	gcry_mpi_point_t i;
	gcry_ctx_t c;
	gcry_md_hd_t mh;
	struct usicrypt_iov *iov=(void *)data;
	unsigned char *ptr;
	unsigned char *sig=NULL;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_reseed(ctx))goto err1;
	if(!mode)gcry_md_hash_buffer(type,hash,data,dlen);
	else
	{
		if(gcry_md_open(&mh,type,GCRY_MD_FLAG_SECURE))goto err1;
		for(len=0;len<dlen;len++)
			gcry_md_write(mh,iov[len].data,iov[len].length);
		memcpy(hash,gcry_md_read(mh,type),gcry_md_get_algo_dlen(type));
		gcry_md_close(mh);
	}
	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if(!(n=gcry_mpi_ec_get_mpi("n",c,0)))goto err2;
	if((bits=gcry_mpi_get_nbits(n))<=0)goto err2;
	len=(bits+7)>>3;
	if(len>gcry_md_get_algo_dlen(type))len=gcry_md_get_algo_dlen(type);
	if(gcry_mpi_scan(&h,GCRYMPI_FMT_USG,hash,len,&nn)||nn!=len)goto err3;
	len=gcry_mpi_get_nbits(h);
	if(len>bits)gcry_mpi_rshift(h,h,len-bits);
	if(!(g=gcry_mpi_ec_get_point("g",c,1)))goto err3;
	if(!(i=gcry_mpi_point_new(0)))goto err4;
	if(!(x=gcry_mpi_new(bits)))goto err5;
	if(!(r=gcry_mpi_new(bits)))goto err6;
	if(!(dr=gcry_mpi_new(bits)))goto err7;
	if(!(sum=gcry_mpi_new(bits)))goto err8;
	if(!(k1=gcry_mpi_new(bits)))goto err9;
	if(!(s=gcry_mpi_new(bits)))goto err10;
	do
	{
		do
		{
			if(k)gcry_mpi_release(k);
			if(!(k=gcry_ec_mpi_generate(id)))goto err11;
			gcry_mpi_ec_mul(i,k,g,c);
			if(gcry_mpi_ec_get_affine(x,NULL,i,c))goto err11;
			gcry_mpi_mod(r,x,n);
		} while(!gcry_mpi_cmp_ui(r,0));
		gcry_mpi_mulm(dr,key,r,n);
		gcry_mpi_addm(sum,h,dr,n);
		if(!gcry_mpi_invm(k1,k,n))goto err11;
		gcry_mpi_mulm(s,k1,sum,n);
	} while(!gcry_mpi_cmp_ui(s,0));
	len=4;
	bits=gcry_mpi_get_nbits(r);
	len+=(bits+7)>>3;
	if(!(bits&7))len++;
	bits=gcry_mpi_get_nbits(s);
	len+=(bits+7)>>3;
	if(!(bits&7))len++;
	if(len<0x80)*slen=len+2;
	else if(len<0x100)*slen=len+3;
	else *slen=len+4;
	if(!(ptr=sig=malloc(*slen)))goto err11;
	*ptr++=0x30;
	if(len<0x80)*ptr++=(unsigned char)len;
	else if(len<0x100)
	{
		*ptr++=0x81;
		*ptr++=(unsigned char)len;
	}
	else
	{
		*ptr++=0x82;
		*ptr++=(unsigned char)(len>>8);
		*ptr++=(unsigned char)(len);
	}
	*ptr++=0x02;
	bits=gcry_mpi_get_nbits(r);
	len=(bits+7)>>3;
	*ptr++=(unsigned char)(len+((!(bits&7))?1:0));
	if(!(bits&7))*ptr++=0x00;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,ptr,len,&nn,r)||nn!=len)goto err12;
	ptr+=len;
	*ptr++=0x02;
	bits=gcry_mpi_get_nbits(s);
	len=(bits+7)>>3;
	*ptr++=(unsigned char)(len+((!(bits&7))?1:0));
	if(!(bits&7))*ptr++=0x00;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,ptr,len,&nn,s)||nn!=len)goto err12;
	goto err11;

err12:	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
	free(sig);
	sig=NULL;
err11:	if(k)gcry_mpi_release(k);
	gcry_mpi_release(s);
err10:	gcry_mpi_release(k1);
err9:	gcry_mpi_release(sum);
err8:	gcry_mpi_release(dr);
err7:	gcry_mpi_release(r);
err6:	gcry_mpi_release(x);
err5:	gcry_mpi_point_release(i);
err4:	gcry_mpi_point_release(g);
err3:	if(h)gcry_mpi_release(h);
err2:	gcry_ctx_release(c);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return sig;
}

static int gcry_ec_mpi_verify(void *ctx,gcry_mpi_t pub,unsigned char *data,
	int dlen,unsigned char *sig,int slen,int id,int md,int mode)
{
	int res=-1;
	int hh;
	int ll;
	int bits;
	int len;
	int rl;
	int sl;
	int type;
	size_t nn;
	gcry_ctx_t c;
	gcry_mpi_t h=NULL;
	gcry_mpi_t r=NULL;
	gcry_mpi_t s=NULL;
	gcry_mpi_t x=NULL;
	gcry_mpi_t y=NULL;
	gcry_mpi_t z;
	gcry_mpi_t n;
	gcry_mpi_t h0;
	gcry_mpi_t h1;
	gcry_mpi_t h2;
	gcry_mpi_t x0;
	gcry_mpi_t y0;
	gcry_mpi_t z0;
	gcry_mpi_t xx;
	gcry_mpi_point_t g;
	gcry_mpi_point_t q;
	gcry_mpi_point_t q0;
	gcry_mpi_point_t q1;
	gcry_mpi_point_t q2;
	gcry_md_hd_t mh;
	struct usicrypt_iov *iov=(void *)data;
	unsigned char *rptr;
	unsigned char *sptr;
	unsigned char *wrk;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_asn_next(sig,slen,0x30,&hh,&ll))goto err1;
	sig+=hh;
	slen-=hh;

	if(gcry_asn_next(sig,slen,0x02,&hh,&ll))goto err1;
	rptr=sig+hh;
	rl=ll;
	sig+=hh+ll;
	slen-=hh+ll;

	if(gcry_asn_next(sig,slen,0x02,&hh,&ll))goto err1;
	sptr=sig+hh;
	sl=ll;

	if(gcry_mpi_ec_new(&c,NULL,gcry_ec_map[id].gcry_name))goto err1;
	if(!mode)gcry_md_hash_buffer(type,hash,data,dlen);
	else
	{
		if(gcry_md_open(&mh,type,GCRY_MD_FLAG_SECURE))goto err1;
		for(len=0;len<dlen;len++)
			gcry_md_write(mh,iov[len].data,iov[len].length);
		memcpy(hash,gcry_md_read(mh,type),gcry_md_get_algo_dlen(type));
		gcry_md_close(mh);
	}
	if((bits=gcry_mpi_get_nbits(pub))<=0)goto err2;
	len=(bits+7)>>3;
	if(!(len&1)||len<3)goto err2;
	if(!(wrk=malloc(len)))goto err2;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,wrk,len,&nn,pub)||nn!=len)goto err3;
	if(*wrk!=0x04)goto err3;
	if(gcry_mpi_scan(&x,GCRYMPI_FMT_USG,wrk+1,(len-1)>>1,&nn)||
		nn!=((len-1)>>1))goto err4;
	if(gcry_mpi_scan(&y,GCRYMPI_FMT_USG,wrk+1+((len-1)>>1),
		(len-1)>>1,&nn)||nn!=((len-1)>>1))goto err5;
	if(!(z=gcry_mpi_new(1)))goto err5;
	gcry_mpi_set_ui(z,1);
	if(!(q=gcry_mpi_point_new(0)))goto err6;
	gcry_mpi_point_set(q,x,y,z);
	if(!(gcry_mpi_ec_curve_point(q,c)))goto err7;
	if(!(n=gcry_mpi_ec_get_mpi("n",c,0)))goto err7;
	if((bits=gcry_mpi_get_nbits(n))<=0)goto err7;
	len=(bits+7)>>3;
	if(len>gcry_md_get_algo_dlen(type))len=gcry_md_get_algo_dlen(type);
	if(gcry_mpi_scan(&h,GCRYMPI_FMT_USG,hash,len,&nn)||nn!=len)goto err8;
	len=gcry_mpi_get_nbits(h);
	if(len>bits)gcry_mpi_rshift(h,h,len-bits);
	if(!(h0=gcry_mpi_new(bits)))goto err8;
	if(!(h1=gcry_mpi_new(bits)))goto err9;
	if(!(h2=gcry_mpi_new(bits)))goto err10;
	if(!(q0=gcry_mpi_point_new(0)))goto err11;
	if(!(q1=gcry_mpi_point_new(0)))goto err12;
	if(!(q2=gcry_mpi_point_new(0)))goto err13;
	if(gcry_mpi_scan(&r,GCRYMPI_FMT_USG,rptr,rl,&nn)||nn!=rl)goto err14;
	if(gcry_mpi_cmp_ui(r,0)<=0||gcry_mpi_cmp(r,n)>=0)goto err14;
	if(gcry_mpi_scan(&s,GCRYMPI_FMT_USG,sptr,sl,&nn)||nn!=sl)goto err15;
	if(gcry_mpi_cmp_ui(s,0)<=0||gcry_mpi_cmp(s,n)>=0)goto err15;
	if(!(g=gcry_mpi_ec_get_point("g",c,1)))goto err15;
	if(!gcry_mpi_invm(h0,s,n))goto err16;
	gcry_mpi_mulm(h1,h,h0,n);
	gcry_mpi_ec_mul(q1,h1,g,c);
	gcry_mpi_mulm(h2,r,h0,n);
	gcry_mpi_ec_mul(q2,h2,q,c);
	gcry_mpi_ec_add(q0,q1,q2,c);
	if(!(x0=gcry_mpi_new(bits)))goto err16;
	if(!(y0=gcry_mpi_new(bits)))goto err17;
	if(!(z0=gcry_mpi_new(bits)))goto err18;
	gcry_mpi_point_get(x0,y0,z0,q0);
	if(!gcry_mpi_cmp_ui(z0,0))goto err19;
	if(!(xx=gcry_mpi_new(bits)))goto err19;
	if(gcry_mpi_ec_get_affine(xx,NULL,q0,c))goto err20;
	gcry_mpi_mod(xx,xx,n);
	if(gcry_mpi_cmp(xx,r))goto err20;
	res=0;

err20:	gcry_mpi_release(xx);
err19:	gcry_mpi_release(z0);
err18:	gcry_mpi_release(y0);
err17:	gcry_mpi_release(x0);
err16:	gcry_mpi_point_release(g);
err15:	if(s)gcry_mpi_release(s);
err14:	if(r)gcry_mpi_release(r);
	gcry_mpi_point_release(q2);
err13:	gcry_mpi_point_release(q1);
err12:	gcry_mpi_point_release(q0);
err11:	gcry_mpi_release(h2);
err10:	gcry_mpi_release(h1);
err9:	gcry_mpi_release(h0);
err8:	if(h)gcry_mpi_release(h);
err7:	gcry_mpi_point_release(q);
err6:	gcry_mpi_release(z);
err5:	if(y)gcry_mpi_release(y);
err4:	if(x)gcry_mpi_release(x);
err3:	((struct usicrypt_thread *)ctx)->global->
		memclear(wrk,(gcry_mpi_get_nbits(pub)+7)>>3);
	free(wrk);
err2:	gcry_ctx_release(c);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return res;
}

#endif
#ifndef USICRYPT_NO_X25519

static gcry_mpi_t gcry_x25519_mpi_generate(void)
{
	gcry_mpi_t key;

	if(!(key=gcry_mpi_snew(256)))return NULL;
	gcry_mpi_randomize(key,256,GCRY_STRONG_RANDOM);
	gcry_mpi_set_bit(key,254);
	gcry_mpi_clear_bit(key,255);
	gcry_mpi_clear_bit(key,0);
	gcry_mpi_clear_bit(key,1);
	gcry_mpi_clear_bit(key,2);
	return key;
}

static gcry_mpi_t gcry_x25519_mpi_pub_fom_key(gcry_mpi_t key)
{
	gcry_mpi_t pub;
	gcry_mpi_point_t q;
	gcry_mpi_point_t g;
	gcry_ctx_t ctx;

	if(!(pub=gcry_mpi_new(256)))goto err1;
	if(gcry_mpi_ec_new(&ctx,NULL,"Curve25519"))goto err2;
	if(!(q=gcry_mpi_point_new(0)))goto err3;
	if(!(g=gcry_mpi_ec_get_point("g",ctx,1)))goto err4;
	gcry_mpi_ec_mul(q,key,g,ctx);
	if(gcry_mpi_ec_get_affine(pub,NULL,q,ctx))goto err5;
	gcry_mpi_point_release(g);
	gcry_mpi_point_release(q);
	gcry_ctx_release(ctx);
	return pub;

err5:	gcry_mpi_point_release(g);
err4:	gcry_mpi_point_release(q);
err3:	gcry_ctx_release(ctx);
err2:	gcry_mpi_release(pub);
err1:	return NULL;
}

static gcry_mpi_t gcry_x25519_mpi_derive(gcry_mpi_t key,gcry_mpi_t pub)
{
	gcry_mpi_t sec;
	gcry_mpi_t y;
	gcry_mpi_t z;
	gcry_mpi_point_t q;
	gcry_mpi_point_t p;
	gcry_ctx_t ctx;

	if(!(y=gcry_mpi_new(0)))goto err1;
	if(!(z=gcry_mpi_new(1)))goto err2;
	if(!(p=gcry_mpi_point_new(0)))goto err3;
	if(!(q=gcry_mpi_point_new(0)))goto err4;
	if(gcry_mpi_ec_new(&ctx,NULL,"Curve25519"))goto err5;
	gcry_mpi_set_ui(z,1);
	gcry_mpi_point_set(p,pub,y,z);
	if(!gcry_mpi_ec_curve_point(p,ctx))goto err6;
	gcry_mpi_ec_mul(q,key,p,ctx);
	if(!(sec=gcry_mpi_snew(256)))goto err6;
	if(gcry_mpi_ec_get_affine(sec,NULL,q,ctx))goto err7;
	gcry_ctx_release(ctx);
	gcry_mpi_point_release(q);
	gcry_mpi_point_release(p);
	gcry_mpi_release(z);
	gcry_mpi_release(y);
	return sec;

err7:	gcry_mpi_release(sec);
err6:	gcry_ctx_release(ctx);
err5:	gcry_mpi_point_release(q);
err4:	gcry_mpi_point_release(p);
err3:	gcry_mpi_release(z);
err2:	gcry_mpi_release(y);
err1:	return NULL;
}

static int gcry_x25519_mpi_check_pub(gcry_mpi_t pub)
{
	int r=-1;
	gcry_mpi_t y;
	gcry_mpi_t z;
	gcry_mpi_point_t p;
	gcry_ctx_t ctx;

	if(!(y=gcry_mpi_new(0)))goto err1;
	if(!(z=gcry_mpi_new(1)))goto err2;
	if(!(p=gcry_mpi_point_new(0)))goto err3;
	if(gcry_mpi_ec_new(&ctx,NULL,"Curve25519"))goto err4;
	gcry_mpi_set_ui(z,1);
	gcry_mpi_point_set(p,pub,y,z);
	if(!gcry_mpi_ec_curve_point(p,ctx))goto err5;
	r=0;
err5:	gcry_ctx_release(ctx);
err4:	gcry_mpi_point_release(p);
err3:	gcry_mpi_release(z);
err2:	gcry_mpi_release(y);
err1:	return r;
}

static int gcry_x25519_mpi_to_le32(void *ctx,gcry_mpi_t val,unsigned char *bfr)
{
	int i;
	size_t n=0;
	unsigned char tmp[32];

	if(gcry_mpi_print(GCRYMPI_FMT_USG,tmp,sizeof(tmp),&n,val))goto err1;
	for(i=0;i<n;i++)bfr[i]=tmp[n-i-1];
	for(;i<32;i++)bfr[i]=0x00;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	return 0;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	return -1;
}

static int gcry_x25519_mpi_from_le32(void *ctx,gcry_mpi_t *val,
	unsigned char *bfr)
{
	int i;
	unsigned char tmp[32];

	for(*val=NULL,i=0;i<32;i++)tmp[i]=bfr[31-i];
	if(gcry_mpi_scan(val,GCRYMPI_FMT_USG,tmp,sizeof(tmp),NULL))goto err1;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	return 0;

err1:	if(*val)gcry_mpi_release(*val);
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	return -1;
}

#endif
#if !defined(USICRYPT_NO_AES) || !defined(USICRYPT_NO_CAMELLIA) || \
	!defined(USICRYPT_NO_CHACHA)
#if !defined(USICRYPT_NO_STREAM) || !defined(USICRYPT_NO_ECB) || \
	!defined(USICRYPT_NO_CBC) || !defined(USICRYPT_NO_CTS) || \
	!defined(USICRYPT_NO_CFB) || !defined(USICRYPT_NO_CFB8) || \
	!defined(USICRYPT_NO_OFB) || !defined(USICRYPT_NO_CTR)

static void *gcry_cipher_init(void *ctx,int type,int mode,int flags,
	void *key,int klen,void *iv,void *ctr,int extra)
{
	int id;
	int len=16;
	struct gcry_cipher *cipher;
	struct usicrypt_global *tmp;

	switch(type)
	{
	case 0:	switch(klen)
		{
		case 128:
			id=GCRY_CIPHER_AES;
			break;
		case 192:
			id=GCRY_CIPHER_AES192;
			break;
		case 256:
			id=GCRY_CIPHER_AES256;
			break;
		default:goto err1;
		}
		break;
	case 1:	switch(klen)
		{
		case 128:
			id=GCRY_CIPHER_CAMELLIA128;
			break;
		case 192:
			id=GCRY_CIPHER_CAMELLIA192;
			break;
		case 256:
			id=GCRY_CIPHER_CAMELLIA256;
			break;
		default:goto err1;
		}
		break;
	case 2:	if(klen==256)
		{
			id=GCRY_CIPHER_CHACHA20;
			len=8;
			break;
		}
	default:goto err1;
	}
	if(extra)extra+=sizeof(struct usicrypt_global *);
	if(!(cipher=malloc(sizeof(struct gcry_cipher)+extra)))goto err1;
	if(gcry_cipher_open(&cipher->h,id,mode,GCRY_CIPHER_SECURE|flags))
		goto err2;
	if(gcry_cipher_setkey(cipher->h,key,klen>>3))goto err3;
	if(iv)
	{
		if(extra)
		{
			tmp=((struct usicrypt_thread *)ctx)->global;
			memcpy(cipher->extra,&tmp,
				sizeof(struct usicrypt_global *));
			memcpy(cipher->extra+sizeof(struct usicrypt_global *),
				iv,len);
		}
		else if(gcry_cipher_setiv(cipher->h,iv,len))goto err3;
	}
	if(ctr)if(gcry_cipher_setctr(cipher->h,ctr,len))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return cipher;

err3:	gcry_cipher_close(cipher->h);
err2:	free(cipher);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

#endif
#if !defined(USICRYPT_NO_CFB) || !defined(USICRYPT_NO_STREAM)

static int gcry_cipher_1_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(src==dst)
	{
		if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,
			slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,
		slen,src,slen))return -1;
	return 0;
}

#endif
#if !defined(USICRYPT_NO_ECB) || !defined(USICRYPT_NO_CBC) || \
	!defined(USICRYPT_NO_CTS) || !defined(USICRYPT_NO_CFB) || \
	!defined(USICRYPT_NO_OFB) || !defined(USICRYPT_NO_CTR) || \
	!defined(USICRYPT_NO_STREAM)

static void gcry_cipher_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_cipher *)ctx)->h);
	free(ctx);
}

#endif
#endif
#if !defined(USICRYPT_NO_AES) || !defined(USICRYPT_NO_CAMELLIA)
#if !defined(USICRYPT_NO_CBC) || !defined(USICRYPT_NO_CTS) || \
	!defined(USICRYPT_NO_CFB) || !defined(USICRYPT_NO_OFB)

static void gcry_cipher_iv16_reset(void *ctx,void *iv)
{
	gcry_cipher_reset(((struct gcry_cipher *)ctx)->h);
	gcry_cipher_setiv(((struct gcry_cipher *)ctx)->h,iv,16);
}

#endif
#if !defined(USICRYPT_NO_ECB) || !defined(USICRYPT_NO_CBC)

static int gcry_cipher_16_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,
			NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,src,
		slen))return -1;
	return 0;
}

static int gcry_cipher_16_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,slen,
			NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,slen,src,
		slen))return -1;
	return 0;
}

#endif
#if !defined(USICRYPT_NO_CTS)

static int gcry_cipher_17_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen<=16)return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,
			NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,src,
		slen))return -1;
	return 0;
}

static int gcry_cipher_17_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen<=16)return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,slen,
			NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,slen,src,
		slen))return -1;
	return 0;
}

#endif
#if !defined(USICRYPT_NO_CFB)

static int gcry_cipher_1_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(src==dst)
	{
		if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,
			slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(((struct gcry_cipher *)ctx)->h,dst,
		slen,src,slen))return -1;
	return 0;
}

#endif
#if !defined(USICRYPT_NO_CFB8)

static int gcry_cipher_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct gcry_cipher_cfb8 *cipher=ctx;

	while(slen--)
	{
		if(gcry_cipher_encrypt(cipher->hd,cipher->mem,16,cipher->iv,16))
			return -1;
		memmove(cipher->iv,cipher->iv+1,15);
		*d++=cipher->iv[15]=*s++^cipher->mem[0];
	}
	return 0;
}

static int gcry_cipher_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct gcry_cipher_cfb8 *cipher=ctx;

	while(slen--)
	{
		if(gcry_cipher_encrypt(cipher->hd,cipher->mem,16,cipher->iv,16))
			return -1;
		memmove(cipher->iv,cipher->iv+1,15);
		cipher->iv[15]=*s;
		*d++=*s++^cipher->mem[0];
	}
	return 0;
}

static void gcry_cipher_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct gcry_cipher_cfb8 *)ctx)->iv,iv,16);
}

static void gcry_cipher_cfb8_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_cipher_cfb8 *)ctx)->hd);
	((struct gcry_cipher_cfb8 *)ctx)->global->
		memclear(((struct gcry_cipher_cfb8 *)ctx)->iv,16);
	((struct gcry_cipher_cfb8 *)ctx)->global->
		memclear(((struct gcry_cipher_cfb8 *)ctx)->mem,16);
	free(ctx);
}

#endif
#if !defined(USICRYPT_NO_OFB) || !defined(USICRYPT_NO_CTR)

static int gcry_cipher_zero_crypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *d;
	unsigned char zero[16];

	if(!src)
	{
		memset(zero,0,sizeof(zero));
		for(d=dst;slen>16;slen-=16,d+=16)
			if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,
				d,16,zero,16))return -1;
		if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,d,slen,
			zero,slen))return -1;
	}
	else if(src==dst)
	{
		if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,
			NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(((struct gcry_cipher *)ctx)->h,dst,slen,src,
		slen))return -1;
	return 0;
}

#endif
#if !defined(USICRYPT_NO_CTR)

static void gcry_cipher_ctr_reset(void *ctx,void *iv)
{
	gcry_cipher_reset(((struct gcry_cipher *)ctx)->h);
	gcry_cipher_setctr(((struct gcry_cipher *)ctx)->h,iv,16);
}

#endif
#if !defined(USICRYPT_NO_XTS)

static int gcry_cipher_xts_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct gcry_cipher_xts *cipher=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(gcry_cipher_encrypt(cipher->tw,cipher->twk,16,iv,16))return -1;

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)cipher->wrk[i]=s[i]^cipher->twk[i];
		if(gcry_cipher_encrypt(cipher->ed,d,16,cipher->wrk,16))
			return -1;
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=cipher->twk[i];
			cipher->twk[i]=(unsigned char)(n|=(cipher->twk[i]<<1));
		}
		if(n)cipher->twk[0]^=0x87;
	}

	if(slen)
	{
		d-=16;
		memcpy(d+16,d,slen);
		memcpy(cipher->wrk,s,slen);
		memcpy(cipher->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)cipher->wrk[i]^=cipher->twk[i];
		if(gcry_cipher_encrypt(cipher->ed,d,16,cipher->wrk,16))
			return -1;
		for(i=0;i<16;i++)d[i]^=cipher->twk[i];
	}

	return 0;
}

static int gcry_cipher_xts_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct gcry_cipher_xts *cipher=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(gcry_cipher_encrypt(cipher->tw,cipher->twk,16,iv,16))return -1;

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)cipher->wrk[i]=s[i]^cipher->twk[i];
		if(gcry_cipher_decrypt(cipher->ed,d,16,cipher->wrk,16))
			return -1;
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=cipher->twk[i];
			cipher->twk[i]=(unsigned char)(n|=(cipher->twk[i]<<1));
		}
		if(n)cipher->twk[0]^=0x87;
	}

	if(slen)
	{
		memcpy(cipher->mem,cipher->twk,16);
		for(n=0,i=0;i<16;i++,n>>=8)
			cipher->twk[i]=(unsigned char)(n|=(cipher->twk[i]<<1));
		if(n)cipher->twk[0]^=0x87;
		for(i=0;i<16;i++)cipher->wrk[i]=s[i]^cipher->twk[i];
		if(gcry_cipher_decrypt(cipher->ed,d,16,cipher->wrk,16))
			return -1;
		for(i=0;i<16;i++)d[i]^=cipher->twk[i];
		memcpy(d+16,d,slen);
		memcpy(cipher->wrk,s+16,slen);
		memcpy(cipher->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)cipher->wrk[i]^=cipher->mem[i];
		if(gcry_cipher_decrypt(cipher->ed,d,16,cipher->wrk,16))
			return -1;
		for(i=0;i<16;i++)d[i]^=cipher->mem[i];
	}

	return 0;
}

static void *gcry_cipher_xts_init(void *ctx,int type,void *key,int klen)
{
	int mode;
	struct gcry_cipher_xts *cipher;

	switch(klen)
	{
	case 256:
		mode=(type?GCRY_CIPHER_CAMELLIA128:GCRY_CIPHER_AES);
		break;
	case 512:
		mode=(type?GCRY_CIPHER_CAMELLIA256:GCRY_CIPHER_AES256);
		break;
	default:goto err1;
	}
	if(!(cipher=malloc(sizeof(struct gcry_cipher_xts))))goto err1;
	if(gcry_cipher_open(&cipher->ed,mode,GCRY_CIPHER_MODE_ECB,
		GCRY_CIPHER_SECURE))goto err2;
	if(gcry_cipher_open(&cipher->tw,mode,GCRY_CIPHER_MODE_ECB,
		GCRY_CIPHER_SECURE))goto err3;
	if(gcry_cipher_setkey(cipher->ed,key,klen>>4))goto err4;
	if(gcry_cipher_setkey(cipher->tw,key+(klen>>4),klen>>4))goto err4;
	cipher->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return cipher;

err4:	gcry_cipher_close(cipher->tw);
err3:	gcry_cipher_close(cipher->ed);
err2:	free(cipher);
err1:   ((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void gcry_cipher_xts_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_cipher_xts *)ctx)->ed);
	gcry_cipher_close(((struct gcry_cipher_xts *)ctx)->tw);
	((struct gcry_cipher_xts *)ctx)->global->
		memclear(((struct gcry_cipher_xts *)ctx)->twk,16);
	((struct gcry_cipher_xts *)ctx)->global->
		memclear(((struct gcry_cipher_xts *)ctx)->wrk,16);
	((struct gcry_cipher_xts *)ctx)->global->
		memclear(((struct gcry_cipher_xts *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int gcry_cipher_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct gcry_cipher_essiv *cipher=ctx;

	if(slen&0xf)return -1;
	if(gcry_cipher_encrypt(cipher->aux,cipher->iv,16,iv,16))return -1;
	gcry_cipher_reset(cipher->h);
	if(gcry_cipher_setiv(cipher->h,cipher->iv,16))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(cipher->h,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(cipher->h,dst,slen,src,slen))return -1;
	return 0;
}

static int gcry_cipher_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct gcry_cipher_essiv *cipher=ctx;

	if(slen&0xf)return -1;
	if(gcry_cipher_encrypt(cipher->aux,cipher->iv,16,iv,16))return -1;
	gcry_cipher_reset(cipher->h);
	if(gcry_cipher_setiv(cipher->h,cipher->iv,16))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(cipher->h,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(cipher->h,dst,slen,src,slen))return -1;
	return 0;
}

static void *gcry_cipher_essiv_init(void *ctx,int type,void *key,int klen)
{
	int mode;
	struct gcry_cipher_essiv *cipher;
	unsigned char tmp[32];

	switch(klen)
	{
	case 128:
		mode=(type?GCRY_CIPHER_CAMELLIA128:GCRY_CIPHER_AES);
		break;
	case 192:
		mode=(type?GCRY_CIPHER_CAMELLIA192:GCRY_CIPHER_AES192);
		break;
	case 256:
		mode=(type?GCRY_CIPHER_CAMELLIA256:GCRY_CIPHER_AES256);
		break;
	default:goto err1;
	}
	if(!(cipher=malloc(sizeof(struct gcry_cipher_essiv))))goto err1;
	cipher->global=((struct usicrypt_thread *)ctx)->global;
	if(gcry_cipher_open(&cipher->h,mode,GCRY_CIPHER_MODE_CBC,
		GCRY_CIPHER_SECURE))goto err2;
	if(gcry_cipher_setkey(cipher->h,key,klen>>3))goto err3;
	gcry_md_hash_buffer(GCRY_MD_SHA256,tmp,key,klen>>3);
	if(gcry_cipher_open(&cipher->aux,
		type?GCRY_CIPHER_CAMELLIA256:GCRY_CIPHER_AES256,
		GCRY_CIPHER_MODE_ECB,GCRY_CIPHER_SECURE))goto err4;
	if(gcry_cipher_setkey(cipher->aux,tmp,32))goto err5;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return cipher;

err5:	gcry_cipher_close(cipher->aux);
err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
err3:	gcry_cipher_close(cipher->h);
err2:	free(cipher);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void gcry_cipher_essiv_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_cipher_essiv *)ctx)->h);
	gcry_cipher_close(((struct gcry_cipher_essiv *)ctx)->aux);
	((struct gcry_cipher_essiv *)ctx)->global->
		memclear(((struct gcry_cipher_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CMAC

static int gcry_cipher_cmac(void *ctx,int mode,void *key,int klen,
	void *src,int slen,void *dst)
{
	int r=-1;
	size_t len=16;
	gcry_mac_hd_t h;

	if(gcry_mac_open(&h,mode,GCRY_MAC_FLAG_SECURE,NULL))goto err1;
	if(gcry_mac_setkey(h,key,klen>>3))goto err2;
	if(gcry_mac_write(h,src,slen))goto err2;
	if(!gcry_mac_read(h,dst,&len))r=0;
err2:	gcry_mac_close(h);
err1:	return r;
}

#ifndef USICRYPT_NO_IOV

static int gcry_cipher_cmac_iov(void *ctx,int mode,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	int r=-1;
	size_t len=16;
	gcry_mac_hd_t h;

	if(gcry_mac_open(&h,mode,GCRY_MAC_FLAG_SECURE,NULL))goto err1;
	if(gcry_mac_setkey(h,key,klen>>3))goto err2;
	for(i=0;i<niov;i++)if(gcry_mac_write(h,iov[i].data,iov[i].length))
		goto err2;
	if(!gcry_mac_read(h,dst,&len))r=0;
err2:	gcry_mac_close(h);
err1:	return r;
}

#endif
#endif
#endif
#if !defined(USICRYPT_NO_CHACHA)
#if !defined(USICRYPT_NO_STREAM)

static void gcry_cipher_iv8_reset(void *ctx,void *iv)
{
	gcry_cipher_reset(((struct gcry_cipher *)ctx)->h);
	gcry_cipher_setiv(((struct gcry_cipher *)ctx)->h,iv,8);
}

#endif
#ifndef USICRYPT_NO_POLY

static int gcry_chacha_poly_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	struct gcry_chacha_poly *chp=ctx;

	if(gcry_cipher_setiv(chp->ctx,iv,12))return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(chp->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(chp->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(chp->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(chp->ctx,tag,16))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_chacha_poly_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	struct gcry_chacha_poly *chp=ctx;

	if(gcry_cipher_setiv(chp->ctx,iv,12))return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(chp->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(chp->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(chp->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(chp->ctx,tag,16))return -1;
	return 0;
}

#endif

static int gcry_chacha_poly_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	struct gcry_chacha_poly *chp=ctx;

	if(gcry_cipher_setiv(chp->ctx,iv,12))return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(chp->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(chp->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(chp->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(chp->ctx,tag,16))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_chacha_poly_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	struct gcry_chacha_poly *chp=ctx;

	if(gcry_cipher_setiv(chp->ctx,iv,12))return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(chp->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(chp->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(chp->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(chp->ctx,tag,16))return -1;
	return 0;
}

#endif

static void *gcry_chacha_poly_init(void *ctx,void *key,int klen,int ilen,
	int tlen)
{
	struct gcry_chacha_poly *chp;

	if(klen!=256||ilen!=12||tlen!=16)goto err1;
	if(!(chp=malloc(sizeof(struct gcry_chacha_poly))))goto err1;
	if(gcry_cipher_open(&chp->ctx,GCRY_CIPHER_CHACHA20,
		GCRY_CIPHER_MODE_POLY1305,GCRY_CIPHER_SECURE))goto err2;
	if(gcry_cipher_setkey(chp->ctx,key,32))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return chp;

err3:	gcry_cipher_close(chp->ctx);
err2:	free(chp);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return NULL;
}

static void gcry_chacha_poly_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_chacha_poly *)ctx)->ctx);
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_GCM

static int gcry_aes_gcm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(aes->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_aes_gcm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(aes->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#endif

static int gcry_aes_gcm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(aes->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_aes_gcm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(aes->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#endif

static void *gcry_aes_gcm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	int mode;
	struct gcry_aes_xcm *aes;

	switch(klen)
	{
	case 128:
		mode=GCRY_CIPHER_AES;
		break;
	case 192:
		mode=GCRY_CIPHER_AES192;
		break;
	case 256:
		mode=GCRY_CIPHER_AES256;
		break;
	default:goto err1;
	}
	if(!(aes=malloc(sizeof(struct gcry_aes_xcm))))goto err1;
	if(gcry_cipher_open(&aes->ctx,mode,GCRY_CIPHER_MODE_GCM,
		GCRY_CIPHER_SECURE))goto err2;
	if(gcry_cipher_setkey(aes->ctx,key,klen>>3))goto err3;
	aes->ilen=ilen;
	aes->tlen=tlen;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err3:	gcry_cipher_close(aes->ctx);
err2:	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void gcry_aes_gcm_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_aes_xcm *)ctx)->ctx);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CCM

static int gcry_aes_ccm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	uint64_t prm[3];
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	prm[0]=slen;
	prm[1]=(aad&&alen)?alen:0;
	prm[2]=aes->tlen;
	if(gcry_cipher_ctl(aes->ctx,GCRYCTL_SET_CCM_LENGTHS,prm,sizeof(prm)))
		return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(aes->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_aes_ccm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	uint64_t prm[3];
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	prm[0]=slen;
	prm[1]=alen;
	prm[2]=aes->tlen;
	if(gcry_cipher_ctl(aes->ctx,GCRYCTL_SET_CCM_LENGTHS,prm,sizeof(prm)))
		return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(aes->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_encrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_encrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_gettag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#endif

static int gcry_aes_ccm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	uint64_t prm[3];
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	prm[0]=slen;
	prm[1]=(aad&&alen)?alen:0;
	prm[2]=aes->tlen;
	if(gcry_cipher_ctl(aes->ctx,GCRYCTL_SET_CCM_LENGTHS,prm,sizeof(prm)))
		return -1;
	if(aad&&alen)if(gcry_cipher_authenticate(aes->ctx,aad,alen))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int gcry_aes_ccm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	uint64_t prm[3];
	struct gcry_aes_xcm *aes=ctx;

	if(gcry_cipher_setiv(aes->ctx,iv,aes->ilen))return -1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	prm[0]=slen;
	prm[1]=alen;
	prm[2]=aes->tlen;
	if(gcry_cipher_ctl(aes->ctx,GCRYCTL_SET_CCM_LENGTHS,prm,sizeof(prm)))
		return -1;
	for(i=0;i<niov;i++)if(gcry_cipher_authenticate(aes->ctx,iov[i].data,
		iov[i].length))return -1;
	if(src==dst)
	{
		if(gcry_cipher_decrypt(aes->ctx,dst,slen,NULL,0))return -1;
	}
	else if(gcry_cipher_decrypt(aes->ctx,dst,slen,src,slen))return -1;
	if(gcry_cipher_checktag(aes->ctx,tag,aes->tlen))return -1;
	return 0;
}

#endif

static void *gcry_aes_ccm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	int mode;
	struct gcry_aes_xcm *aes;

	switch(klen)
	{
	case 128:
		mode=GCRY_CIPHER_AES;
		break;
	case 192:
		mode=GCRY_CIPHER_AES192;
		break;
	case 256:
		mode=GCRY_CIPHER_AES256;
		break;
	default:goto err1;
	}
	if(!(aes=malloc(sizeof(struct gcry_aes_xcm))))goto err1;
	if(gcry_cipher_open(&aes->ctx,mode,GCRY_CIPHER_MODE_CCM,
		GCRY_CIPHER_SECURE))goto err2;
	if(gcry_cipher_setkey(aes->ctx,key,klen>>3))goto err3;
	aes->ilen=ilen;
	aes->tlen=tlen;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err3:	gcry_cipher_close(aes->ctx);
err2:	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void gcry_aes_ccm_exit(void *ctx)
{
	gcry_cipher_close(((struct gcry_aes_xcm *)ctx)->ctx);
	free(ctx);
}

#endif
#endif

int USICRYPT(random)(void *ctx,void *data,int len)
{
	if((((struct usicrypt_thread *)ctx)->total+=1)>=10000)
	{
		if(gcry_reseed(ctx))return -1;
		((struct usicrypt_thread *)ctx)->total=0;
	}
	gcry_randomize(data,len,GCRY_STRONG_RANDOM);
	return 0;
}

int USICRYPT(digest_size)(void *ctx,int md)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return gcry_md_get_algo_dlen(GCRY_MD_SHA1);
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return gcry_md_get_algo_dlen(GCRY_MD_SHA256);
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return gcry_md_get_algo_dlen(GCRY_MD_SHA384);
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return gcry_md_get_algo_dlen(GCRY_MD_SHA512);
#endif
#endif
	default:return -1;
	}
}

int USICRYPT(digest)(void *ctx,int md,void *in,int len,void *out)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		gcry_md_hash_buffer(GCRY_MD_SHA1,out,in,len);
		return 0;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		gcry_md_hash_buffer(GCRY_MD_SHA256,out,in,len);
		return 0;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		gcry_md_hash_buffer(GCRY_MD_SHA384,out,in,len);
		return 0;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		gcry_md_hash_buffer(GCRY_MD_SHA512,out,in,len);
		return 0;
#endif
#endif
	default:return -1;
	}
}

int USICRYPT(digest_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *out)
{
	int r=-1;
	int i;
	int digest;
	gcry_md_hd_t h;

	switch(md)
	{
#if !defined(USICRYPT_NO_DIGEST) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=GCRY_MD_SHA512;
		break;
#endif
#endif
	default:goto err1;
	}

	if(gcry_md_open(&h,digest,GCRY_MD_FLAG_SECURE))goto err1;
	for(i=0;i<niov;i++)gcry_md_write(h,iov[i].data,iov[i].length);
	memcpy(out,gcry_md_read(h,digest),gcry_md_get_algo_dlen(digest));
	r=0;
	gcry_md_close(h);
err1:	return r;
}

int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,int klen,
	void *out)
{
	int type;
	gcry_md_hd_t hm;

	switch(md)
	{
#ifndef USICRYPT_NO_HMAC
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
#endif
	default:goto err1;
	}

	if(gcry_md_open(&hm,type,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE))
		goto err1;
	if(gcry_md_setkey(hm,key,klen))goto err2;
	gcry_md_write(hm,data,dlen);
	memcpy(out,gcry_md_read(hm,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(hm);
	return 0;

err2:	gcry_md_close(hm);
err1:	return -1;
}

int USICRYPT(hmac_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *key,int klen,void *out)
{
	int r=-1;
	int i;
	int digest;
	gcry_md_hd_t hm;

	switch(md)
	{
#if !defined(USICRYPT_NO_HMAC) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=GCRY_MD_SHA512;
		break;
#endif
#endif
	default:goto err1;
	}

	if(gcry_md_open(&hm,digest,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE))
		goto err1;
	if(gcry_md_setkey(hm,key,klen))goto err2;
	for(i=0;i<niov;i++)gcry_md_write(hm,iov[i].data,iov[i].length);
	memcpy(out,gcry_md_read(hm,digest),gcry_md_get_algo_dlen(digest));
	r=0;
err2:	gcry_md_close(hm);
err1:	return r;
}

int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	int iter,void *out)
{
	int r=0;

	switch(md)
	{
#ifndef USICRYPT_NO_PBKDF2
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		if(gcry_kdf_derive(key,klen,GCRY_KDF_PBKDF2,GCRY_MD_SHA1,
			salt,slen,iter,gcry_md_get_algo_dlen(GCRY_MD_SHA1),
			out))r=-1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		if(gcry_kdf_derive(key,klen,GCRY_KDF_PBKDF2,GCRY_MD_SHA256,
			salt,slen,iter,gcry_md_get_algo_dlen(GCRY_MD_SHA256),
			out))r=-1;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		if(gcry_kdf_derive(key,klen,GCRY_KDF_PBKDF2,GCRY_MD_SHA384,
			salt,slen,iter,gcry_md_get_algo_dlen(GCRY_MD_SHA384),
			out))r=-1;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		if(gcry_kdf_derive(key,klen,GCRY_KDF_PBKDF2,GCRY_MD_SHA512,
			salt,slen,iter,gcry_md_get_algo_dlen(GCRY_MD_SHA512),
			out))r=-1;
		break;
#endif
#endif
	default:r=-1;
		break;
	}
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
	return r;
}

int USICRYPT(hkdf)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	void *info,int ilen,void *out)
{
#ifndef USICRYPT_NO_HKDF
	int type;
	gcry_md_hd_t hm;
	unsigned char s[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(!salt||!slen)
	{
		slen=gcry_md_get_algo_dlen(type);
		salt=s;
		memset(s,0,slen);
	}
	if(gcry_md_open(&hm,type,GCRY_MD_FLAG_HMAC|GCRY_MD_FLAG_SECURE))
		goto err1;
	if(gcry_md_setkey(hm,salt,slen))goto err2;
	gcry_md_write(hm,key,klen);
	memcpy(out,gcry_md_read(hm,type),gcry_md_get_algo_dlen(type));
	gcry_md_reset(hm);
	if(gcry_md_setkey(hm,out,gcry_md_get_algo_dlen(type)))goto err2;
	gcry_md_write(hm,info,ilen);
	s[0]=1;
	gcry_md_write(hm,s,1);
	memcpy(out,gcry_md_read(hm,type),gcry_md_get_algo_dlen(type));
	gcry_md_close(hm);
	return 0;

err2:	gcry_md_close(hm);
err1:	return -1;
#else
	return -1;
#endif
}

void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	int i;
	int n;
	unsigned char *s=in;
	unsigned char *d;
	unsigned char *data=NULL;

	*olen=(ilen/3+(ilen%3?1:0))<<2;
	if(!(d=data=malloc(*olen+1)))goto err1;
	for(n=ilen-ilen%3,i=0;i<n;i+=3)
	{
		*d++=gcry_b64enc[s[i]>>2];
		*d++=gcry_b64enc[((s[i]<<4)|(s[i+1]>>4))&0x3f];
		*d++=gcry_b64enc[((s[i+1]<<2)|(s[i+2]>>6))&0x3f];
		*d++=gcry_b64enc[s[i+2]&0x3f];
	}
	if(i<ilen)
	{
		*d++=gcry_b64enc[(s[i]>>2)&0x3f];
		if(i+1<ilen)
		{
			*d++=gcry_b64enc[((s[i]<<4)+(s[i+1]>>4))&0x3f];
			*d++=gcry_b64enc[(s[i+1]<<2)&0x3f];
		}
		else
		{
			*d++=gcry_b64enc[(s[i]<<4)&0x3f];
			*d++='=';
		}
		*d++='=';
	}
	*d=0;
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	int i;
	int n=0;
	unsigned char *s=in;
	unsigned char *d;
	unsigned char *data=NULL;

	if(ilen<=0||(ilen&3))goto err1;
	for(i=0;i<ilen;i++)if(s[i]=='=')
	{
		if(i+1==ilen)n=1;
		else if(i+2==ilen&&s[i+1]=='=')n=2;
		else goto err1;
		break;
	}
	else if(gcry_b64dec[s[i]]==0xff)goto err1;
	*olen=(ilen>>2)*3-n;
	if(!(d=data=malloc(*olen)))goto err1;
	for(ilen-=(n?4:0),i=0;i<ilen;i+=4)
	{
		*d++=(gcry_b64dec[s[i]]<<2)|(gcry_b64dec[s[i+1]]>>4);
		*d++=(gcry_b64dec[s[i+1]]<<4)|(gcry_b64dec[s[i+2]]>>2);
		*d++=(gcry_b64dec[s[i+2]]<<6)|gcry_b64dec[s[i+3]];
	}
	switch(n)
	{
	case 1:	*d++=(gcry_b64dec[s[i]]<<2)|(gcry_b64dec[s[i+1]]>>4);
		*d=(gcry_b64dec[s[i+1]]<<4)|(gcry_b64dec[s[i+2]]>>2);
		break;
	case 2:	*d=(gcry_b64dec[s[i]]<<2)|(gcry_b64dec[s[i+1]]>>4);
		break;
	}
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_generate)(void *ctx,int bits)
{
#ifndef USICRYPT_NO_RSA
	if(bits<USICRYPT_RSA_BITS_MIN||bits>USICRYPT_RSA_BITS_MAX||(bits&7))
		goto err1;
	if(gcry_reseed(ctx))goto err1;
	return gcry_rsa_mpi_generate(bits,USICRYPT_RSA_EXPONENT);

err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(rsa_size)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	struct gcry_rsa *rsa=key;

	return gcry_mpi_get_nbits(rsa->n);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_RSA
	int l1;
	int l2;
	int sum0;
	int sum1;
	int sum2;
	int r;
	unsigned char *ptr;
	unsigned char *data;
	struct gcry_rsa *rsa=key;

	l1=gcry_rsa_mpi_int_size(rsa->n);
	l2=gcry_rsa_mpi_int_size(rsa->e);
	sum0=l1+l2;
	sum1=gcry_rsa_mpi_hdr_add(sum0)+1;
	sum2=gcry_rsa_mpi_hdr_add(sum1);
	*len=gcry_rsa_mpi_hdr_add(sum2+sizeof(gcry_rsa_pub_oid)+6);
	if(!(ptr=data=malloc(*len)))goto err1;
	ptr+=gcry_rsa_mpi_write_hdr(0x30,ptr,sum2+sizeof(gcry_rsa_pub_oid)+6);
	ptr+=gcry_rsa_mpi_write_hdr(0x30,ptr,sizeof(gcry_rsa_pub_oid)+4);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(gcry_rsa_pub_oid);
	memcpy(ptr,gcry_rsa_pub_oid,sizeof(gcry_rsa_pub_oid));
	ptr+=sizeof(gcry_rsa_pub_oid);
	*ptr++=0x05;
	*ptr++=0x00;
	ptr+=gcry_rsa_mpi_write_hdr(0x03,ptr,sum1);
	*ptr++=0x00;
	ptr+=gcry_rsa_mpi_write_hdr(0x30,ptr,sum0);
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->n))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->e))==-1)goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int h;
	int l;
	gcry_mpi_t n;
	gcry_mpi_t e;
	struct gcry_rsa *rsa;
	unsigned char *pub=key;

	if(gcry_asn_next(pub,len,0x30,&h,&l))goto err1;
	pub+=h;
	len-=h;

	if(gcry_asn_next(pub,len,0x30,&h,&l))goto err1;
	pub+=h;
	len-=h;

	if(gcry_asn_next(pub,len,0x06,&h,&l))goto err1;
	if(l!=sizeof(gcry_rsa_pub_oid)||memcmp(pub+h,gcry_rsa_pub_oid,l))
		goto err1;
	pub+=h+l;
	len-=h+l;

	if(gcry_asn_next(pub,len,0x05,&h,&l))goto err1;
	if(l)goto err1;
	pub+=h;
	len-=h;

	if(gcry_asn_next(pub,len,0x03,&h,&l))goto err1;
	if(l<1||pub[h])goto err1;
	pub+=h+1;
	len-=h+1;

	if(gcry_asn_next(pub,len,0x30,&h,&l))goto err1;
	pub+=h;
	len-=h;

	if(gcry_asn_next(pub,len,0x02,&h,&l))goto err1;
	if(!(n=gcry_rsa_mpi_read_int(ctx,pub+h,l,0)))goto err1;
	pub+=h+l;
	len-=h+l;

	if(gcry_asn_next(pub,len,0x02,&h,&l))goto err2;
	if(!(e=gcry_rsa_mpi_read_int(ctx,pub+h,l,0)))goto err2;

	if(!gcry_mpi_cmp_ui(n,0)||!gcry_mpi_cmp_ui(e,0))goto err3;
	if(!gcry_mpi_test_bit(n,0)||!gcry_mpi_test_bit(e,0))goto err3;
	h=gcry_mpi_get_nbits(n);
	l=gcry_mpi_get_nbits(e);
	if(h<USICRYPT_RSA_BITS_MIN||h>USICRYPT_RSA_BITS_MAX||l<2)goto err3;
	if(gcry_mpi_cmp(e,n)>=0)goto err3;

	if(!(rsa=malloc(sizeof(struct gcry_rsa))))goto err3;
	rsa->n=n;
	rsa->e=e;
	rsa->d=NULL;
	rsa->p=NULL;
	rsa->q=NULL;
	rsa->e1=NULL;
	rsa->e2=NULL;
	rsa->c=NULL;
	return rsa;

err3:	gcry_mpi_release(e);
err2:	gcry_mpi_release(n);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_RSA
	int ln;
	int le;
	int ld;
	int lp;
	int lq;
	int le1;
	int le2;
	int lc;
	int sum;
	int r;
	unsigned char *ptr;
	unsigned char *data;
	struct gcry_rsa *rsa=key;

	ln=gcry_rsa_mpi_int_size(rsa->n);
	le=gcry_rsa_mpi_int_size(rsa->e);
	ld=gcry_rsa_mpi_int_size(rsa->d);
	lp=gcry_rsa_mpi_int_size(rsa->p);
	lq=gcry_rsa_mpi_int_size(rsa->q);
	le1=gcry_rsa_mpi_int_size(rsa->e1);
	le2=gcry_rsa_mpi_int_size(rsa->e2);
	lc=gcry_rsa_mpi_int_size(rsa->c);
	sum=ln+le+ld+lp+lq+le1+le2+lc+3;
	*len=gcry_rsa_mpi_hdr_add(sum);
	if(!(ptr=data=malloc(*len)))goto err1;
	ptr+=gcry_rsa_mpi_write_hdr(0x30,ptr,sum);
	*ptr++=0x02;
	*ptr++=0x01;
	*ptr++=0x00;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->n))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->e))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->d))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->p))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->q))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->e1))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->e2))==-1)goto err2;
	ptr+=r;
	if((r=gcry_rsa_mpi_write_int(ptr,rsa->c))==-1)goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int h;
	int l;
	gcry_mpi_t n;
	gcry_mpi_t e;
	gcry_mpi_t d;
	gcry_mpi_t p;
	gcry_mpi_t q;
	gcry_mpi_t e1;
	gcry_mpi_t e2;
	gcry_mpi_t c;
	struct gcry_rsa *rsa;
	unsigned char *prv=key;

	if(gcry_asn_next(prv,len,0x30,&h,&l))goto err1;
	prv+=h;
	len-=h;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err1;
	if(l!=1||prv[h])goto err1;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err1;
	if(!(n=gcry_rsa_mpi_read_int(ctx,prv+h,l,0)))goto err1;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err2;
	if(!(e=gcry_rsa_mpi_read_int(ctx,prv+h,l,0)))goto err2;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err3;
	if(!(d=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err3;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err4;
	if(!(p=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err4;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err5;
	if(!(q=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err5;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err6;
	if(!(e1=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err6;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err7;
	if(!(e2=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err7;
	prv+=h+l;
	len-=h+l;

	if(gcry_asn_next(prv,len,0x02,&h,&l))goto err8;
	if(!(c=gcry_rsa_mpi_read_int(ctx,prv+h,l,1)))goto err8;

	if(!gcry_mpi_cmp_ui(n,0)||!gcry_mpi_cmp_ui(e,0))goto err9;
	if(!gcry_mpi_test_bit(n,0)||!gcry_mpi_test_bit(e,0))goto err9;
	h=gcry_mpi_get_nbits(n);
	l=gcry_mpi_get_nbits(e);
	if(h<USICRYPT_RSA_BITS_MIN||h>USICRYPT_RSA_BITS_MAX||l<2)goto err9;
	if(gcry_mpi_cmp(e,n)>=0)goto err9;
	if(gcry_rsa_mpi_check(n,e,d,p,q,e1,e2,c))goto err9;

	if(!(rsa=malloc(sizeof(struct gcry_rsa))))goto err9;
	rsa->n=n;
	rsa->e=e;
	rsa->d=d;
	rsa->p=p;
	rsa->q=q;
	rsa->e1=e1;
	rsa->e2=e2;
	rsa->c=c;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return rsa;

err9:	gcry_mpi_release(c);
err8:	gcry_mpi_release(e2);
err7:	gcry_mpi_release(e1);
err6:	gcry_mpi_release(q);
err5:	gcry_mpi_release(p);
err4:	gcry_mpi_release(d);
err3:	gcry_mpi_release(e);
err2:	gcry_mpi_release(n);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(rsa_sign_v15)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return gcry_rsa_do_sign_v15(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return gcry_rsa_do_sign_v15(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return gcry_rsa_do_verify_v15(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return gcry_rsa_do_verify_v15(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return gcry_rsa_do_sign_pss(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return gcry_rsa_do_sign_pss(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return gcry_rsa_do_verify_pss(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return gcry_rsa_do_verify_pss(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l=0;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;

	if(gcry_reseed(ctx))goto err1;
	*olen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(dlen>*olen-11)goto err1;
	if(!(tmp=malloc(*olen)))goto err1;
	if(!(out=malloc(*olen)))goto err2;
	if(gcry_rsa_mpi_add_type2(tmp,*olen,data,dlen))goto err3;
	if(!gcry_rsa_mpi_public(tmp,*olen,out,&l,rsa)&&l==*olen)goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
err1:	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;

	*olen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(dlen!=*olen)goto err1;
	if(!(tmp=malloc(*olen)))goto err1;
	if(!(out=malloc(*olen)))goto err2;
	if(gcry_rsa_mpi_private(data,*olen,tmp,&l,rsa)||l!=*olen)goto err3;
	if(tmp[0])goto err3;
	if((l=gcry_rsa_mpi_check_type2(out,*olen,tmp,*olen))==-1)goto err3;
	out=USICRYPT(do_realloc)(ctx,out,*olen,l);
	*olen=l;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
err1:	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_encrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l=0;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(gcry_reseed(ctx))goto err1;
	*olen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(dlen>*olen-2*gcry_md_get_algo_dlen(type)-2)goto err1;
	if(!(tmp=malloc(*olen)))goto err1;
	if(!(out=malloc(*olen)))goto err2;
	if(gcry_add_oaep_mgf1(ctx,tmp,*olen,data,dlen,NULL,0,type))
		goto err3;
	if(!gcry_rsa_mpi_public(tmp,*olen,out,&l,rsa)&&l==*olen)goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
err1:	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l;
	int type;
	struct gcry_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=GCRY_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=GCRY_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=GCRY_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=GCRY_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	*olen=(gcry_mpi_get_nbits(rsa->n)+7)>>3;
	if(dlen!=*olen)goto err1;
	if(!(tmp=malloc(*olen)))goto err1;
	if(!(out=malloc(*olen)))goto err2;
	if(gcry_rsa_mpi_private(data,*olen,tmp,&l,rsa)||l!=*olen)goto err3;
	if(tmp[0])goto err3;
	if((l=gcry_check_oaep_mgf1(ctx,out,*olen,tmp+1,*olen-1,*olen,NULL,0,
		type))==-1)goto err3;
	out=USICRYPT(do_realloc)(ctx,out,*olen,l);
	*olen=l;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
err1:	return out;
#else
	return NULL;
#endif
}

void USICRYPT(rsa_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	struct gcry_rsa *rsa=key;

	if(rsa->n)gcry_mpi_release(rsa->n);
	if(rsa->e)gcry_mpi_release(rsa->e);
	if(rsa->d)gcry_mpi_release(rsa->d);
	if(rsa->p)gcry_mpi_release(rsa->p);
	if(rsa->q)gcry_mpi_release(rsa->q);
	if(rsa->e1)gcry_mpi_release(rsa->e1);
	if(rsa->e2)gcry_mpi_release(rsa->e2);
	if(rsa->c)gcry_mpi_release(rsa->c);
	free(rsa);
#endif
}

void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len)
{
#ifndef USICRYPT_NO_DH
	int l;
	int n;
	size_t nn;
	gcry_mpi_t p;
	gcry_mpi_t x;
	unsigned char *bfr;
	unsigned char *data;
	unsigned char *ptr;

	if(bits<USICRYPT_DH_BITS_MIN||bits>USICRYPT_DH_BITS_MAX||
		(bits&7)||(generator!=2&&generator!=5))goto err1;
	if(gcry_reseed(ctx))goto err1;
	if(!(p=gcry_mpi_new(bits)))goto err1;
	if(!(x=gcry_mpi_new(bits)))goto err2;
	while(1)
	{
		if(gcry_dh_mpi_gen_prime(&p,bits))goto err3;
		switch(generator)
		{
		case 2:	gcry_mpi_set_ui(x,24);
			gcry_mpi_mod(x,p,x);
			if(gcry_mpi_cmp_ui(x,11))continue;
			break;

		case 3:	gcry_mpi_set_ui(x,12);
			gcry_mpi_mod(x,p,x);
			if(gcry_mpi_cmp_ui(x,5))continue;
			break;

		case 5:	gcry_mpi_set_ui(x,10);
			gcry_mpi_mod(x,p,x);
			if(gcry_mpi_cmp_ui(x,3)&&gcry_mpi_cmp_ui(x,7))continue;
			break;
		}
		break;
	}
	l=(gcry_mpi_get_nbits(p)+7)>>3;
	if(!(bfr=malloc(l)))goto err3;
	if(gcry_mpi_print(GCRYMPI_FMT_USG,bfr,l,&nn,p)||nn!=l)goto err4;

	n=l+((*bfr&0x80)?1:0);
	if(n>=0x100)n+=7;
	else if(n>=0x80)n+=6;
	else n+=5;
	if(n>=0x100)n+=4;
	else if(n>=0x80)n+=3;
	else n+=2;
	*len=n;
	if(!(ptr=data=malloc(n)))goto err4;

	*ptr++=0x30;
	n=l+((*bfr&0x80)?1:0);
	if(n>=0x100)n+=7;
	else if(n>=0x80)n+=6;
	else n+=5;
	if(n>=0x100)
	{
		*ptr++=0x82;
		*ptr++=(unsigned char)(n>>8);
	}
	else if(n>=0x80)*ptr++=0x81;
	*ptr++=(unsigned char)n;

	*ptr++=0x02;
	n=l+((*bfr&0x80)?1:0);
	if(n>=0x100)
	{
		*ptr++=0x82;
		*ptr++=(unsigned char)(n>>8);
	}
	else if(n>=0x80)*ptr++=0x81;
	*ptr++=(unsigned char)n;
	if(*bfr&0x80)*ptr++=0x00;
	memcpy(ptr,bfr,l);
	ptr+=l;

	*ptr++=0x02;
	*ptr++=0x01;
	*ptr=(unsigned char)generator;

	((struct usicrypt_thread *)ctx)->global->memclear(bfr,l);
	free(bfr);
	gcry_mpi_release(x);
	gcry_mpi_release(p);

	return data;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,l);
	free(bfr);
err3:	gcry_mpi_release(x);
err2:	gcry_mpi_release(p);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_init)(void *ctx,void *params,int len)
{
#ifndef USICRYPT_NO_DH
	struct gcry_dh *dh;

	if(!(dh=malloc(sizeof(struct gcry_dh))))goto err1;
	if(gcry_dh_mpi_parse_param(params,len,&dh->p,&dh->g))goto err2;
	dh->key=NULL;
	return dh;

err2:	free(dh);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len)
{
#ifndef USICRYPT_NO_DH
	struct gcry_dh *d=dh;
	gcry_mpi_t pub;
	unsigned char *data=NULL;

	if(gcry_reseed(ctx))goto err1;
	if(d->key)gcry_mpi_release(d->key);
	if(!(d->key=gcry_dh_mpi_generate(d->p)))goto err1;
	if(!(pub=gcry_dh_mpi_pub_from_key(d->key,d->p,d->g)))goto err1;
	data=gcry_dh_mpi_get_val(ctx,pub,len);
	gcry_mpi_release(pub);
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,int *slen)
{
#ifndef USICRYPT_NO_DH
	struct gcry_dh *d=dh;
	gcry_mpi_t p;
	gcry_mpi_t s;
	unsigned char *data=NULL;

	if(!(p=gcry_dh_mpi_set_pub(pub,plen)))goto err1;
	if(!(s=gcry_dh_mpi_derive(d->key,p,d->p)))goto err2;
	data=gcry_dh_mpi_get_val(ctx,s,slen);
	gcry_mpi_release(s);
err2:	gcry_mpi_release(p);
err1:	return data;
#else
	return NULL;
#endif
}

void USICRYPT(dh_free)(void *ctx,void *dh)
{
#ifndef USICRYPT_NO_DH
	struct gcry_dh *d=dh;

	if(d->key)gcry_mpi_release(d->key);
	gcry_mpi_release(d->p);
	gcry_mpi_release(d->g);
	free(d);
#endif
}

void *USICRYPT(ec_generate)(void *ctx,int curve)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec;

	if(gcry_reseed(ctx))goto err1;
	switch(curve)
	{
	case USICRYPT_BRAINPOOLP512R1:
	case USICRYPT_BRAINPOOLP384R1:
	case USICRYPT_BRAINPOOLP256R1:
	case USICRYPT_SECP521R1:
	case USICRYPT_SECP384R1:
	case USICRYPT_SECP256R1:
		break;
	default:goto err1;
	}
	if(!(ec=malloc(sizeof(struct gcry_ec))))goto err1;
	ec->curve=curve;
	if(!(ec->key=gcry_ec_mpi_generate(curve)))goto err2;
	if(!(ec->pub=gcry_ec_mpi_pub_from_key(ctx,ec->key,curve)))goto err3;
	return ec;

err3:	gcry_mpi_release(ec->key);
err2:	free(ec);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ec_identifier)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec=key;

	return ec->curve;
#else
	return -1;
#endif
}

void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *k=key;
	struct gcry_ec *p=pub;

	if(k->curve!=p->curve)return NULL;
	return gcry_ec_mpi_derive(ctx,k->key,p->pub,klen,k->curve);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec=k;

	return gcry_ec_mpi_get_pub(ctx,ec->pub,len,ec->curve);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec;

	if(!(ec=malloc(sizeof(struct gcry_ec))))goto err1;
	ec->key=NULL;
	if(!(ec->pub=gcry_ec_mpi_set_pub(ctx,key,len,&ec->curve)))goto err2;
	return ec;

err2:	free(ec);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec=k;

	return gcry_ec_mpi_get_key(ctx,ec->key,ec->pub,len,ec->curve);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec;

	if(!(ec=malloc(sizeof(struct gcry_ec))))goto err1;
	if(!(ec->key=gcry_ec_mpi_set_key(ctx,key,len,&ec->curve,&ec->pub)))
		goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return ec;

err2:	free(ec);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_EC
	return gcry_ec_mpi_sign(ctx,((struct gcry_ec *)key)->key,data,dlen,
		slen,((struct gcry_ec *)key)->curve,md,0);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return gcry_ec_mpi_sign(ctx,((struct gcry_ec *)key)->key,(void *)iov,
		niov,slen,((struct gcry_ec *)key)->curve,md,1);
#else
	return NULL;
#endif
}

int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_EC
	return gcry_ec_mpi_verify(ctx,((struct gcry_ec *)key)->pub,data,dlen,
		sig,slen,((struct gcry_ec *)key)->curve,md,0);
#else
	return -1;
#endif
}

int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return gcry_ec_mpi_verify(ctx,((struct gcry_ec *)key)->pub,(void *)iov,
		niov,sig,slen,((struct gcry_ec *)key)->curve,md,1);
#else
	return -1;
#endif
}

void USICRYPT(ec_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	struct gcry_ec *ec=key;

	if(ec->key)gcry_mpi_release(ec->key);
	if(ec->pub)gcry_mpi_release(ec->pub);
	free(ec);
#endif
}

void *USICRYPT(x25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x;

	if(gcry_reseed(ctx))goto err1;
	if(!(x=malloc(sizeof(struct gcry_x25519))))goto err1;
	if(!(x->key=gcry_x25519_mpi_generate()))goto err2;
	if(!(x->pub=gcry_x25519_mpi_pub_fom_key(x->key)))goto err3;
	return x;

err3:	gcry_mpi_release(x->key);
err2:	free(x);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *k=key;
	struct gcry_x25519 *p=pub;
	gcry_mpi_t s;
	unsigned char *data;

	if(!(s=gcry_x25519_mpi_derive(k->key,p->pub)))goto err1;
	*klen=32;
	if(!(data=malloc(*klen)))goto err2;
	if(gcry_x25519_mpi_to_le32(ctx,s,data))goto err3;
	gcry_mpi_release(s);
	return data;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(data,*klen);
	free(data);
err2:	gcry_mpi_release(s);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x=key;
	unsigned char *data;

	*len=sizeof(gcry_x25519_asn1_pub)+32;
	if(!(data=malloc(*len)))goto err1;
	memcpy(data,gcry_x25519_asn1_pub,sizeof(gcry_x25519_asn1_pub));
	if(gcry_x25519_mpi_to_le32(ctx,x->pub,
		data+sizeof(gcry_x25519_asn1_pub)))goto err2;
	return data;

err2:	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x;

	if(len<sizeof(gcry_x25519_asn1_pub)+32||
		memcmp(key,gcry_x25519_asn1_pub,sizeof(gcry_x25519_asn1_pub)))
		goto err1;
	if(!(x=malloc(sizeof(struct gcry_x25519))))goto err1;
	x->key=NULL;
	if(gcry_x25519_mpi_from_le32(ctx,&x->pub,
		((unsigned char *)key)+sizeof(gcry_x25519_asn1_pub)))goto err2;
	if(gcry_x25519_mpi_check_pub(x->pub))goto err3;
	return x;

err3:	gcry_mpi_release(x->pub);
err2:	free(x);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x=key;
	unsigned char *data;

	*len=sizeof(gcry_x25519_asn1_key)+32;
	if(!(data=malloc(*len)))goto err1;
	memcpy(data,gcry_x25519_asn1_key,sizeof(gcry_x25519_asn1_key));
	if(gcry_x25519_mpi_to_le32(ctx,x->key,
		data+sizeof(gcry_x25519_asn1_key)))goto err2;
	return data;

err2:	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x;

	if(len<sizeof(gcry_x25519_asn1_key)+32||
		memcmp(key,gcry_x25519_asn1_key,sizeof(gcry_x25519_asn1_key)))
		goto err1;
	if(!(x=malloc(sizeof(struct gcry_x25519))))goto err1;
	if(gcry_x25519_mpi_from_le32(ctx,&x->key,
		((unsigned char *)key)+sizeof(gcry_x25519_asn1_key)))goto err2;
	if(!(x->pub=gcry_x25519_mpi_pub_fom_key(x->key)))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return x;

err3:	gcry_mpi_release(x->key);
err2:	free(x);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void USICRYPT(x25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_X25519
	struct gcry_x25519 *x=key;

	if(x->key)gcry_mpi_release(x->key);
	if(x->pub)gcry_mpi_release(x->pub);
	free(x);
#endif
}

void *USICRYPT(encrypt_p8)(void *ctx,void *key,int klen,void *data,int dlen,
	int cipher,int mode,int bits,int digest,int iter,int *rlen)
{
#ifndef USICRYPT_NO_PBKDF2
	int cidx;
	int didx;
	int plen;
	int len1;
	int len2;
	int len3;
	int ilen;
	void *c;
	unsigned char *out;
	unsigned char *ptr;
	unsigned char bfr[64];
	unsigned char iv[16];
	unsigned char salt[8];

	if(dlen>0x3fff||iter<=0||(digest==USICRYPT_SHA1&&bits!=128))goto err1;

	if(gcry_asn_next(data,dlen,0x30,&cidx,&didx))goto err1;
	if(cidx+didx!=dlen)goto err1;

	for(didx=0;didx<4;didx++)if(gcry_digest_asn[didx].oidlen&&
		gcry_digest_asn[didx].digest==digest)break;
	if(didx==4)goto err1;

	for(cidx=0;cidx<24;cidx++)if(gcry_cipher_asn[cidx].oidlen&&
		gcry_cipher_asn[cidx].cipher==cipher&&
		gcry_cipher_asn[cidx].mode==mode&&
		gcry_cipher_asn[cidx].bits==bits)break;
	if(cidx==24)goto err1;

	if(USICRYPT(random)(ctx,salt,8))goto err1;
	if(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,8,iter,bfr))goto err2;

	if(gcry_cipher_asn[cidx].ivlen)
		if(USICRYPT(random)(ctx,iv,gcry_cipher_asn[cidx].ivlen))
			goto err3;

	if(!(c=USICRYPT(blkcipher_init)(ctx,cipher,mode,bfr,bits,iv)))goto err4;

	if(iter>=0x800000)ilen=4;
	else if(iter>=0x8000)ilen=3;
	else if(iter>=0x80)ilen=2;
	else ilen=1;

	if(gcry_cipher_asn[cidx].pad)
		plen=usicrypt_cipher_padding_add(ctx,NULL,dlen);
	else plen=0;
	len1=gcry_asn_length(NULL,dlen+plen)+1;
	len2=gcry_cipher_asn[cidx].oidlen+gcry_cipher_asn[cidx].ivlen+6;
	len3=ilen+sizeof(gcry_pbes2_oid)+sizeof(gcry_pbkdf2_oid)+24;
	if(digest!=USICRYPT_SHA1)len3+=gcry_digest_asn[didx].oidlen+6;
	*rlen=gcry_asn_length(NULL,len1+len2+len3+dlen+plen)+
		len1+len2+len3+dlen+plen+1;

	if(!(ptr=out=malloc(*rlen)))goto err5;

	*ptr++=0x30;
	ptr+=gcry_asn_length(ptr,len1+len2+len3+dlen+plen);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(gcry_pbes2_oid);
	memcpy(ptr,gcry_pbes2_oid,sizeof(gcry_pbes2_oid));
	ptr+=sizeof(gcry_pbes2_oid);
	len3-=sizeof(gcry_pbes2_oid)+6;
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(gcry_pbkdf2_oid);
	memcpy(ptr,gcry_pbkdf2_oid,sizeof(gcry_pbkdf2_oid));
	ptr+=sizeof(gcry_pbkdf2_oid);
	*ptr++=0x30;
	*ptr++=(unsigned char)
	     (ilen+12+(digest!=USICRYPT_SHA1?gcry_digest_asn[didx].oidlen+6:0));
	*ptr++=0x04;
	*ptr++=0x08;
	memcpy(ptr,salt,8);
	ptr+=8;
	*ptr++=0x02;
	*ptr++=(unsigned char)(ilen);
	switch(ilen)
	{
	case 4:	*ptr++=(unsigned char)(iter>>24);
	case 3:	*ptr++=(unsigned char)(iter>>16);
	case 2:	*ptr++=(unsigned char)(iter>>8);
	case 1:	*ptr++=(unsigned char)iter;
	}
	if(digest!=USICRYPT_SHA1)
	{
		*ptr++=0x30;
		*ptr++=(unsigned char)(gcry_digest_asn[didx].oidlen+4);
		*ptr++=0x06;
		*ptr++=(unsigned char)gcry_digest_asn[didx].oidlen;
		memcpy(ptr,gcry_digest_asn[didx].oid,
			gcry_digest_asn[didx].oidlen);
		ptr+=gcry_digest_asn[didx].oidlen;
		*ptr++=0x05;
		*ptr++=0x00;
	}
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)gcry_cipher_asn[cidx].oidlen;
	memcpy(ptr,gcry_cipher_asn[cidx].oid,gcry_cipher_asn[cidx].oidlen);
	ptr+=gcry_cipher_asn[cidx].oidlen;
	*ptr++=0x04;
	*ptr++=(unsigned char)gcry_cipher_asn[cidx].ivlen;
	if(gcry_cipher_asn[cidx].ivlen)
	{
		memcpy(ptr,iv,gcry_cipher_asn[cidx].ivlen);
		ptr+=gcry_cipher_asn[cidx].ivlen;
	}
	*ptr++=0x04;
	ptr+=gcry_asn_length(ptr,dlen+plen);
	memcpy(ptr,data,dlen);
	if(gcry_cipher_asn[cidx].pad)usicrypt_cipher_padding_add(ctx,ptr,dlen);

	if(USICRYPT(blkcipher_encrypt)(c,ptr,dlen+plen,ptr))goto err6;
	USICRYPT(blkcipher_exit)(c);

	((struct usicrypt_thread *)ctx)->global->memclear(salt,sizeof(salt));
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	((struct usicrypt_thread *)ctx)->global->memclear(iv,sizeof(iv));
	return out;

err6:	((struct usicrypt_thread *)ctx)->global->memclear(out,*rlen);
	free(out);
err5:	USICRYPT(blkcipher_exit)(c);
err4:	((struct usicrypt_thread *)ctx)->global->memclear(iv,sizeof(iv));
err3:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
err2:	((struct usicrypt_thread *)ctx)->global->memclear(salt,sizeof(salt));
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#endif
	return NULL;
}

void *USICRYPT(decrypt_p8)(void *ctx,void *key,int klen,void *data,int dlen,
	int *rlen)
{
#ifndef USICRYPT_NO_PBKDF2
	int h;
	int l;
	int digest=USICRYPT_SHA1;
	int elen;
	int mlen;
	int slen;
	int ilen;
	int clen;
	int ivlen;
	void *c;
	unsigned char *out;
	unsigned char *eptr;
	unsigned char *md=NULL;
	unsigned char *salt;
	unsigned char *iter;
	unsigned char *cipher;
	unsigned char *iv;
	unsigned char bfr[64];

	if(dlen>0x3fff)goto err1;

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	eptr=data+h+l;
	elen=dlen-h-l;
	data+=h;
	dlen=l;

	if(gcry_asn_next(data,dlen,0x06,&h,&l))goto err1;
	if(l!=sizeof(gcry_pbes2_oid)||memcmp(data+h,gcry_pbes2_oid,l))goto err1;
	data+=h+l;
	dlen-=h+l;

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(gcry_asn_next(data,dlen,0x06,&h,&l))goto err1;
	if(l!=sizeof(gcry_pbkdf2_oid)||memcmp(data+h,gcry_pbkdf2_oid,l))
		goto err1;
	data+=h+l;
	dlen-=h+l;

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;
	mlen=l;

	if(gcry_asn_next(data,dlen,0x04,&h,&l))goto err1;
	salt=data+h;
	slen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(gcry_asn_next(data,dlen,0x02,&h,&l))goto err1;
	if(!l||l>sizeof(int))goto err1;
	iter=data+h;
	ilen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(mlen<0)goto err1;
	else if(mlen)
	{
		if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
		data+=h;
		dlen-=h;

		if(gcry_asn_next(data,dlen,0x06,&h,&l))goto err1;
		md=data+h;
		mlen=l;
		data+=h+l;
		dlen-=h+l;

		if(gcry_asn_next(data,dlen,0x05,&h,&l))goto err1;
		if(l)goto err1;
		data+=h;
		dlen-=h;
	}

	if(gcry_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(gcry_asn_next(data,dlen,0x06,&h,&l))goto err1;
	cipher=data+h;
	clen=l;
	data+=h+l;
	dlen-=h+l;

	if(gcry_asn_next(data,dlen,0x04,&h,&l))goto err1;
	iv=data+h;
	ivlen=l;
	data+=h+l;
	dlen-=h+l;
	if(data!=eptr)goto err1;

	if(gcry_asn_next(eptr,elen,0x04,&h,&l))goto err1;
	eptr+=h;
	elen=l;

	for(l=0,h=0;h<ilen;h++)l=(l<<8)|iter[h];
	if(!l)goto err1;

	if(mlen)
	{
		for(h=0;h<4;h++)if(gcry_digest_asn[h].oidlen&&
			mlen==gcry_digest_asn[h].oidlen&&
			!memcmp(md,gcry_digest_asn[h].oid,mlen))break;
		if(h==4)goto err1;
		else digest=gcry_digest_asn[h].digest;
	}

	for(h=0;h<24;h++)if(gcry_cipher_asn[h].oidlen&&
		clen==gcry_cipher_asn[h].oidlen&&
		!memcmp(cipher,gcry_cipher_asn[h].oid,clen))break;
	if(h==24||gcry_cipher_asn[h].ivlen!=ivlen||
		(gcry_cipher_asn[h].bits!=128&&digest==USICRYPT_SHA1))goto err1;

	if(gcry_cipher_asn[h].pad)if(elen&0x0f)goto err1;

	if(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,slen,l,bfr))goto err1;

	if(!(out=malloc(elen)))goto err2;

	if(!(c=USICRYPT(blkcipher_init)(ctx,gcry_cipher_asn[h].cipher,
		gcry_cipher_asn[h].mode,bfr,gcry_cipher_asn[h].bits,iv)))
		goto err3;
	if(USICRYPT(blkcipher_decrypt)(c,eptr,elen,out))goto err5;
	USICRYPT(blkcipher_exit)(c);

	if(gcry_cipher_asn[h].pad)
	{
		if((*rlen=usicrypt_cipher_padding_get(ctx,out,elen))==-1)
			goto err4;
		else *rlen=elen-*rlen;
	}
	else *rlen=elen;

	if(gcry_asn_next(out,*rlen,0x30,&h,&l))goto err4;
	if(h+l!=*rlen)goto err4;

	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return USICRYPT(do_realloc)(ctx,out,elen,*rlen);

err5:	USICRYPT(blkcipher_exit)(c);
err4:	((struct usicrypt_thread *)ctx)->global->memclear(out,elen);
err3:	free(out);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#endif
	return NULL;
}

int USICRYPT(cipher_block_size)(void *ctx,int cipher)
{
	switch(cipher)
	{
#ifndef USICRYPT_NO_AES
#if !defined(USICRYPT_NO_ECB) || !defined(USICRYPT_NO_CBC) || \
	!defined(USICRYPT_NO_CFB) || !defined(USICRYPT_NO_CFB) || \
	!defined(USICRYPT_NO_OFB) || !defined(USICRYPT_NO_CTR)
	case USICRYPT_AES:
		return gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES);
#endif
#ifndef USICRYPT_NO_GCM
	case USICRYPT_AES_GCM:
		return 1;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		return 1;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#if !defined(USICRYPT_NO_ECB) || !defined(USICRYPT_NO_CBC) || \
	!defined(USICRYPT_NO_CFB) || !defined(USICRYPT_NO_CFB) || \
	!defined(USICRYPT_NO_OFB) || !defined(USICRYPT_NO_CTR)
	case USICRYPT_CAMELLIA:
		return gcry_cipher_get_algo_blklen(GCRY_CIPHER_CAMELLIA128);
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20:
		return 1;
#endif
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		return 1;
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(blkcipher_init)(void *ctx,int cipher,int mode,void *key,int klen,
	void *iv)
{
	struct usicrypt_cipher *c=NULL;

	switch(cipher|mode)
	{
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_ECB
	case USICRYPT_AES|USICRYPT_ECB:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_ECB,
			0,key,klen,NULL,NULL,0)))break;
		c->encrypt=gcry_cipher_16_encrypt;
		c->decrypt=gcry_cipher_16_decrypt;
		c->reset=NULL;
		c->exit=gcry_cipher_exit;
		break;
		return c;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_CBC,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_16_encrypt;
		c->decrypt=gcry_cipher_16_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_AES|USICRYPT_CTS:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_CBC,
			GCRY_CIPHER_CBC_CTS,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_17_encrypt;
		c->decrypt=gcry_cipher_17_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_CFB,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_1_encrypt;
		c->decrypt=gcry_cipher_1_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_AES|USICRYPT_CFB8:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_ECB,
			0,key,klen,iv,NULL,32)))break;
		c->encrypt=gcry_cipher_cfb8_encrypt;
		c->decrypt=gcry_cipher_cfb8_decrypt;
		c->reset=gcry_cipher_cfb8_reset;
		c->exit=gcry_cipher_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_OFB,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_zero_crypt;
		c->decrypt=gcry_cipher_zero_crypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_AES|USICRYPT_CTR:
		if(!(c=gcry_cipher_init(ctx,0,GCRY_CIPHER_MODE_CTR,
			0,key,klen,NULL,iv,0)))break;
		c->encrypt=gcry_cipher_zero_crypt;
		c->decrypt=gcry_cipher_zero_crypt;
		c->reset=gcry_cipher_ctr_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_ECB,
			0,key,klen,NULL,NULL,0)))break;
		c->encrypt=gcry_cipher_16_encrypt;
		c->decrypt=gcry_cipher_16_decrypt;
		c->reset=NULL;
		c->exit=gcry_cipher_exit;
		break;
		return c;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_CBC,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_16_encrypt;
		c->decrypt=gcry_cipher_16_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_CAMELLIA|USICRYPT_CTS:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_CBC,
			GCRY_CIPHER_CBC_CTS,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_17_encrypt;
		c->decrypt=gcry_cipher_17_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_CFB,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_1_encrypt;
		c->decrypt=gcry_cipher_1_decrypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_CAMELLIA|USICRYPT_CFB8:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_ECB,
			0,key,klen,iv,NULL,32)))break;
		c->encrypt=gcry_cipher_cfb8_encrypt;
		c->decrypt=gcry_cipher_cfb8_decrypt;
		c->reset=gcry_cipher_cfb8_reset;
		c->exit=gcry_cipher_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_OFB,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_zero_crypt;
		c->decrypt=gcry_cipher_zero_crypt;
		c->reset=gcry_cipher_iv16_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_CAMELLIA|USICRYPT_CTR:
		if(!(c=gcry_cipher_init(ctx,1,GCRY_CIPHER_MODE_CTR,
			0,key,klen,NULL,iv,0)))break;
		c->encrypt=gcry_cipher_zero_crypt;
		c->decrypt=gcry_cipher_zero_crypt;
		c->reset=gcry_cipher_ctr_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20|USICRYPT_STREAM:
		if(!(c=gcry_cipher_init(ctx,2,GCRY_CIPHER_MODE_STREAM,
			0,key,klen,iv,NULL,0)))break;
		c->encrypt=gcry_cipher_1_encrypt;
		c->decrypt=gcry_cipher_1_encrypt;
		c->reset=gcry_cipher_iv8_reset;
		c->exit=gcry_cipher_exit;
		break;
#endif
#endif
	default:break;
	}
	return c;
}

int USICRYPT(blkcipher_encrypt)(void *ctx,void *src,int slen,void *dst)
{
	return ((struct usicrypt_cipher *)ctx)->encrypt(ctx,src,slen,dst);
}

int USICRYPT(blkcipher_decrypt)(void *ctx,void *src,int slen,void *dst)
{
	return ((struct usicrypt_cipher *)ctx)->decrypt(ctx,src,slen,dst);
}

void USICRYPT(blkcipher_reset)(void *ctx,void *iv)
{
	if(((struct usicrypt_cipher *)ctx)->reset)
		((struct usicrypt_cipher *)ctx)->reset(ctx,iv);
}

void USICRYPT(blkcipher_exit)(void *ctx)
{
	((struct usicrypt_cipher *)ctx)->exit(ctx);
}

void *USICRYPT(dskcipher_init)(void *ctx,int cipher,int mode,void *key,int klen)
{
	struct usicrypt_dskcipher *c=NULL;

	switch(cipher|mode)
	{
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_XTS
	case USICRYPT_AES|USICRYPT_XTS:
		if(!(c=gcry_cipher_xts_init(ctx,0,key,klen)))break;
		c->encrypt=gcry_cipher_xts_encrypt;
		c->decrypt=gcry_cipher_xts_decrypt;
		c->exit=gcry_cipher_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_AES|USICRYPT_ESSIV:
		if(!(c=gcry_cipher_essiv_init(ctx,0,key,klen)))break;
		c->encrypt=gcry_cipher_essiv_encrypt;
		c->decrypt=gcry_cipher_essiv_decrypt;
		c->exit=gcry_cipher_essiv_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_XTS
	case USICRYPT_CAMELLIA|USICRYPT_XTS:
		if(!(c=gcry_cipher_xts_init(ctx,1,key,klen)))break;
		c->encrypt=gcry_cipher_xts_encrypt;
		c->decrypt=gcry_cipher_xts_decrypt;
		c->exit=gcry_cipher_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_CAMELLIA|USICRYPT_ESSIV:
		if(!(c=gcry_cipher_essiv_init(ctx,1,key,klen)))break;
		c->encrypt=gcry_cipher_essiv_encrypt;
		c->decrypt=gcry_cipher_essiv_decrypt;
		c->exit=gcry_cipher_essiv_exit;
		break;
#endif
#endif
	default:break;
	}

	return c;
}

int USICRYPT(dskcipher_encrypt)(void *ctx,void *iv,void *src,int slen,void *dst)
{
	return ((struct usicrypt_dskcipher *)ctx)->encrypt(ctx,iv,src,slen,dst);
}

int USICRYPT(dskcipher_decrypt)(void *ctx,void *iv,void *src,int slen,void *dst)
{
	return ((struct usicrypt_dskcipher *)ctx)->decrypt(ctx,iv,src,slen,dst);
}

void USICRYPT(dskcipher_exit)(void *ctx)
{
	((struct usicrypt_dskcipher *)ctx)->exit(ctx);
}

void *USICRYPT(aeadcipher_init)(void *ctx,int cipher,void *key,int klen,
	int ilen,int tlen)
{       
	struct usicrypt_aeadcipher *c=NULL;
	
	switch(cipher)
	{
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_GCM
	case USICRYPT_AES_GCM:
		if(!(c=gcry_aes_gcm_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=gcry_aes_gcm_encrypt;
		c->decrypt=gcry_aes_gcm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=gcry_aes_gcm_encrypt_iov;
		c->decrypt_iov=gcry_aes_gcm_decrypt_iov;
#endif
		c->exit=gcry_aes_gcm_exit;
		break;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		if(!(c=gcry_aes_ccm_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=gcry_aes_ccm_encrypt;
		c->decrypt=gcry_aes_ccm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=gcry_aes_ccm_encrypt_iov;
		c->decrypt_iov=gcry_aes_ccm_decrypt_iov;
#endif
		c->exit=gcry_aes_ccm_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		if(!(c=gcry_chacha_poly_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=gcry_chacha_poly_encrypt;
		c->decrypt=gcry_chacha_poly_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=gcry_chacha_poly_encrypt_iov;
		c->decrypt_iov=gcry_chacha_poly_decrypt_iov;
#endif
		c->exit=gcry_chacha_poly_exit;
		break;
#endif
#endif
	default:break;
	}
	
	return c;
}

int USICRYPT(aeadcipher_encrypt)(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	return ((struct usicrypt_aeadcipher *)ctx)->encrypt(ctx,iv,src,
		slen,aad,alen,dst,tag);
}

int USICRYPT(aeadcipher_encrypt_iov)(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
#ifndef USICRYPT_NO_IOV
	return ((struct usicrypt_aeadcipher *)ctx)->encrypt_iov(ctx,iv,src,
		slen,iov,niov,dst,tag);
#else
	return -1;
#endif
}

int USICRYPT(aeadcipher_decrypt)(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	return ((struct usicrypt_aeadcipher *)ctx)->decrypt(ctx,iv,src,
		slen,aad,alen,dst,tag);
}

int USICRYPT(aeadcipher_decrypt_iov)(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
#ifndef USICRYPT_NO_IOV
	return ((struct usicrypt_aeadcipher *)ctx)->decrypt_iov(ctx,iv,src,
		slen,iov,niov,dst,tag);
#else
	return -1;
#endif
}

void USICRYPT(aeadcipher_exit)(void *ctx)
{
	((struct usicrypt_aeadcipher *)ctx)->exit(ctx);
}

int USICRYPT(cmac)(void *ctx,int cipher,void *key,int klen,void *src,int slen,
	void *dst)
{
	switch(cipher)
	{
#ifndef USICRYPT_NO_CMAC
#ifndef USICRYPT_NO_AES
	case USICRYPT_AES:
		return gcry_cipher_cmac(ctx,GCRY_MAC_CMAC_AES,
				key,klen,src,slen,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return gcry_cipher_cmac(ctx,GCRY_MAC_CMAC_CAMELLIA,
				key,klen,src,slen,dst);
#endif
#endif
	default:return -1;
	}
}

int USICRYPT(cmac_iov)(void *ctx,int cipher,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	switch(cipher)
	{
#if !defined(USICRYPT_NO_CMAC) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_AES
	case USICRYPT_AES:
		return gcry_cipher_cmac_iov(ctx,GCRY_MAC_CMAC_AES,
				key,klen,iov,niov,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return gcry_cipher_cmac_iov(ctx,GCRY_MAC_CMAC_CAMELLIA,
				key,klen,iov,niov,dst);
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(thread_init)(void *global)
{
	struct usicrypt_thread *ctx;

	if(!(ctx=malloc(sizeof(struct usicrypt_thread))))goto err1;
	ctx->global=global;
	ctx->total=0;
err1:	return ctx;
}

void USICRYPT(thread_exit)(void *ctx)
{
	free(ctx);
}

void *USICRYPT(global_init)(int (*rng_seed)(void *data,int len),
	void (*memclear)(void *data,int len))
{
	struct usicrypt_global *ctx;
	unsigned char bfr[32];

	USICRYPT(do_realloc)(NULL,NULL,0,0);
	if(!(ctx=malloc(sizeof(struct usicrypt_global))))goto err1;
	ctx->rng_seed=(rng_seed?rng_seed:USICRYPT(get_random));
	ctx->memclear=(memclear?memclear:USICRYPT(do_memclear));
	/* we do not want to wait on a blocking /dev/random */
	if(gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM))goto err2;
	/* we do not want any crazy secure memory noise */
	if(gcry_control(GCRYCTL_DISABLE_SECMEM_WARN))goto err2;
	/* we do not want libgcrypt to mess up privileges */
	if(gcry_control(GCRYCTL_DISABLE_PRIV_DROP))goto err2;
	/* we do not want to need root or capabilities */
	if(gcry_control(GCRYCTL_DISABLE_LOCKED_SECMEM))goto err2;
	/* 64KB secure memory should be enough */
	if(gcry_control(GCRYCTL_INIT_SECMEM,65536))goto err2;
	if(gcry_control(GCRYCTL_INITIALIZATION_FINISHED))goto err3;
	if(ctx->rng_seed(bfr,sizeof(bfr)))goto err4;
	if(gcry_random_add_bytes(bfr,sizeof(bfr),100))goto err5;
	ctx->memclear(bfr,sizeof(bfr));
	return ctx;

err5:	ctx->memclear(bfr,sizeof(bfr));
err4:	gcry_control(GCRYCTL_CLOSE_RANDOM_DEVICE);
err3:	gcry_control(GCRYCTL_TERM_SECMEM);
err2:	free(ctx);
err1:	return NULL;
}

void USICRYPT(global_exit)(void *ctx)
{
	gcry_control(GCRYCTL_TERM_SECMEM);
	gcry_control(GCRYCTL_CLOSE_RANDOM_DEVICE);
	free(ctx);
}

#endif
