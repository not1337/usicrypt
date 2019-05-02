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
#ifndef USICRYPT_NTTL
#define USICRYPT_NTTL
#endif
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#if defined(USICRYPT_NTTL)

#include <nettle/yarrow.h>
#include <nettle/pbkdf2.h>
#include <nettle/hmac.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#include <nettle/base64.h>
#include <nettle/bignum.h>
#include <nettle/rsa.h>
#include <nettle/ecc-curve.h>
#include <nettle/ecc.h>
#include <nettle/dsa.h>
#include <nettle/ecdsa.h>
#include <nettle/curve25519.h>
#include <nettle/aes.h>
#include <nettle/chacha.h>
#include <nettle/chacha-poly1305.h>
#include <nettle/camellia.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>
#include <nettle/ccm.h>
#include <gmp.h>

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) nttl_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

/******************************************************************************/
/*                                  Nettle                                    */
/******************************************************************************/

struct nttl_rsa
{
	struct rsa_public_key pub;
	struct rsa_private_key key;
};

struct nttl_dh
{
	mpz_t p;
	mpz_t g;
	mpz_t key;
};

struct nttl_ec
{
	int curve;
	struct ecc_scalar key;
	struct ecc_point pub;
};

struct nttl_x25519
{
	unsigned char pub[CURVE25519_SIZE];
	unsigned char key[CURVE25519_SIZE];
};

struct nttl_aes_ecb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct aes_ctx dec;
};

struct nttl_aes_cbc
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct aes_ctx dec;
	unsigned char iv[16];
};

struct nttl_aes_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct aes_ctx dec;
	unsigned char iv[16];
	unsigned char tmp[32];
};

struct nttl_aes_xfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	int n;
	unsigned char iv[16];
	union
	{
		unsigned char mem[16];
		unsigned char zero[16];
	};
};

struct nttl_aes_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct nttl_aes_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	int n;
	unsigned char ctr[16];
	unsigned char mem[16];
};

struct nttl_aes_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct aes_ctx dec;
	struct aes_ctx twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct nttl_aes_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct aes_ctx dec;
	struct aes_ctx aux;
	unsigned char iv[16];
};

struct nttl_aes_gcm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct gcm_key gcm;
	struct gcm_ctx ctx;
	int ilen;
	int tlen;
	unsigned char mem[GCM_BLOCK_SIZE];
};

struct nttl_aes_ccm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	struct aes_ctx enc;
	struct ccm_ctx ctx;
	int ilen;
	int tlen;
};

struct nttl_chacha_poly
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	struct chacha_poly1305_ctx ctx;
};

struct nttl_chacha
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	int n;
	struct chacha_ctx ctx;
	unsigned char mem[CHACHA_BLOCK_SIZE];
};

struct nttl_camellia_ecb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	union
	{
		struct camellia128_ctx dec128;
		struct camellia256_ctx dec256;
	} dec;
};

struct nttl_camellia_cbc
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	union
	{
		struct camellia128_ctx dec128;
		struct camellia256_ctx dec256;
	} dec;
	unsigned char iv[16];
};

struct nttl_camellia_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	union
	{
		struct camellia128_ctx dec128;
		struct camellia256_ctx dec256;
	} dec;
	unsigned char iv[16];
	unsigned char tmp[32];
};

struct nttl_camellia_xfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	int n;
	unsigned char iv[16];
	union
	{
		unsigned char mem[16];
		unsigned char zero[16];
	};
};

struct nttl_camellia_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct nttl_camellia_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	int n;
	unsigned char ctr[16];
	unsigned char mem[16];
};

struct nttl_camellia_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	union
	{
		struct camellia128_ctx dec128;
		struct camellia256_ctx dec256;
	} dec;
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct nttl_camellia_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	union
	{
		struct camellia128_ctx dec128;
		struct camellia256_ctx dec256;
	} dec;
	struct camellia256_ctx aux;
	unsigned char iv[16];
};

struct nttl_hm
{
	int idx;
	union
	{
		struct hmac_sha1_ctx sha1;
		struct hmac_sha256_ctx sha256;
		struct hmac_sha384_ctx sha384;
		struct hmac_sha512_ctx sha512;
	} ctx;
};

struct nttl_md
{
	int idx;
	union
	{
		struct sha1_ctx sha1;
		struct sha256_ctx sha256;
		struct sha384_ctx sha384;
		struct sha512_ctx sha512;
	} ctx;
};

static const struct
{
	const int size;
	void (*const init)(void *ctx,size_t length,const uint8_t *data);
	void (*const update)(void *ctx,size_t length,const uint8_t *data);
	void (*const digest)(void *ctx,size_t length,uint8_t *digest);
} nttl_hm[4]=
{
	{
#ifndef USICRYPT_NO_SHA1
		SHA1_DIGEST_SIZE,
		(void *)hmac_sha1_set_key,
		(void *)hmac_sha1_update,
		(void *)hmac_sha1_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA256
		SHA256_DIGEST_SIZE,
		(void *)hmac_sha256_set_key,
		(void *)hmac_sha256_update,
		(void *)hmac_sha256_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA384
		SHA384_DIGEST_SIZE,
		(void *)hmac_sha384_set_key,
		(void *)hmac_sha384_update,
		(void *)hmac_sha384_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA512
		SHA512_DIGEST_SIZE,
		(void *)hmac_sha512_set_key,
		(void *)hmac_sha512_update,
		(void *)hmac_sha512_digest
#endif
	}
};

static const struct
{
	const int size;
	void (*const init)(void *ctx);
	void (*const update)(void *ctx,size_t length,const uint8_t *data);
	void (*const digest)(void *ctx,size_t length,uint8_t *digest);
} nttl_md[4]=
{
	{
#ifndef USICRYPT_NO_SHA1
		SHA1_DIGEST_SIZE,
		(void *)sha1_init,
		(void *)sha1_update,
		(void *)sha1_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA256
		SHA256_DIGEST_SIZE,
		(void *)sha256_init,
		(void *)sha256_update,
		(void *)sha256_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA384
		SHA384_DIGEST_SIZE,
		(void *)sha384_init,
		(void *)sha384_update,
		(void *)sha384_digest
#endif
	},
	{
#ifndef USICRYPT_NO_SHA512
		SHA512_DIGEST_SIZE,
		(void *)sha512_init,
		(void *)sha512_update,
		(void *)sha512_digest
#endif
	}
};

#ifndef USICRYPT_NO_PBKDF2

static const unsigned char nttl_pbes2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

static const unsigned char nttl_pbkdf2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c
};

static const struct
{
	const int digest;
	const int oidlen;
	const unsigned char oid[0x08];

} nttl_digest_asn[4]=
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
	const unsigned int cipher:9;
	const unsigned int mode:4;
	const unsigned int pad:1;
	const unsigned int bits:9;
	const unsigned int ivlen:5;
	const unsigned int oidlen:4;
	const unsigned char oid[0x0b];
} nttl_cipher_asn[24]=
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

static const unsigned char nttl_rsa_pub_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01
};

#endif
#ifndef USICRYPT_NO_DH

static const int nttl_primes[171]=
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
	const int bits;
	const int iter;
} nttl_mr_tab[11]=
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

static const unsigned char nttl_ansi_pubkey_type[7]=
{
	0x2a,0x86,0x48,0xce,0x3d,0x02,0x01
};

static const unsigned char nttl_ec_k1h1[4]=
{
	0x02,0x01,0x01,0x04
};

static const struct
{       
	const struct ecc_curve *curve;
	const int publen;
	const int kmax;
	const int xylen;
	const int phdrlen;
	const int k1h2len;
	const unsigned char oidlen;
	const unsigned char oid[9];
	const unsigned char phdr[29];
	const unsigned char k1h2[20];
} nttl_ec_map[USICRYPT_TOT_EC_CURVES]=
{
	{
		NULL,
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
		NULL,
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
		NULL,
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
		&nettle_secp_521r1,
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
		&nettle_secp_384r1,
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
		&nettle_secp_256r1,
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

static const unsigned char nttl_x25519_asn1_pub[12]=
{
	0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6e,0x03,0x21,0x00
};

static const unsigned char nttl_x25519_asn1_key[16]=
{
	0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20
};

#endif

static int nttl_reseed(void *ctx)
{
	int r=-1;
	unsigned char bfr[32];

	if(U(((struct usicrypt_thread *)ctx)->global->
		rng_seed(bfr,sizeof(bfr))))goto err1;
	yarrow256_update(&((struct usicrypt_thread *)ctx)->rng,
		0,0,sizeof(bfr),bfr);
	if(((struct usicrypt_thread *)ctx)->global->
		rng_seed(bfr,sizeof(bfr)))goto err1;
	yarrow256_update(&((struct usicrypt_thread *)ctx)->rng,
		1,0,sizeof(bfr),bfr);
	r=0;
err1:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return r;
}

#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC) || !defined(USICRYPT_NO_PBKDF2)

static int nttl_asn_next(unsigned char *prm,int len,unsigned char id,
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

#endif
#ifndef USICRYPT_NO_PBKDF2

static int nttl_asn_length(unsigned char *ptr,int len)
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
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_EC)

static void nttl_cb_random(void *ctx,size_t length,uint8_t *dst)
{
	yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,length,dst);
}

#endif
#ifndef USICRYPT_NO_RSA

static int nttl_rsa_mpz_check(struct nttl_rsa *rsa)
{
	int r=-1;
	mpz_t p1;
	mpz_t q1;
	mpz_t tmp1;
	mpz_t tmp2;

	mpz_init(p1);
	mpz_init(q1);
	mpz_init(tmp1);
	mpz_init(tmp2);
	if(U(!mpz_cmp_ui(rsa->key.d,0))||U(!mpz_cmp_ui(rsa->key.p,0))||
		U(!mpz_cmp_ui(rsa->key.q,0)))goto err1;
	if(U(!mpz_invert(tmp1,rsa->key.q,rsa->key.p)))goto err1;
	if(U(mpz_cmp(tmp1,rsa->key.c)))goto err1;
	mpz_mul(tmp1,rsa->key.p,rsa->key.q);
	if(U(mpz_cmp(tmp1,rsa->pub.n)))goto err1;
	mpz_sub_ui(p1,rsa->key.p,1);
	mpz_mod(tmp1,rsa->key.d,p1);
	if(U(mpz_cmp(tmp1,rsa->key.a)))goto err1;
	mpz_sub_ui(q1,rsa->key.q,1);
	mpz_mod(tmp1,rsa->key.d,q1);
	if(U(mpz_cmp(tmp1,rsa->key.b)))goto err1;
	mpz_mul(tmp2,p1,q1);
	mpz_gcd(tmp1,rsa->pub.e,tmp2);
	if(U(mpz_cmp_ui(tmp1,1)))goto err1;
	mpz_gcd(tmp1,p1,q1);
	mpz_tdiv_qr(tmp1,tmp2,tmp2,tmp1);
	if(U(mpz_cmp_ui(tmp2,0)))goto err1;
	mpz_mul(tmp2,rsa->key.d,rsa->pub.e);
	mpz_mod(tmp2,tmp2,tmp1);
	if(U(mpz_cmp_ui(tmp2,1)))goto err1;
	r=0;

err1:	mpz_clear(tmp2);
	mpz_clear(tmp1);
	mpz_clear(q1);
	mpz_clear(p1);
	return r;
}

static int nttl_rsa_mpz_write_hdr(unsigned char id,unsigned char *ptr,int len)
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

static int nttl_rsa_mpz_write_int(unsigned char *ptr,mpz_t val)
{
	int bits;
	int len;
	int rl;

	bits=mpz_sizeinbase(val,2);
	len=((bits+7)>>3)+((!(bits&7))?1:0);
	ptr+=(rl=nttl_rsa_mpz_write_hdr(0x02,ptr,len));
	rl+=len;
	if(!(bits&7))*ptr++=0x00;
	len=(bits+7)>>3;
	nettle_mpz_get_str_256(len,ptr,val);
	return rl;
}

static int nttl_rsa_mpz_hdr_add(int len)
{
	if(len>=0x100)len+=4;
	else if(len>=0x80)len+=3;
	else len+=2;
	return len;
}

static int nttl_rsa_mpz_int_size(mpz_t val)
{
	int bits;
	int len;

	bits=mpz_sizeinbase(val,2);
	len=((bits+7)>>3)+((!(bits&7))?1:0);
	return nttl_rsa_mpz_hdr_add(len);
}

static int nttl_rsa_mpz_public(unsigned char *in,int ilen,unsigned char *out,
	int *olen,struct nttl_rsa *rsa)
{
	int len;
	int r=-1;
	mpz_t ival;
	mpz_t oval;

	nettle_mpz_init_set_str_256_u(ival,ilen,in);
	if(U(mpz_cmp(ival,rsa->pub.n)>=0))goto err1;
	*olen=nettle_mpz_sizeinbase_256_u(rsa->pub.n);
	mpz_init(oval);
	mpz_powm(oval,ival,rsa->pub.e,rsa->pub.n);
	len=nettle_mpz_sizeinbase_256_u(oval);
	if(U(len>*olen))goto err2;
	if(len<*olen)memset(out,0,*olen-len);
	if(len)nettle_mpz_get_str_256(len,out+*olen-len,oval);
	r=0;

err2:	mpz_clear(oval);
err1:	mpz_clear(ival);
	return r;
}

static int nttl_rsa_mpz_private(void *ctx,unsigned char *in,int ilen,
	unsigned char *out,int *olen,struct nttl_rsa *rsa)
{
	int len;
	int r=-1;
	mpz_t ival;
	mpz_t oval;

	nettle_mpz_init_set_str_256_u(ival,ilen,in);
	if(U(mpz_cmp(ival,rsa->pub.n)>=0))goto err1;
	*olen=nettle_mpz_sizeinbase_256_u(rsa->pub.n);
	mpz_init(oval);
	if(U(!rsa_compute_root_tr(&rsa->pub,&rsa->key,ctx,nttl_cb_random,
		oval,ival)))goto err2;
	len=nettle_mpz_sizeinbase_256_u(oval);
	if(U(len>*olen))goto err2;
	if(len<*olen)memset(out,0,*olen-len);
	if(len)nettle_mpz_get_str_256(len,out+*olen-len,oval);
	r=0;

err2:	mpz_clear(oval);
err1:	mpz_clear(ival);
	return r;
}

static void nttl_mgf1(unsigned char *mask,int len,unsigned char *seed,int slen,
	struct nttl_md *md)
{
	int i;
	int mdlen;
	int olen=0;
	unsigned char bfr[4];

	mdlen=nttl_md[md->idx].size;
	for(i=0;olen<len;i++)
	{
		bfr[0]=(unsigned char)(i>>24);
		bfr[1]=(unsigned char)(i>>16);
		bfr[2]=(unsigned char)(i>>8);
		bfr[3]=(unsigned char)i;
		nttl_md[md->idx].init(&md->ctx);
		nttl_md[md->idx].update(&md->ctx,slen,seed);
		nttl_md[md->idx].update(&md->ctx,sizeof(bfr),bfr);
		if(olen+mdlen<=len)
		{
			nttl_md[md->idx].digest(&md->ctx,mdlen,mask+olen);
			olen+=mdlen;
		}
		else
		{
			nttl_md[md->idx].digest(&md->ctx,len-olen,mask+olen);
			olen=len;
		}
	}
}

static int nttl_add_oaep_mgf1(void *ctx,unsigned char *dst,int dlen,
	unsigned char *src,int slen,unsigned char *p,int plen,
	struct nttl_md *md)
{
	int i;
	int mdlen;
	unsigned char *dm;
	unsigned char sm[64];

	mdlen=nttl_md[md->idx].size;
	if(U(dlen-1<2*mdlen+1))goto err1;
	dst[0]=0x00;
	yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,mdlen,dst+1);
	nttl_md[md->idx].init(&md->ctx);
	nttl_md[md->idx].update(&md->ctx,plen,p);
	nttl_md[md->idx].digest(&md->ctx,mdlen,dst+mdlen+1);
	memset(dst+2*mdlen+1,0,dlen-slen-2*mdlen-2);
	dst[dlen-slen-1]=0x01;
	memcpy(dst+dlen-slen,src,slen);
	if(U(!(dm=malloc(dlen-mdlen-1))))goto err1;
	nttl_mgf1(dm,dlen-mdlen-1,dst+1,mdlen,md);
	for(i=0;i<dlen-mdlen-1;i++)dst[i+mdlen+1]^=dm[i];
	nttl_mgf1(sm,mdlen,dst+mdlen+1,dlen-mdlen-1,md);
	for(i=0;i<mdlen;i++)dst[i+1]^=sm[i];
	((struct usicrypt_thread *)ctx)->global->memclear(sm,sizeof(sm));
	((struct usicrypt_thread *)ctx)->global->memclear(dm,dlen-mdlen-1);
	free(dm);
	return 0;

err1:	return -1;
}

static int nttl_check_oaep_mgf1(void *ctx,unsigned char *dst,int dlen,
	unsigned char *src,int slen,int n,unsigned char *p,int plen,
	struct nttl_md *md)
{
	int i;
	int l;
	int mdlen;
	unsigned char *mem;
	unsigned char wrk[64];

	mdlen=nttl_md[md->idx].size;
	if(U(n<2*mdlen+2)||U(n-1<slen))goto err1;
	if(U(!(mem=malloc(2*n-mdlen-2))))goto err1;
	memset(mem+n-mdlen-1,0,n-slen-1);
	memcpy(mem+2*n-slen-mdlen-2,src,slen);
	nttl_mgf1(wrk,mdlen,mem+n-1,n-mdlen-1,md);
	for(i=0;i<mdlen;i++)wrk[i]^=mem[i+n-mdlen-1];
	nttl_mgf1(mem,n-mdlen-1,wrk,mdlen,md);
	for(i=0;i<n-mdlen-1;i++)mem[i]^=mem[i+n-1];
	nttl_md[md->idx].init(&md->ctx);
	nttl_md[md->idx].update(&md->ctx,plen,p);
	nttl_md[md->idx].digest(&md->ctx,mdlen,wrk);
	if(U(memcmp(mem,wrk,mdlen)))goto err2;
	for(i=mdlen;i<n-mdlen-1;i++)if(mem[i])break;
	if(U(i==n-mdlen-1)||U(mem[i]!=0x01))goto err2;
	if(U(dlen<(l=n-i-mdlen-2)))goto err2;
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

static int nttl_rsa_mpz_add_pss(void *ctx,struct nttl_rsa *rsa,
	unsigned char *out,unsigned char *in,struct nttl_md *md)
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

	mdlen=nttl_md[md->idx].size;
	bits=(mpz_sizeinbase(rsa->pub.n,2)-1)&0x7;
	bytes=(mpz_sizeinbase(rsa->pub.n,2)+7)>>3;
	slen=bytes-mdlen-2-(bits?0:1);
	if(U(slen-mdlen<0))goto err1;
	if(!bits)
	{
		*out++=0x00;
		bytes--;
	}
	if(slen)
	{
		if(U(!(salt=malloc(slen))))goto err1;
		yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,
			slen,salt);
	}
	else salt=NULL;
	nttl_md[md->idx].init(&md->ctx);
	nttl_md[md->idx].update(&md->ctx,sizeof(zero),(void *)&zero);
	nttl_md[md->idx].update(&md->ctx,mdlen,in);
	nttl_md[md->idx].update(&md->ctx,slen,salt);
	nttl_md[md->idx].digest(&md->ctx,mdlen,out+bytes-mdlen-1);
	nttl_mgf1(out,bytes-mdlen-1,out+bytes-mdlen-1,mdlen,md);
	p=out+bytes-slen-mdlen-2;
	*p++^=0x01;
	for(i=0;i<slen;i++)*p++^=salt[i];
	if(bits)out[0]&=0xff>>(8-bits);
	out[bytes-1]=0xbc;
	r=0;
	if(salt)
	{
		((struct usicrypt_thread *)ctx)->global->memclear(salt,slen);
		free(salt);
	}
	((struct usicrypt_thread *)ctx)->global->
		memclear(&md->ctx,sizeof(md->ctx));
err1:	return r;
}

static int nttl_rsa_mpz_check_pss(void *ctx,struct nttl_rsa *rsa,
	unsigned char *hash,unsigned char *sig,struct nttl_md *md)
{
	int i;
	int r=-1;
	int mdlen;
	int bits;
	int bytes;
	unsigned long long zero=0ULL;
	unsigned char *wrk;

	mdlen=nttl_md[md->idx].size;
	bits=(mpz_sizeinbase(rsa->pub.n,2)-1)&0x7;
	bytes=(mpz_sizeinbase(rsa->pub.n,2)+7)>>3;
	if(U(bytes-2*mdlen-2-(bits?0:1)<0))goto err1;
	if(U(*sig&(0xff<<bits)))goto err1;
	if(!bits)
	{
		sig++;
		bytes--;
	}
	if(U(bytes<mdlen))goto err1;
	if(U(sig[bytes-1]!=0xbc))goto err1;
	if(U(!(wrk=malloc(bytes-mdlen-1))))goto err1;
	nttl_mgf1(wrk,bytes-mdlen-1,sig+bytes-mdlen-1,mdlen,md);
	for(i=0;i<bytes-mdlen-1;i++)wrk[i]^=sig[i];
	if(bits)wrk[0]&=0xff>>(8-bits);
	for(i=0;!wrk[i]&&i<bytes-mdlen-2;i++);
	if(U(wrk[i++]!=0x01))goto err2;
	nttl_md[md->idx].init(&md->ctx);
	nttl_md[md->idx].update(&md->ctx,sizeof(zero),(void *)&zero);
	nttl_md[md->idx].update(&md->ctx,mdlen,hash);
	nttl_md[md->idx].update(&md->ctx,bytes-mdlen-i-1,wrk+i);
	nttl_md[md->idx].digest(&md->ctx,mdlen,hash);
	if(L(!memcmp(hash,sig+bytes-mdlen-1,mdlen)))r=0;
	((struct usicrypt_thread *)ctx)->global->memclear(hash,mdlen);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,bytes-mdlen-1);
	free(wrk);
err1:	return r;
}

static void *nttl_rsa_do_sign_v15(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int n;
	struct nttl_rsa *rsa=key;
	unsigned char *sig=NULL;
	struct usicrypt_iov *iov=data;
	struct nttl_md c;
	unsigned char hash[SHA512_DIGEST_SIZE];
	mpz_t s;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(n=0;n<dlen;n++)
		nttl_md[c.idx].update(&c.ctx,iov[n].length,iov[n].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	mpz_init(s);
	if(U(rsa_pkcs1_sign_tr(&rsa->pub,&rsa->key,ctx,nttl_cb_random,
		nttl_md[c.idx].size,hash,s)!=1))goto err2;
	*slen=nettle_mpz_sizeinbase_256_u(rsa->pub.n);
	n=nettle_mpz_sizeinbase_256_u(s);
	if(U(!(sig=malloc(*slen))))goto err2;
	if(n<*slen)memset(sig,0,*slen-n);
	nettle_mpz_get_str_256(n,sig+*slen-n,s);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mpz_clear(s);
err1:	return sig;
}

static int nttl_rsa_do_verify_v15(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int r;
	struct nttl_rsa *rsa=key;
	struct usicrypt_iov *iov=data;
	struct nttl_md c;
	unsigned char hash[SHA512_DIGEST_SIZE];
	mpz_t s;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:return -1;
	}

	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(r=0;r<dlen;r++)
		nttl_md[c.idx].update(&c.ctx,iov[r].length,iov[r].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	nettle_mpz_init_set_str_256_u(s,slen,sig);
	r=rsa_pkcs1_verify(&rsa->pub,nttl_md[c.idx].size,hash,s);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mpz_clear(s);
	return L(r==1)?0:-1;
}

static void *nttl_rsa_do_sign_pss(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int l;
	struct nttl_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *sig=NULL;
	struct usicrypt_iov *iov=data;
	struct nttl_md c;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	if(U(nttl_reseed(ctx)))goto err1;
	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(l=0;l<dlen;l++)
		nttl_md[c.idx].update(&c.ctx,iov[l].length,iov[l].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	*slen=(mpz_sizeinbase(rsa->pub.n,2)+7)>>3;
	if(U(!(tmp=malloc(*slen))))goto err2;
	if(U(!(sig=malloc(*slen))))goto err3;
	if(U(nttl_rsa_mpz_add_pss(ctx,rsa,tmp,hash,&c)))goto err5;
	if(L(!nttl_rsa_mpz_private(ctx,tmp,*slen,sig,&l,rsa))&&L(l==*slen))
		goto err4;

	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
err5:	free(sig);
	sig=NULL;
err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*slen);
err3:	free(tmp);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	return sig;
}

static int nttl_rsa_do_verify_pss(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int l;
	int r=-1;
	struct nttl_rsa *rsa=key;
	unsigned char *tmp;
	struct usicrypt_iov *iov=data;
	struct nttl_md c;
	unsigned char hash[64];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(l=0;l<dlen;l++)
		nttl_md[c.idx].update(&c.ctx,iov[l].length,iov[l].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	if(U(slen!=((mpz_sizeinbase(rsa->pub.n,2)+7)>>3)))goto err2;
	if(!(tmp=malloc(slen)))goto err2;
	if(U(nttl_rsa_mpz_public(sig,slen,tmp,&l,rsa))||U(l!=slen))goto err3;
	if(U(nttl_rsa_mpz_check_pss(ctx,rsa,hash,tmp,&c)))goto err3;
	r=0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,slen);
	free(tmp);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	return r;
}

#endif
#ifndef USICRYPT_NO_DH

static int nttl_dh_mpz_test_primes(mpz_t *prime)
{
	int r=-1;
	int i;
	mpz_t n;
	
	mpz_init(n);
	for(i=0;i<171;i++)
	{
		mpz_tdiv_r_ui(n,*prime,nttl_primes[i]);
		if(!mpz_cmp_ui(n,0))break;
	}
	if(i==171)r=0;
	mpz_clear(n);
	return r;
}       

static int nttl_dh_mpz_miller_rabin(void *ctx,mpz_t *prime)
{
	int res=-1;
	int i;
	int n;
	int x;
	int c;
	int iter;
	int bits;
	mpz_t w;
	mpz_t r;
	mpz_t a;

	mpz_init(w);
	mpz_init(r);
	mpz_init(a);

	bits=mpz_sizeinbase(*prime,2);
	
	for(i=0;bits<nttl_mr_tab[i].bits;i++);
	iter=nttl_mr_tab[i].iter;

	mpz_sub_ui(w,*prime,1);
	for(x=0;x<bits;x++)if(mpz_tstbit(w,x))break;
	mpz_tdiv_q_2exp(r,w,x);

	for(i=0,c=32;i<iter;i++,c=32)
	{
		do
		{
			if(U(!c--))goto err1;
			nettle_mpz_random_size(a,ctx,nttl_cb_random,bits);
			n=mpz_sizeinbase(a,2)-mpz_sizeinbase(w,2);
			if(n>0)mpz_tdiv_q_2exp(a,a,n);
		} while(mpz_cmp(a,w)>=0||mpz_cmp_ui(a,2)<0);

		mpz_powm(a,a,r,*prime);
		if(!mpz_cmp(a,w)||!mpz_cmp_ui(a,1))continue;

		for(n=1;n<x&&mpz_cmp(a,w);n++)
		{
			mpz_mul(a,a,a);
			mpz_mod(a,a,*prime);
			if(!mpz_cmp_ui(a,1))goto err1;
		}
		if(mpz_cmp(a,w))goto err1;
	}
	res=0;

err1:	mpz_clear(w);
	mpz_clear(r);
	mpz_clear(a);
	return res;
}

static int nttl_dh_mpz_is_prime(void *ctx,mpz_t *prime1,mpz_t *prime2)
{
	if(nttl_dh_mpz_test_primes(prime1))return -1;
	if(nttl_dh_mpz_test_primes(prime2))return -1;
	if(nttl_dh_mpz_miller_rabin(ctx,prime1))return -1;
	if(nttl_dh_mpz_miller_rabin(ctx,prime2))return -1;
	return 0;
}

static int nttl_dh_mpz_gen_prime(void *ctx,mpz_t *prime,int bits)
{
	int r=-1;
	mpz_t p;
	mpz_t n;

	mpz_init(p);
	mpz_init(n);

	do
	{
		nettle_mpz_random_size(p,ctx,nttl_cb_random,bits);
		mpz_setbit(p,bits-1);
		mpz_setbit(p,0);
		mpz_setbit(p,1);

		mpz_tdiv_r_ui(n,p,3);
		if(!mpz_cmp_ui(n,0))mpz_add_ui(p,p,8);
		else if(!mpz_cmp_ui(n,1))mpz_add_ui(p,p,4);

		mpz_tdiv_q_2exp(n,p,1);

		while(1)
		{
			while(nttl_dh_mpz_is_prime(ctx,&p,&n))
			{
				mpz_add_ui(p,p,12);
				mpz_add_ui(n,n,6);
			}
			if(!mpz_probab_prime_p(p,32)||!mpz_probab_prime_p(n,32))
			{
				mpz_add_ui(p,p,12);
				mpz_add_ui(n,n,6);
			}
			else break;
		}
	} while(mpz_sizeinbase(p,2)!=bits);

	mpz_set(*prime,p);
	r=0;

	mpz_clear(p);
	mpz_clear(n);
	return r;
}

#endif
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_CMAC

static int nttl_aes_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	unsigned char *s=src;
	struct aes_ctx enc;
	unsigned char wrk[4][16];

	if(U(klen&7))return -1;
	aes_set_encrypt_key(&enc,klen>>3,key);
	memset(wrk,0,sizeof(wrk));
	aes_encrypt(&enc,16,wrk[1],wrk[1]);
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(;slen>16;slen-=16,s+=16)
	{
		for(i=0;i<16;i++)wrk[0][i]^=s[i];
		aes_encrypt(&enc,16,wrk[0],wrk[0]);
	}
	if(slen<16)for(i=0;i<16;i++)
	{
		if(i<slen)wrk[1][i]=s[i];
		else if(i==slen)wrk[1][i]=0x80;
		else wrk[1][i]=0x00;
		wrk[1][i]^=wrk[3][i];
	}
	else for(i=0;i<16;i++)wrk[1][i]=s[i]^wrk[2][i];
	for(i=0;i<16;i++)wrk[0][i]^=wrk[1][i];
	aes_encrypt(&enc,16,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_aes_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	int n;
	int j;
	int r1;
	int r2;
	int x1;
	int x2;
	unsigned char *s;
	unsigned char *p1;
	unsigned char *p2;
	struct aes_ctx enc;
	unsigned char wrk[6][16];

	if(U(klen&7))return -1;
	aes_set_encrypt_key(&enc,klen>>3,key);
	memset(wrk,0,sizeof(wrk));
	aes_encrypt(&enc,16,wrk[1],wrk[1]);
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(j=0,r1=0,r2=0,p1=&wrk[4][0],p2=&wrk[5][0];j<niov;j++)
	{
		if(r1<16)
		{
			x1=(r1+iov[j].length>16?16-r1:iov[j].length);
			memcpy(p1+r1,iov[j].data,x1);
			r1+=x1;
		}
		else x1=0;
		while(iov[j].length-x1)
		{
			x2=(r2+iov[j].length-x1>16?16-r2:iov[j].length-x1);
			memcpy(p2+r2,iov[j].data+x1,x2);
			r2+=x2;
			x1+=x2;
			if(r2==16)
			{
				for(i=0;i<16;i++)wrk[0][i]^=p1[i];
				aes_encrypt(&enc,16,wrk[0],wrk[0]);
				s=p1;
				p1=p2;
				p2=s;
				r2=0;
			}
		}
	}
	if(r2)
	{
		for(i=0;i<16;i++)wrk[0][i]^=p1[i];
		aes_encrypt(&enc,16,wrk[0],wrk[0]);
		s=p1;
		p1=p2;
		p2=s;
		r1=r2;
	}
	if(r1<16)for(i=0;i<16;i++)
	{
		if(i<r1)wrk[1][i]=p1[i];
		else if(i==r1)wrk[1][i]=0x80;
		else wrk[1][i]=0x00;
		wrk[1][i]^=wrk[3][i];
	}
	else for(i=0;i<16;i++)wrk[1][i]=p1[i]^wrk[2][i];
	for(i=0;i<16;i++)wrk[0][i]^=wrk[1][i];
	aes_encrypt(&enc,16,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int nttl_aes_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	aes_encrypt(&((struct nttl_aes_ecb *)ctx)->enc,slen,dst,src);
	return 0;
}

static int nttl_aes_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	aes_decrypt(&((struct nttl_aes_ecb *)ctx)->dec,slen,dst,src);
	return 0;
}

static void *nttl_aes_ecb_init(void *ctx,void *key,int klen)
{
	struct nttl_aes_ecb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_ecb)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes_set_decrypt_key(&aes->dec,klen>>3,key);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_ecb_exit(void *ctx)
{
	((struct nttl_aes_ecb *)ctx)->global->memclear(
		&((struct nttl_aes_ecb *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_ecb *)ctx)->global->memclear(
		&((struct nttl_aes_ecb *)ctx)->dec,sizeof(struct aes_ctx));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int nttl_aes_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	cbc_encrypt(&((struct nttl_aes_cbc *)ctx)->enc,(void *)aes_encrypt,
		16,((struct nttl_aes_cbc *)ctx)->iv,slen,dst,src);
	return 0;
}

static int nttl_aes_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	cbc_decrypt(&((struct nttl_aes_cbc *)ctx)->dec,(void *)aes_decrypt,
		16,((struct nttl_aes_cbc *)ctx)->iv,slen,dst,src);
	return 0;
}

static void *nttl_aes_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_aes_cbc *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_cbc)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes_set_decrypt_key(&aes->dec,klen>>3,key);
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct nttl_aes_cbc *)ctx)->iv,iv,16);
}

static void nttl_aes_cbc_exit(void *ctx)
{
	((struct nttl_aes_cbc *)ctx)->global->memclear(
		&((struct nttl_aes_cbc *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_cbc *)ctx)->global->memclear(
		&((struct nttl_aes_cbc *)ctx)->dec,sizeof(struct aes_ctx));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int nttl_aes_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct nttl_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	cbc_encrypt(&aes->enc,(void *)aes_encrypt,16,aes->iv,slen-rem,d,s);
	s+=slen-rem;
	d+=slen-rem;
	memcpy(aes->tmp,s,rem);
	if(rem<16)memset(aes->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	cbc_encrypt(&aes->enc,(void *)aes_encrypt,16,aes->iv,16,d-16,aes->tmp);
	return 0;
}

static int nttl_aes_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct nttl_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(slen-rem-16)
	{
		cbc_decrypt(&aes->dec,(void *)aes_decrypt,16,aes->iv,
			slen-rem-16,d,s);
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(aes->tmp+16,s,16);
	aes_decrypt(&aes->dec,16,aes->tmp,s);
	memcpy(aes->tmp,s+16,rem);
	cbc_decrypt(&aes->dec,(void *)aes_decrypt,16,aes->iv,32,aes->tmp,
		aes->tmp);
	memcpy(d,aes->tmp,rem+16);
	return 0;
}

static void *nttl_aes_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_aes_cts *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_cts)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes_set_decrypt_key(&aes->dec,klen>>3,key);
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct nttl_aes_cts *)ctx)->iv,iv,16);
}

static void nttl_aes_cts_exit(void *ctx)
{
	((struct nttl_aes_cts *)ctx)->global->memclear(
		&((struct nttl_aes_cts *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_cts *)ctx)->global->memclear(
		&((struct nttl_aes_cts *)ctx)->dec,sizeof(struct aes_ctx));
	((struct nttl_aes_cts *)ctx)->global->memclear(
		((struct nttl_aes_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int nttl_aes_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!aes->n)aes_encrypt(&aes->enc,16,aes->mem,aes->iv);
		aes->iv[aes->n]=*d++=*s++^aes->mem[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static int nttl_aes_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!aes->n)aes_encrypt(&aes->enc,16,aes->mem,aes->iv);
		aes->iv[aes->n]=*s;
		*d++=*s++^aes->mem[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static void *nttl_aes_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_aes_xfb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_xfb)))))goto err1;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_cfb_reset(void *ctx,void *iv)
{
	((struct nttl_aes_xfb *)ctx)->n=0;
	memcpy(((struct nttl_aes_xfb *)ctx)->iv,iv,16);
}

static void nttl_aes_cfb_exit(void *ctx)
{
	((struct nttl_aes_xfb *)ctx)->global->
		memclear(&((struct nttl_aes_xfb *)ctx)->enc,
		sizeof(struct aes_ctx));
	((struct nttl_aes_xfb *)ctx)->global->
		memclear(&((struct nttl_aes_xfb *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int nttl_aes_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
        unsigned char *s=src;
        unsigned char *d=dst;
        struct nttl_aes_cfb8 *aes=ctx;

        while(slen--)
        {
		aes_encrypt(&aes->enc,16,aes->mem,aes->iv);
                memmove(aes->iv,aes->iv+1,15);
                *d++=aes->iv[15]=*s++^aes->mem[0];
        }
        return 0;
}

static int nttl_aes_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
        unsigned char *s=src;
        unsigned char *d=dst;
        struct nttl_aes_cfb8 *aes=ctx;

        while(slen--)
        {
		aes_encrypt(&aes->enc,16,aes->mem,aes->iv);
                memmove(aes->iv,aes->iv+1,15);
                aes->iv[15]=*s;
                *d++=*s++^aes->mem[0];
        }
        return 0;
}

static void *nttl_aes_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
        struct nttl_aes_cfb8 *aes;

        if(U(klen&7))goto err1;
        if(U(!(aes=malloc(sizeof(struct nttl_aes_cfb8)))))goto err1;
        aes->global=((struct usicrypt_thread *)ctx)->global;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
        ((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
        return aes;

err1:   ((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
        return NULL;
}

static void nttl_aes_cfb8_reset(void *ctx,void *iv)
{
        memcpy(((struct nttl_aes_cfb8 *)ctx)->iv,iv,16);
}

static void nttl_aes_cfb8_exit(void *ctx)
{
        ((struct nttl_aes_cfb8 *)ctx)->global->
                memclear(&((struct nttl_aes_cfb8 *)ctx)->enc,
		sizeof(struct aes_ctx));
        ((struct nttl_aes_cfb8 *)ctx)->global->
                memclear(((struct nttl_aes_cfb8 *)ctx)->iv,16);
        ((struct nttl_aes_cfb8 *)ctx)->global->
                memclear(((struct nttl_aes_cfb8 *)ctx)->mem,16);
        free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int nttl_aes_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!aes->n)cbc_encrypt(&aes->enc,(void *)aes_encrypt,16,aes->iv,
			16,aes->iv,aes->zero);
		*d++=aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!aes->n)cbc_encrypt(&aes->enc,(void *)aes_encrypt,16,aes->iv,
			16,aes->iv,aes->zero);
		*d++=*s++^aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static void *nttl_aes_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_aes_xfb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_xfb)))))goto err1;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	memset(aes->zero,0,sizeof(aes->zero));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_ofb_reset(void *ctx,void *iv)
{
	((struct nttl_aes_xfb *)ctx)->n=0;
	memcpy(((struct nttl_aes_xfb *)ctx)->iv,iv,16);
}

static void nttl_aes_ofb_exit(void *ctx)
{
	((struct nttl_aes_xfb *)ctx)->global->
		memclear(&((struct nttl_aes_xfb *)ctx)->enc,
		sizeof(struct aes_ctx));
	((struct nttl_aes_xfb *)ctx)->global->
		memclear(&((struct nttl_aes_xfb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int nttl_aes_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	int i;
	struct nttl_aes_ctr *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(aes->n&&slen)
	{
		if(s)*d++=aes->mem[aes->n++]^*s++;
		else *d++=aes->mem[aes->n++];
		aes->n&=0xf;
		if(!--slen)return 0;
	}
	while(slen>=16)
	{
		aes_encrypt(&aes->enc,16,d,aes->ctr);
		for(i=15;i>=0;i--)if(++(aes->ctr[i]))break;
		if(s)for(i=0;i<16;i++)d[i]^=*s++;
		d+=16;
		slen-=16;
	}
	if(slen)
	{
		aes_encrypt(&aes->enc,16,aes->mem,aes->ctr);
		for(i=15;i>=0;i--)if(++(aes->ctr[i]))break;
		if(s)for(i=0;i<slen;i++)d[i]=aes->mem[aes->n++]^*s++;
		else for(i=0;i<slen;i++)d[i]=aes->mem[aes->n++];
	}
	return 0;
}

static void *nttl_aes_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_aes_ctr *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_ctr)))))goto err1;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	if(iv)memcpy(aes->ctr,iv,16);
	else memset(aes->ctr,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_ctr_reset(void *ctx,void *iv)
{
	((struct nttl_aes_ctr *)ctx)->n=0;
	memcpy(((struct nttl_aes_ctr *)ctx)->ctr,iv,16);
}

static void nttl_aes_ctr_exit(void *ctx)
{
	((struct nttl_aes_ctr *)ctx)->global->
		memclear(&((struct nttl_aes_ctr *)ctx)->enc,
			sizeof(struct aes_ctx));
	((struct nttl_aes_ctr *)ctx)->global->
		memclear(&((struct nttl_aes_ctr *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int nttl_aes_xts_encrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct nttl_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	aes_encrypt(&aes->twe,16,aes->twk,iv);

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		aes_encrypt(&aes->enc,16,d,aes->wrk);
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=aes->twk[i];
			aes->twk[i]=(unsigned char)(n|=(aes->twk[i]<<1));
		}
		if(n)aes->twk[0]^=0x87;
	}

	if(slen)
	{
		d-=16;
		memcpy(d+16,d,slen);
		memcpy(aes->wrk,s,slen);
		memcpy(aes->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)aes->wrk[i]^=aes->twk[i];
		aes_encrypt(&aes->enc,16,d,aes->wrk);
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
	}

	return 0;
}

static int nttl_aes_xts_decrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct nttl_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	aes_encrypt(&aes->twe,16,aes->twk,iv);

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		aes_decrypt(&aes->dec,16,d,aes->wrk);
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=aes->twk[i];
			aes->twk[i]=(unsigned char)(n|=(aes->twk[i]<<1));
		}
		if(n)aes->twk[0]^=0x87;
	}

	if(slen)
	{
		memcpy(aes->mem,aes->twk,16);
		for(n=0,i=0;i<16;i++,n>>=8)
			aes->twk[i]=(unsigned char)(n|=(aes->twk[i]<<1));
		if(n)aes->twk[0]^=0x87;
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		aes_decrypt(&aes->dec,16,d,aes->wrk);
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
		memcpy(d+16,d,slen);
		memcpy(aes->wrk,s+16,slen);
		memcpy(aes->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)aes->wrk[i]^=aes->mem[i];
		aes_decrypt(&aes->dec,16,d,aes->wrk);
		for(i=0;i<16;i++)d[i]^=aes->mem[i];
	}

	return 0;
}

static void *nttl_aes_xts_init(void *ctx,void *key,int klen)
{
	struct nttl_aes_xts *aes;

	if(U(klen!=256&&klen!=512))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_xts)))))goto err1;
	aes_set_encrypt_key(&aes->enc,klen>>4,key);
	aes_set_decrypt_key(&aes->dec,klen>>4,key);
	aes_set_encrypt_key(&aes->twe,klen>>4,key+(klen>>4));
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_xts_exit(void *ctx)
{
	struct usicrypt_global *global=((struct nttl_aes_xts *)ctx)->global;

	global->memclear(ctx,sizeof(struct nttl_aes_xts));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int nttl_aes_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct nttl_aes_essiv *aes=ctx;

	if(U(slen&0xf))return -1;
	aes_encrypt(&aes->aux,16,aes->iv,iv);
	cbc_encrypt(&aes->enc,(void *)aes_encrypt,16,aes->iv,slen,dst,src);
	return 0;
}

static int nttl_aes_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct nttl_aes_essiv *aes=ctx;

	if(U(slen&0xf))return -1;
	aes_encrypt(&aes->aux,16,aes->iv,iv);
	cbc_decrypt(&aes->dec,(void *)aes_decrypt,16,aes->iv,slen,dst,src);
	return 0;
}

static void *nttl_aes_essiv_init(void *ctx,void *key,int klen)
{
	struct nttl_aes_essiv *aes;
	struct sha256_ctx h;
	unsigned char tmp[SHA256_DIGEST_SIZE];

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_essiv)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	aes_set_decrypt_key(&aes->dec,klen>>3,key);
	sha256_init(&h);
	sha256_update(&h,klen>>3,key);
	sha256_digest(&h,SHA256_DIGEST_SIZE,tmp);
	aes_set_encrypt_key(&aes->aux,SHA256_DIGEST_SIZE,tmp);
	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_essiv_exit(void *ctx)
{
	((struct nttl_aes_essiv *)ctx)->global->memclear(
		&((struct nttl_aes_essiv *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_essiv *)ctx)->global->memclear(
		&((struct nttl_aes_essiv *)ctx)->dec,sizeof(struct aes_ctx));
	((struct nttl_aes_essiv *)ctx)->global->memclear(
		&((struct nttl_aes_essiv *)ctx)->aux,sizeof(struct aes_ctx));
	((struct nttl_aes_essiv *)ctx)->global->memclear(
		&((struct nttl_aes_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_GCM

static int nttl_aes_gcm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int rem;
	struct nttl_aes_gcm *aes=ctx;

	gcm_set_iv(&aes->ctx,&aes->gcm,aes->ilen,iv);
	if(aad&&alen)
	{
		rem=alen&(GCM_BLOCK_SIZE-1);
		gcm_update(&aes->ctx,&aes->gcm,alen-rem,aad);
		if(rem)
		{
			memcpy(aes->mem,aad+alen-rem,rem);
			memset(aes->mem+rem,0,GCM_BLOCK_SIZE-rem);
			gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,aes->mem);
			aes->ctx.auth_size-=GCM_BLOCK_SIZE-rem;
		}
	}
	gcm_encrypt(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		slen,dst,src);
	gcm_digest(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		aes->tlen,tag);
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_aes_gcm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int n;
	int x;
	int i;
	struct nttl_aes_gcm *aes=ctx;

	gcm_set_iv(&aes->ctx,&aes->gcm,aes->ilen,iv);
	for(i=0,n=0;i<niov;i++)
	{
		if(n)
		{
			x=(n+iov[i].length>GCM_BLOCK_SIZE?
				GCM_BLOCK_SIZE-n:iov[i].length);
			memcpy(aes->mem+n,iov[i].data,x);
			if(n+x==GCM_BLOCK_SIZE)
			{
				gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,
					aes->mem);
				n=0;
			}
			else n+=x;
		}
		else x=0;
		if(!(iov[i].length-x))continue;
		n=(iov[i].length-x)&(GCM_BLOCK_SIZE-1);
		gcm_update(&aes->ctx,&aes->gcm,iov[i].length-x-n,iov[i].data+x);
		if(n)memcpy(aes->mem,iov[i].data+iov[i].length-n,n);
	}
	if(n)
	{
		memset(aes->mem+n,0,GCM_BLOCK_SIZE-n);
		gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,aes->mem);
		aes->ctx.auth_size-=GCM_BLOCK_SIZE-n;
	}
	gcm_encrypt(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		slen,dst,src);
	gcm_digest(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		aes->tlen,tag);
	return 0;
}

#endif

static int nttl_aes_gcm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int rem;
	int r;
	struct nttl_aes_gcm *aes=ctx;
	unsigned char cmp[16];

	gcm_set_iv(&aes->ctx,&aes->gcm,aes->ilen,iv);
	if(aad&&alen)
	{
		rem=alen&(GCM_BLOCK_SIZE-1);
		gcm_update(&aes->ctx,&aes->gcm,alen-rem,aad);
		if(rem)
		{
			memcpy(aes->mem,aad+alen-rem,rem);
			memset(aes->mem+rem,0,GCM_BLOCK_SIZE-rem);
			gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,aes->mem);
			aes->ctx.auth_size-=GCM_BLOCK_SIZE-rem;
		}
	}
	gcm_decrypt(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		slen,dst,src);
	gcm_digest(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		aes->tlen,cmp);
	r=memcmp(cmp,tag,aes->tlen);
	((struct nttl_aes_gcm *)ctx)->global->memclear(cmp,aes->tlen);
	return U(r)?-1:0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_aes_gcm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int n;
	int x;
	int i;
	int r;
	struct nttl_aes_gcm *aes=ctx;
	unsigned char cmp[16];

	gcm_set_iv(&aes->ctx,&aes->gcm,aes->ilen,iv);
	for(i=0,n=0;i<niov;i++)
	{
		if(n)
		{
			x=(n+iov[i].length>GCM_BLOCK_SIZE?
				GCM_BLOCK_SIZE-n:iov[i].length);
			memcpy(aes->mem+n,iov[i].data,x);
			if(n+x==GCM_BLOCK_SIZE)
			{
				gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,
					aes->mem);
				n=0;
			}
			else n+=x;
		}
		else x=0;
		if(!(iov[i].length-x))continue;
		n=(iov[i].length-x)&(GCM_BLOCK_SIZE-1);
		gcm_update(&aes->ctx,&aes->gcm,iov[i].length-x-n,iov[i].data+x);
		if(n)memcpy(aes->mem,iov[i].data+iov[i].length-n,n);
	}
	if(n)
	{
		memset(aes->mem+n,0,GCM_BLOCK_SIZE-n);
		gcm_update(&aes->ctx,&aes->gcm,GCM_BLOCK_SIZE,aes->mem);
		aes->ctx.auth_size-=GCM_BLOCK_SIZE-n;
	}
	gcm_decrypt(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		slen,dst,src);
	gcm_digest(&aes->ctx,&aes->gcm,&aes->enc,(void *)aes_encrypt,
		aes->tlen,cmp);
	r=memcmp(cmp,tag,aes->tlen);
	((struct nttl_aes_gcm *)ctx)->global->memclear(cmp,aes->tlen);
	return U(r)?-1:0;
}

#endif

static void *nttl_aes_gcm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct nttl_aes_gcm *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_gcm)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->ilen=ilen;
	aes->tlen=tlen;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	gcm_set_key(&aes->gcm,&aes->enc,(void *)aes_encrypt);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_gcm_exit(void *ctx)
{
	((struct nttl_aes_gcm *)ctx)->global->memclear(
		&((struct nttl_aes_gcm *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_gcm *)ctx)->global->memclear(
		&((struct nttl_aes_gcm *)ctx)->gcm,sizeof(struct gcm_key));
	((struct nttl_aes_gcm *)ctx)->global->memclear(
		&((struct nttl_aes_gcm *)ctx)->ctx,sizeof(struct gcm_ctx));
	((struct nttl_aes_gcm *)ctx)->global->memclear(
		&((struct nttl_aes_gcm *)ctx)->mem,GCM_BLOCK_SIZE);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CCM

static int nttl_aes_ccm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	struct nttl_aes_ccm *aes=ctx;

	ccm_set_nonce(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->ilen,
		iv,alen,slen,aes->tlen);
	if(aad&&alen)ccm_update(&aes->ctx,&aes->enc,(void *)aes_encrypt,
		alen,aad);
	ccm_encrypt(&aes->ctx,&aes->enc,(void *)aes_encrypt,slen,dst,src);
	ccm_digest(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->tlen,tag);
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_aes_ccm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	struct nttl_aes_ccm *aes=ctx;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	ccm_set_nonce(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->ilen,
		iv,alen,slen,aes->tlen);
	for(i=0;i<niov;i++)ccm_update(&aes->ctx,&aes->enc,(void *)aes_encrypt,
		iov[i].length,iov[i].data);
	ccm_encrypt(&aes->ctx,&aes->enc,(void *)aes_encrypt,slen,dst,src);
	ccm_digest(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->tlen,tag);
	return 0;
}

#endif

static int nttl_aes_ccm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int r;
	struct nttl_aes_ccm *aes=ctx;
	unsigned char cmp[16];

	ccm_set_nonce(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->ilen,
		iv,alen,slen,aes->tlen);
	if(aad&&alen)ccm_update(&aes->ctx,&aes->enc,(void *)aes_encrypt,
		alen,aad);
	ccm_decrypt(&aes->ctx,&aes->enc,(void *)aes_encrypt,slen,dst,src);
	ccm_digest(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->tlen,cmp);
	r=memcmp(cmp,tag,aes->tlen);
	((struct nttl_aes_ccm *)ctx)->global->memclear(cmp,aes->tlen);
	return U(r)?-1:0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_aes_ccm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	int r;
	struct nttl_aes_ccm *aes=ctx;
	unsigned char cmp[16];

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	ccm_set_nonce(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->ilen,
		iv,alen,slen,aes->tlen);
	for(i=0;i<niov;i++)ccm_update(&aes->ctx,&aes->enc,(void *)aes_encrypt,
		iov[i].length,iov[i].data);
	ccm_decrypt(&aes->ctx,&aes->enc,(void *)aes_encrypt,slen,dst,src);
	ccm_digest(&aes->ctx,&aes->enc,(void *)aes_encrypt,aes->tlen,cmp);
	r=memcmp(cmp,tag,aes->tlen);
	((struct nttl_aes_ccm *)ctx)->global->memclear(cmp,aes->tlen);
	return U(r)?-1:0;
}

#endif

static void *nttl_aes_ccm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct nttl_aes_ccm *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct nttl_aes_ccm)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->ilen=ilen;
	aes->tlen=tlen;
	aes_set_encrypt_key(&aes->enc,klen>>3,key);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_aes_ccm_exit(void *ctx)
{
	((struct nttl_aes_ccm *)ctx)->global->memclear(
		&((struct nttl_aes_ccm *)ctx)->enc,sizeof(struct aes_ctx));
	((struct nttl_aes_ccm *)ctx)->global->memclear(
		&((struct nttl_aes_ccm *)ctx)->ctx,sizeof(struct ccm_ctx));
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY

static int nttl_chacha_poly_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	chacha_poly1305_set_nonce(&((struct nttl_chacha_poly *)ctx)->ctx,iv);
	if(aad&&alen)chacha_poly1305_update(
		&((struct nttl_chacha_poly *)ctx)->ctx,alen,aad);
	chacha_poly1305_encrypt(&((struct nttl_chacha_poly *)ctx)->ctx,
		slen,dst,src);
	chacha_poly1305_digest(&((struct nttl_chacha_poly *)ctx)->ctx,
		CHACHA_POLY1305_DIGEST_SIZE,tag);
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_chacha_poly_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;

	chacha_poly1305_set_nonce(&((struct nttl_chacha_poly *)ctx)->ctx,iv);
	for(i=0;i<niov;i++)chacha_poly1305_update(
		&((struct nttl_chacha_poly *)ctx)->ctx,iov[i].length,
		iov[i].data);
	chacha_poly1305_encrypt(&((struct nttl_chacha_poly *)ctx)->ctx,
		slen,dst,src);
	chacha_poly1305_digest(&((struct nttl_chacha_poly *)ctx)->ctx,
		CHACHA_POLY1305_DIGEST_SIZE,tag);
	return 0;
}

#endif

static int nttl_chacha_poly_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int r;
	unsigned char cmp[CHACHA_POLY1305_DIGEST_SIZE];

	chacha_poly1305_set_nonce(&((struct nttl_chacha_poly *)ctx)->ctx,iv);
	if(aad&&alen)chacha_poly1305_update(
		&((struct nttl_chacha_poly *)ctx)->ctx,alen,aad);
	chacha_poly1305_decrypt(&((struct nttl_chacha_poly *)ctx)->ctx,
		slen,dst,src);
	chacha_poly1305_digest(&((struct nttl_chacha_poly *)ctx)->ctx,
		CHACHA_POLY1305_DIGEST_SIZE,cmp);
	r=memcmp(cmp,tag,CHACHA_POLY1305_DIGEST_SIZE);
	((struct nttl_chacha_poly *)ctx)->global->memclear(cmp,sizeof(cmp));
	return U(r)?-1:0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_chacha_poly_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int r;
	unsigned char cmp[CHACHA_POLY1305_DIGEST_SIZE];

	chacha_poly1305_set_nonce(&((struct nttl_chacha_poly *)ctx)->ctx,iv);
	for(i=0;i<niov;i++)chacha_poly1305_update(
		&((struct nttl_chacha_poly *)ctx)->ctx,iov[i].length,
		iov[i].data);
	chacha_poly1305_decrypt(&((struct nttl_chacha_poly *)ctx)->ctx,
		slen,dst,src);
	chacha_poly1305_digest(&((struct nttl_chacha_poly *)ctx)->ctx,
		CHACHA_POLY1305_DIGEST_SIZE,cmp);
	r=memcmp(cmp,tag,CHACHA_POLY1305_DIGEST_SIZE);
	((struct nttl_chacha_poly *)ctx)->global->memclear(cmp,sizeof(cmp));
	return U(r)?-1:0;
}

#endif

static void *nttl_chacha_poly_init(void *ctx,void *key,int klen,int ilen,
	int tlen)
{
	struct nttl_chacha_poly *chp;

	if(U(klen!=256)||U(ilen!=12)||U(tlen!=16))goto err1;
	if(U(!(chp=malloc(sizeof(struct nttl_chacha_poly)))))goto err1;
	chp->global=((struct usicrypt_thread *)ctx)->global;
	chacha_poly1305_set_key(&chp->ctx,key);
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return chp;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return NULL;
}

static void nttl_chacha_poly_exit(void *ctx)
{
	((struct nttl_chacha_poly *)ctx)->global->memclear(
		&((struct nttl_chacha_poly *)ctx)->ctx,
			sizeof(struct chacha_poly1305_ctx));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_STREAM

static int nttl_chacha_crypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct nttl_chacha *ch=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(ch->n&&slen)
	{
		*d++=*s++^ch->mem[ch->n++];
		ch->n&=CHACHA_BLOCK_SIZE-1;
		if(!--slen)return 0;
	}
	rem=slen&(CHACHA_BLOCK_SIZE-1);
	if(slen-rem)chacha_crypt(&ch->ctx,slen-rem,d,s);
	if(rem)
	{
		d+=slen-rem;
		s+=slen-rem;
		memset(ch->mem,0,CHACHA_BLOCK_SIZE);
		chacha_crypt(&ch->ctx,CHACHA_BLOCK_SIZE,ch->mem,ch->mem);
		while(rem--)*d++=*s++^ch->mem[ch->n++];
	}
	return 0;
}

static void *nttl_chacha_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_chacha *ch;
	unsigned long long zero[2]={0,0};

	if(U(klen!=256))goto err1;
	if(U(!(ch=malloc(sizeof(struct nttl_chacha)))))goto err1;
	ch->global=((struct usicrypt_thread *)ctx)->global;
	ch->n=0;
	chacha_set_key(&ch->ctx,key);
	if(!iv)iv=zero;
	chacha_set_nonce(&ch->ctx,iv);
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return ch;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return NULL;
}

static void nttl_chacha_reset(void *ctx,void *iv)
{
	((struct nttl_chacha *)ctx)->n=0;
	chacha_set_nonce(&((struct nttl_chacha *)ctx)->ctx,iv);
}

static void nttl_chacha_exit(void *ctx)
{
	((struct nttl_chacha *)ctx)->global->memclear(
		&((struct nttl_chacha *)ctx)->ctx,sizeof(struct chacha_ctx));
	((struct nttl_chacha *)ctx)->global->memclear(
		&((struct nttl_chacha *)ctx)->mem,CHACHA_BLOCK_SIZE);
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_CMAC

static int nttl_camellia_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	unsigned char *s=src;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	unsigned char wrk[4][16];

	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&enc.enc128,key);
		crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&enc.enc256,key);
		crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&enc.enc256,key);
		crypt=(void *)camellia256_crypt;
		break;
	default:return -1;
	}
	memset(wrk,0,sizeof(wrk));
	crypt(&enc,16,wrk[1],wrk[1]);
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(;slen>16;slen-=16,s+=16)
	{
		for(i=0;i<16;i++)wrk[0][i]^=s[i];
		crypt(&enc,16,wrk[0],wrk[0]);
	}
	if(slen<16)for(i=0;i<16;i++)
	{
		if(i<slen)wrk[1][i]=s[i];
		else if(i==slen)wrk[1][i]=0x80;
		else wrk[1][i]=0x00;
		wrk[1][i]^=wrk[3][i];
	}
	else for(i=0;i<16;i++)wrk[1][i]=s[i]^wrk[2][i];
	for(i=0;i<16;i++)wrk[0][i]^=wrk[1][i];
	crypt(&enc,16,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int nttl_camellia_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	int n;
	int j;
	int r1;
	int r2;
	int x1;
	int x2;
	unsigned char *s;
	unsigned char *p1;
	unsigned char *p2;
	void (*crypt)(void *ctx,size_t length,uint8_t *dst,const uint8_t *src);
	union
	{
		struct camellia128_ctx enc128;
		struct camellia256_ctx enc256;
	} enc;
	unsigned char wrk[6][16];

	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&enc.enc128,key);
		crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&enc.enc256,key);
		crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&enc.enc256,key);
		crypt=(void *)camellia256_crypt;
		break;
	default:return -1;
	}
	memset(wrk,0,sizeof(wrk));
	crypt(&enc,16,wrk[1],wrk[1]);
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(j=0,r1=0,r2=0,p1=&wrk[4][0],p2=&wrk[5][0];j<niov;j++)
	{
		if(r1<16)
		{
			x1=(r1+iov[j].length>16?16-r1:iov[j].length);
			memcpy(p1+r1,iov[j].data,x1);
			r1+=x1;
		}
		else x1=0;
		while(iov[j].length-x1)
		{
			x2=(r2+iov[j].length-x1>16?16-r2:iov[j].length-x1);
			memcpy(p2+r2,iov[j].data+x1,x2);
			r2+=x2;
			x1+=x2;
			if(r2==16)
			{
				for(i=0;i<16;i++)wrk[0][i]^=p1[i];
				crypt(&enc,16,wrk[0],wrk[0]);
				s=p1;
				p1=p2;
				p2=s;
				r2=0;
			}
		}
	}
	if(r2)
	{
		for(i=0;i<16;i++)wrk[0][i]^=p1[i];
		crypt(&enc,16,wrk[0],wrk[0]);
		s=p1;
		p1=p2;
		p2=s;
		r1=r2;
	}
	if(r1<16)for(i=0;i<16;i++)
	{
		if(i<r1)wrk[1][i]=p1[i];
		else if(i==r1)wrk[1][i]=0x80;
		else wrk[1][i]=0x00;
		wrk[1][i]^=wrk[3][i];
	}
	else for(i=0;i<16;i++)wrk[1][i]=p1[i]^wrk[2][i];
	for(i=0;i<16;i++)wrk[0][i]^=wrk[1][i];
	crypt(&enc,16,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int nttl_camellia_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	((struct nttl_camellia_ecb *)ctx)->
		crypt(&((struct nttl_camellia_ecb *)ctx)->enc,slen,dst,src);
	return 0;
}

static int nttl_camellia_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	((struct nttl_camellia_ecb *)ctx)->
		crypt(&((struct nttl_camellia_ecb *)ctx)->dec,slen,dst,src);
	return 0;
}

static void *nttl_camellia_ecb_init(void *ctx,void *key,int klen)
{
	struct nttl_camellia_ecb *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_ecb)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia128_set_decrypt_key(&camellia->dec.dec128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia192_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia256_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_ecb_exit(void *ctx)
{
	((struct nttl_camellia_ecb *)ctx)->global->memclear(
		&((struct nttl_camellia_ecb *)ctx)->enc,
		sizeof(((struct nttl_camellia_ecb *)ctx)->enc));
	((struct nttl_camellia_ecb *)ctx)->global->memclear(
		&((struct nttl_camellia_ecb *)ctx)->dec,
		sizeof(((struct nttl_camellia_ecb *)ctx)->dec));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int nttl_camellia_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	cbc_encrypt(&((struct nttl_camellia_cbc *)ctx)->enc,
		(void *)(((struct nttl_camellia_cbc *)ctx)->crypt),
		16,((struct nttl_camellia_cbc *)ctx)->iv,slen,dst,src);
	return 0;
}

static int nttl_camellia_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	cbc_decrypt(&((struct nttl_camellia_cbc *)ctx)->dec,
		(void *)(((struct nttl_camellia_cbc *)ctx)->crypt),
		16,((struct nttl_camellia_cbc *)ctx)->iv,slen,dst,src);
	return 0;
}

static void *nttl_camellia_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_camellia_cbc *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_cbc)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia128_set_decrypt_key(&camellia->dec.dec128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia192_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia256_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct nttl_camellia_cbc *)ctx)->iv,iv,16);
}

static void nttl_camellia_cbc_exit(void *ctx)
{
	((struct nttl_camellia_cbc *)ctx)->global->memclear(
		&((struct nttl_camellia_cbc *)ctx)->enc,
		sizeof(((struct nttl_camellia_cbc *)ctx)->enc));
	((struct nttl_camellia_cbc *)ctx)->global->memclear(
		&((struct nttl_camellia_cbc *)ctx)->dec,
		sizeof(((struct nttl_camellia_cbc *)ctx)->dec));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int nttl_camellia_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct nttl_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	cbc_encrypt(&camellia->enc,(void *)(camellia->crypt),16,camellia->iv,
		slen-rem,d,s);
	s+=slen-rem;
	d+=slen-rem;
	memcpy(camellia->tmp,s,rem);
	if(rem<16)memset(camellia->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	cbc_encrypt(&camellia->enc,(void *)(camellia->crypt),16,camellia->iv,
		16,d-16,camellia->tmp);
	return 0;
}

static int nttl_camellia_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct nttl_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(slen-rem-16)
	{
		cbc_decrypt(&camellia->dec,(void *)(camellia->crypt),16,
			camellia->iv,slen-rem-16,d,s);
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(camellia->tmp+16,s,16);
	camellia->crypt(&camellia->dec,16,camellia->tmp,s);
	memcpy(camellia->tmp,s+16,rem);
	cbc_decrypt(&camellia->dec,(void *)(camellia->crypt),16,camellia->iv,
		32,camellia->tmp,camellia->tmp);
	memcpy(d,camellia->tmp,rem+16);
	return 0;
}

static void *nttl_camellia_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_camellia_cts *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_cts)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia128_set_decrypt_key(&camellia->dec.dec128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia192_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia256_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct nttl_camellia_cts *)ctx)->iv,iv,16);
}

static void nttl_camellia_cts_exit(void *ctx)
{
	((struct nttl_camellia_cts *)ctx)->global->memclear(
		&((struct nttl_camellia_cts *)ctx)->enc,
		sizeof(((struct nttl_camellia_cts *)ctx)->enc));
	((struct nttl_camellia_cts *)ctx)->global->memclear(
		&((struct nttl_camellia_cts *)ctx)->dec,
		sizeof(((struct nttl_camellia_cts *)ctx)->dec));
	((struct nttl_camellia_cts *)ctx)->global->memclear(
		((struct nttl_camellia_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int nttl_camellia_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!camellia->n)camellia->crypt(&camellia->enc,16,
			camellia->mem,camellia->iv);
		camellia->iv[camellia->n]=*d++=*s++^camellia->mem[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static int nttl_camellia_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!camellia->n)camellia->crypt(&camellia->enc,16,
			camellia->mem,camellia->iv);
		camellia->iv[camellia->n]=*s;
		*d++=*s++^camellia->mem[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static void *nttl_camellia_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_camellia_xfb *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_xfb)))))goto err1;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_cfb_reset(void *ctx,void *iv)
{
	((struct nttl_camellia_xfb *)ctx)->n=0;
	memcpy(((struct nttl_camellia_xfb *)ctx)->iv,iv,16);
}

static void nttl_camellia_cfb_exit(void *ctx)
{
	((struct nttl_camellia_xfb *)ctx)->global->
		memclear(&((struct nttl_camellia_xfb *)ctx)->enc,
		sizeof(((struct nttl_camellia_xfb *)ctx)->enc));
	((struct nttl_camellia_xfb *)ctx)->global->
		memclear(&((struct nttl_camellia_xfb *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int nttl_camellia_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
        unsigned char *s=src;
        unsigned char *d=dst;
        struct nttl_camellia_cfb8 *camellia=ctx;

        while(slen--)
        {
		camellia->crypt(&camellia->enc,16,camellia->mem,camellia->iv);
                memmove(camellia->iv,camellia->iv+1,15);
                *d++=camellia->iv[15]=*s++^camellia->mem[0];
        }
        return 0;
}

static int nttl_camellia_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
        unsigned char *s=src;
        unsigned char *d=dst;
        struct nttl_camellia_cfb8 *camellia=ctx;

        while(slen--)
        {
		camellia->crypt(&camellia->enc,16,camellia->mem,camellia->iv);
                memmove(camellia->iv,camellia->iv+1,15);
                camellia->iv[15]=*s;
                *d++=*s++^camellia->mem[0];
        }
        return 0;
}

static void *nttl_camellia_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
        struct nttl_camellia_cfb8 *camellia;

        if(U(!(camellia=malloc(sizeof(struct nttl_camellia_cfb8)))))goto err1;
        camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
        ((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
        return camellia;

err2:	free(camellia);
err1:   ((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
        return NULL;
}

static void nttl_camellia_cfb8_reset(void *ctx,void *iv)
{
        memcpy(((struct nttl_camellia_cfb8 *)ctx)->iv,iv,16);
}

static void nttl_camellia_cfb8_exit(void *ctx)
{
        ((struct nttl_camellia_cfb8 *)ctx)->global->
                memclear(&((struct nttl_camellia_cfb8 *)ctx)->enc,
		sizeof(((struct nttl_camellia_cfb8 *)ctx)->enc));
        ((struct nttl_camellia_cfb8 *)ctx)->global->
                memclear(((struct nttl_camellia_cfb8 *)ctx)->iv,16);
        ((struct nttl_camellia_cfb8 *)ctx)->global->
                memclear(((struct nttl_camellia_cfb8 *)ctx)->mem,16);
        free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int nttl_camellia_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct nttl_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!camellia->n)cbc_encrypt(&camellia->enc,
			(void *)camellia->crypt,16,camellia->iv,
			16,camellia->iv,camellia->zero);
		*d++=camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!camellia->n)cbc_encrypt(&camellia->enc,
			(void *)camellia->crypt,16,camellia->iv,
			16,camellia->iv,camellia->zero);
		*d++=*s++^camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static void *nttl_camellia_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_camellia_xfb *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_xfb)))))goto err1;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	memset(camellia->zero,0,sizeof(camellia->zero));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_ofb_reset(void *ctx,void *iv)
{
	((struct nttl_camellia_xfb *)ctx)->n=0;
	memcpy(((struct nttl_camellia_xfb *)ctx)->iv,iv,16);
}

static void nttl_camellia_ofb_exit(void *ctx)
{
	((struct nttl_camellia_xfb *)ctx)->global->
		memclear(&((struct nttl_camellia_xfb *)ctx)->enc,
		sizeof(((struct nttl_camellia_xfb *)ctx)->enc));
	((struct nttl_camellia_xfb *)ctx)->global->
		memclear(&((struct nttl_camellia_xfb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int nttl_camellia_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	int i;
	struct nttl_camellia_ctr *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(camellia->n&&slen)
	{
		if(s)*d++=camellia->mem[camellia->n++]^*s++;
		else *d++=camellia->mem[camellia->n++];
		camellia->n&=0xf;
		if(!--slen)return 0;
	}
	while(slen>=16)
	{
		camellia->crypt(&camellia->enc,16,d,camellia->ctr);
		for(i=15;i>=0;i--)if(++(camellia->ctr[i]))break;
		if(s)for(i=0;i<16;i++)d[i]^=*s++;
		d+=16;
		slen-=16;
	}
	if(slen)
	{
		camellia->crypt(&camellia->enc,16,camellia->mem,camellia->ctr);
		for(i=15;i>=0;i--)if(++(camellia->ctr[i]))break;
		if(s)for(i=0;i<slen;i++)d[i]=camellia->mem[camellia->n++]^*s++;
		else for(i=0;i<slen;i++)d[i]=camellia->mem[camellia->n++];
	}
	return 0;
}

static void *nttl_camellia_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct nttl_camellia_ctr *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_ctr)))))goto err1;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->ctr,iv,16);
	else memset(camellia->ctr,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_ctr_reset(void *ctx,void *iv)
{
	((struct nttl_camellia_ctr *)ctx)->n=0;
	memcpy(((struct nttl_camellia_ctr *)ctx)->ctr,iv,16);
}

static void nttl_camellia_ctr_exit(void *ctx)
{
	((struct nttl_camellia_ctr *)ctx)->global->
		memclear(&((struct nttl_camellia_ctr *)ctx)->enc,
		sizeof(((struct nttl_camellia_ctr *)ctx)->enc));
	((struct nttl_camellia_ctr *)ctx)->global->
		memclear(&((struct nttl_camellia_ctr *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int nttl_camellia_xts_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct nttl_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	camellia->crypt(&camellia->twe,16,camellia->twk,iv);

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		camellia->crypt(&camellia->enc,16,d,camellia->wrk);
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=camellia->twk[i];
			camellia->twk[i]=
				(unsigned char)(n|=(camellia->twk[i]<<1));
		}
		if(n)camellia->twk[0]^=0x87;
	}

	if(slen)
	{
		d-=16;
		memcpy(d+16,d,slen);
		memcpy(camellia->wrk,s,slen);
		memcpy(camellia->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)camellia->wrk[i]^=camellia->twk[i];
		camellia->crypt(&camellia->enc,16,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
	}

	return 0;
}

static int nttl_camellia_xts_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct nttl_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	camellia->crypt(&camellia->twe,16,camellia->twk,iv);

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		camellia->crypt(&camellia->dec,16,d,camellia->wrk);
		for(n=0,i=0;i<16;i++,n>>=8)
		{
			d[i]^=camellia->twk[i];
			camellia->twk[i]=
				(unsigned char)(n|=(camellia->twk[i]<<1));
		}
		if(n)camellia->twk[0]^=0x87;
	}

	if(slen)
	{
		memcpy(camellia->mem,camellia->twk,16);
		for(n=0,i=0;i<16;i++,n>>=8)camellia->twk[i]=
			(unsigned char)(n|=(camellia->twk[i]<<1));
		if(n)camellia->twk[0]^=0x87;
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		camellia->crypt(&camellia->dec,16,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
		memcpy(d+16,d,slen);
		memcpy(camellia->wrk,s+16,slen);
		memcpy(camellia->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)camellia->wrk[i]^=camellia->mem[i];
		camellia->crypt(&camellia->dec,16,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->mem[i];
	}

	return 0;
}

static void *nttl_camellia_xts_init(void *ctx,void *key,int klen)
{
	struct nttl_camellia_xts *camellia;

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_xts)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 256:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia128_set_decrypt_key(&camellia->dec.dec128,key);
		camellia128_set_encrypt_key(&camellia->twe.enc128,
			key+(klen>>4));
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 512:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia256_set_decrypt_key(&camellia->dec.dec256,key);
		camellia256_set_encrypt_key(&camellia->twe.enc256,
			key+(klen>>4));
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_xts_exit(void *ctx)
{
	struct usicrypt_global *global;

	global=((struct nttl_camellia_xts *)ctx)->global;
	global->memclear(ctx,sizeof(struct nttl_camellia_xts));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int nttl_camellia_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct nttl_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	camellia256_crypt(&camellia->aux,16,camellia->iv,iv);
	cbc_encrypt(&camellia->enc,(void *)camellia->crypt,16,camellia->iv,slen,
		dst,src);
	return 0;
}

static int nttl_camellia_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct nttl_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	camellia256_crypt(&camellia->aux,16,camellia->iv,iv);
	cbc_decrypt(&camellia->dec,(void *)camellia->crypt,16,camellia->iv,slen,
		dst,src);
	return 0;
}

static void *nttl_camellia_essiv_init(void *ctx,void *key,int klen)
{
	struct nttl_camellia_essiv *camellia;
	struct sha256_ctx h;
	unsigned char tmp[SHA256_DIGEST_SIZE];

	if(U(!(camellia=malloc(sizeof(struct nttl_camellia_essiv)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	switch(klen)
	{
	case 128:
		camellia128_set_encrypt_key(&camellia->enc.enc128,key);
		camellia128_set_decrypt_key(&camellia->dec.dec128,key);
		camellia->crypt=(void *)camellia128_crypt;
		break;
	case 192:
		camellia192_set_encrypt_key(&camellia->enc.enc256,key);
		camellia192_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	case 256:
		camellia256_set_encrypt_key(&camellia->enc.enc256,key);
		camellia256_set_decrypt_key(&camellia->dec.dec256,key);
		camellia->crypt=(void *)camellia256_crypt;
		break;
	default:goto err2;
	}
	sha256_init(&h);
	sha256_update(&h,klen>>3,key);
	sha256_digest(&h,SHA256_DIGEST_SIZE,tmp);
	camellia256_set_encrypt_key(&camellia->aux,tmp);
	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void nttl_camellia_essiv_exit(void *ctx)
{
	struct usicrypt_global *global;

	global=((struct nttl_camellia_essiv *)ctx)->global;
	global->memclear(ctx,sizeof(struct nttl_camellia_essiv));
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_EC

static void *nttl_ec_mpz_sign(void *ctx,int md,void *key,void *data,int dlen,
	int *slen,int mode)
{
	int bits;
	int len;
	struct usicrypt_iov *iov=data;
	struct nttl_ec *ec=key;
	unsigned char *ptr;
	unsigned char *sig=NULL;
	struct nttl_md c;
	struct dsa_signature dsg;
	unsigned char hash[SHA512_DIGEST_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	if(U(nttl_reseed(ctx)))goto err1;

	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(len=0;len<dlen;len++)
		nttl_md[c.idx].update(&c.ctx,iov[len].length,iov[len].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	((struct usicrypt_thread *)ctx)->global->
		memclear(&c.ctx,sizeof(c.ctx));

	dsa_signature_init(&dsg);
	ecdsa_sign(&ec->key,ctx,nttl_cb_random,nttl_md[c.idx].size,hash,&dsg);

	len=4;
	bits=mpz_sizeinbase(dsg.r,2);
	len+=(bits+7)>>3;
	if(!(bits&7))len++;
	bits=mpz_sizeinbase(dsg.s,2);
	len+=(bits+7)>>3;
	if(!(bits&7))len++;
	if(len<0x80)*slen=len+2;
	else if(len<0x100)*slen=len+3;
	else *slen=len+4;
	if(U(!(ptr=sig=malloc(*slen))))goto err2;
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
	bits=mpz_sizeinbase(dsg.r,2);
	len=(bits+7)>>3;
	*ptr++=(unsigned char)(len+((!(bits&7))?1:0));
	if(!(bits&7))*ptr++=0x00;
	nettle_mpz_get_str_256(len,ptr,dsg.r);
	ptr+=len;
	*ptr++=0x02;
	bits=mpz_sizeinbase(dsg.s,2);
	len=(bits+7)>>3;
	*ptr++=(unsigned char)(len+((!(bits&7))?1:0));
	if(!(bits&7))*ptr++=0x00;
	nettle_mpz_get_str_256(len,ptr,dsg.s);

err2:	dsa_signature_clear(&dsg);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return sig;
}

static int nttl_ec_mpz_verify(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen,int mode)
{
	int res=-1;
	int hh;
	int ll;
	int rl;
	int sl;
	struct usicrypt_iov *iov=data;
	struct nttl_ec *ec=key;
	unsigned char *rptr;
	unsigned char *sptr;
	struct nttl_md c;
	struct dsa_signature dsg;
	unsigned char hash[SHA512_DIGEST_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	if(U(nttl_asn_next(sig,slen,0x30,&hh,&ll)))goto err1;
	sig+=hh;
	slen-=hh;

	if(U(nttl_asn_next(sig,slen,0x02,&hh,&ll)))goto err1;
	rptr=sig+hh;
	rl=ll;
	sig+=hh+ll;
	slen-=hh+ll;

	if(U(nttl_asn_next(sig,slen,0x02,&hh,&ll)))goto err1;
	sptr=sig+hh;
	sl=ll;

	dsa_signature_init(&dsg);
	nettle_mpz_set_str_256_u(dsg.r,rl,rptr);
	nettle_mpz_set_str_256_u(dsg.s,sl,sptr);
	nttl_md[c.idx].init(&c.ctx);
	if(!mode)nttl_md[c.idx].update(&c.ctx,dlen,data);
	else for(ll=0;ll<dlen;ll++)
		nttl_md[c.idx].update(&c.ctx,iov[ll].length,iov[ll].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,hash);
	((struct usicrypt_thread *)ctx)->global->
		memclear(&c.ctx,sizeof(c.ctx));
	if(L(ecdsa_verify(&ec->pub,nttl_md[c.idx].size,hash,&dsg)==1))res=0;
	dsa_signature_clear(&dsg);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));

err1:	return res;
}

#endif

int USICRYPT(random)(void *ctx,void *data,int len)
{
	if(U((((struct usicrypt_thread *)ctx)->total+=1)>=10000))
	{
		if(U(nttl_reseed(ctx)))return -1;
		((struct usicrypt_thread *)ctx)->total=0;
	}
	yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,len,data);
	return 0;
}

int USICRYPT(digest_size)(void *ctx,int md)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return SHA1_DIGEST_SIZE;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return SHA256_DIGEST_SIZE;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return SHA384_DIGEST_SIZE;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return SHA512_DIGEST_SIZE;
#endif
#endif
	default:return -1;
	}
}

int USICRYPT(digest)(void *ctx,int md,void *in,int len,void *out)
{
#ifndef USICRYPT_NO_DIGEST
	struct nttl_md c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:return -1;
	}

	nttl_md[c.idx].init(&c.ctx);
	nttl_md[c.idx].update(&c.ctx,len,in);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,out);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	return 0;
#else
	return -1;
#endif
}

int USICRYPT(digest_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *out)
{
#if !defined(USICRYPT_NO_DIGEST) && !defined(USICRYPT_NO_IOV)
	int i;
	struct nttl_md c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:return -1;
	}

	nttl_md[c.idx].init(&c.ctx);
	for(i=0;i<niov;i++)nttl_md[c.idx].update(&c.ctx,iov[i].length,
		iov[i].data);
	nttl_md[c.idx].digest(&c.ctx,nttl_md[c.idx].size,out);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	return 0;
#else
	return -1;
#endif
}

int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,int klen,
	void *out)
{
#ifndef USICRYPT_NO_HMAC
	struct nttl_hm hm;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		hm.idx=md;
		break;
#endif
	default:return -1;
	}

	nttl_hm[hm.idx].init(&hm.ctx,klen,key);
	nttl_hm[hm.idx].update(&hm.ctx,dlen,data);
	nttl_hm[hm.idx].digest(&hm.ctx,nttl_hm[hm.idx].size,out);
	((struct usicrypt_thread *)ctx)->global->memclear(&hm,sizeof(hm));
	return 0;
#else
	return -1;
#endif
}

int USICRYPT(hmac_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *key,int klen,void *out)
{
#if !defined(USICRYPT_NO_HMAC) && !defined(USICRYPT_NO_IOV)
	int i;
	struct nttl_hm hm;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		hm.idx=md;
		break;
#endif
	default:return -1;
	}

	nttl_hm[hm.idx].init(&hm.ctx,klen,key);
	for(i=0;i<niov;i++)nttl_hm[hm.idx].update(&hm.ctx,iov[i].length,
		iov[i].data);
	nttl_hm[hm.idx].digest(&hm.ctx,nttl_hm[hm.idx].size,out);
	((struct usicrypt_thread *)ctx)->global->memclear(&hm,sizeof(hm));
	return 0;
#else
	return -1;
#endif
}

int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	int iter,void *out)
{
	int r=0;
#ifndef USICRYPT_NO_PBKDF2
#if !defined(USICRYPT_NO_SHA384) || !defined(USICRYPT_NO_SHA512)
	union
	{
		struct hmac_sha384_ctx hm384;
		struct hmac_sha512_ctx hm512;
	}u;
#endif
#endif

	switch(md)
	{
#ifndef USICRYPT_NO_PBKDF2
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		pbkdf2_hmac_sha1(klen,key,iter,slen,salt,SHA1_DIGEST_SIZE,out);
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		pbkdf2_hmac_sha256(klen,key,iter,slen,salt,SHA256_DIGEST_SIZE,
			out);
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		hmac_sha384_set_key(&u.hm384,klen,key);
		pbkdf2(&u.hm384,(void*)hmac_sha384_update,
			(void *)hmac_sha384_digest,SHA384_DIGEST_SIZE,
			iter,slen,salt,SHA384_DIGEST_SIZE,out);
		((struct usicrypt_thread *)ctx)->global->
			memclear(&u.hm384,sizeof(u.hm384));
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		hmac_sha512_set_key(&u.hm512,klen,key);
		pbkdf2(&u.hm512,(void*)hmac_sha512_update,
			(void *)hmac_sha512_digest,SHA512_DIGEST_SIZE,
			iter,slen,salt,SHA512_DIGEST_SIZE,out);
		((struct usicrypt_thread *)ctx)->global->
			memclear(&u.hm512,sizeof(u.hm512));
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
	struct nttl_hm hm;
	unsigned char s[SHA512_DIGEST_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_HKDF
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		hm.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		hm.idx=md;
		break;
#endif
#endif
	default:return -1;
	}

	if(!salt||!slen)
	{
		slen=nttl_hm[hm.idx].size;
		salt=s;
		memset(s,0,nttl_hm[hm.idx].size);
	}
	nttl_hm[hm.idx].init(&hm.ctx,slen,salt);
	nttl_hm[hm.idx].update(&hm.ctx,klen,key);
	nttl_hm[hm.idx].digest(&hm.ctx,nttl_hm[hm.idx].size,out);
	nttl_hm[hm.idx].init(&hm.ctx,nttl_hm[hm.idx].size,out);
	nttl_hm[hm.idx].update(&hm.ctx,ilen,info);
	s[0]=1;
	nttl_hm[hm.idx].update(&hm.ctx,1,s);
	nttl_hm[hm.idx].digest(&hm.ctx,nttl_hm[hm.idx].size,out);
	((struct usicrypt_thread *)ctx)->global->
		memclear(&hm.ctx,sizeof(hm.ctx));
	return 0;
}

void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen)
{
	char *out=NULL;

#ifndef USICRYPT_NO_BASE64
	*olen=BASE64_ENCODE_RAW_LENGTH(ilen);

	if(U(!(out=malloc(*olen+1))))return NULL;
	base64_encode_raw(out,ilen,in);
	out[*olen]=0;
#endif
	return out;
}

void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	size_t len;
	unsigned char *out;
	struct base64_decode_ctx b64;

	len=*olen=BASE64_DECODE_LENGTH(ilen);
	if(U(!(out=malloc(len))))goto err1;
	base64_decode_init(&b64);
	if(U(!base64_decode_update(&b64,&len,out,ilen,in)))goto err2;
	out=USICRYPT(do_realloc)(ctx,out,*olen,len);
	((struct usicrypt_thread *)ctx)->global->memclear(&b64,sizeof(b64));
	*olen=len;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(&b64,sizeof(b64));
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_generate)(void *ctx,int bits)
{
#ifndef USICRYPT_NO_RSA
	struct nttl_rsa *rsa;

	if(U(bits<USICRYPT_RSA_BITS_MIN)||U(bits>USICRYPT_RSA_BITS_MAX)||
		U(bits&7))goto err1;
	if(U(!(rsa=malloc(sizeof(struct nttl_rsa)))))goto err1;
	rsa_public_key_init(&rsa->pub);
	rsa_private_key_init(&rsa->key);
	mpz_set_ui(rsa->pub.e,USICRYPT_RSA_EXPONENT);
	if(U(rsa_generate_keypair(&rsa->pub,&rsa->key,ctx,nttl_cb_random,
		NULL,NULL,bits,0)!=1))goto err2;
	return rsa;

err2:	rsa_public_key_clear(&rsa->pub);
	rsa_private_key_clear(&rsa->key);
	free(rsa);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(rsa_size)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	return (((struct rsa_public_key *)key)->size)<<3;
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
	unsigned char *ptr;
	unsigned char *data;
	struct nttl_rsa *rsa=key;

	l1=nttl_rsa_mpz_int_size(rsa->pub.n);
	l2=nttl_rsa_mpz_int_size(rsa->pub.e);
	sum0=l1+l2;
	sum1=nttl_rsa_mpz_hdr_add(sum0)+1;
	sum2=nttl_rsa_mpz_hdr_add(sum1);
	*len=nttl_rsa_mpz_hdr_add(sum2+sizeof(nttl_rsa_pub_oid)+6);
	if(U(!(ptr=data=malloc(*len))))goto err1;
	ptr+=nttl_rsa_mpz_write_hdr(0x30,ptr,sum2+sizeof(nttl_rsa_pub_oid)+6);
	ptr+=nttl_rsa_mpz_write_hdr(0x30,ptr,sizeof(nttl_rsa_pub_oid)+4);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(nttl_rsa_pub_oid);
	memcpy(ptr,nttl_rsa_pub_oid,sizeof(nttl_rsa_pub_oid));
	ptr+=sizeof(nttl_rsa_pub_oid);
	*ptr++=0x05;
	*ptr++=0x00;
	ptr+=nttl_rsa_mpz_write_hdr(0x03,ptr,sum1);
	*ptr++=0x00;
	ptr+=nttl_rsa_mpz_write_hdr(0x30,ptr,sum0);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->pub.n);
	nttl_rsa_mpz_write_int(ptr,rsa->pub.e);
	return data;

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
	struct nttl_rsa *rsa;
	unsigned char *pub=key;

	if(U(!(rsa=malloc(sizeof(struct nttl_rsa)))))goto err1;
	rsa_public_key_init(&rsa->pub);
	rsa_private_key_init(&rsa->key);

	if(U(nttl_asn_next(pub,len,0x30,&h,&l)))goto err2;
	pub+=h;
	len-=h;

	if(U(nttl_asn_next(pub,len,0x30,&h,&l)))goto err2;
	pub+=h;
	len-=h;

	if(U(nttl_asn_next(pub,len,0x06,&h,&l)))goto err2;
	if(U(l!=sizeof(nttl_rsa_pub_oid))||U(memcmp(pub+h,nttl_rsa_pub_oid,l)))
		goto err2;
	pub+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(pub,len,0x05,&h,&l)))goto err2;
	if(l)goto err2;
	pub+=h;
	len-=h;

	if(U(nttl_asn_next(pub,len,0x03,&h,&l)))goto err2;
	if(l<1||pub[h])goto err2;
	pub+=h+1;
	len-=h+1;

	if(U(nttl_asn_next(pub,len,0x30,&h,&l)))goto err2;
	pub+=h;
	len-=h;

	if(U(nttl_asn_next(pub,len,0x02,&h,&l)))goto err2;
	nettle_mpz_set_str_256_u(rsa->pub.n,l,pub+h);
	pub+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(pub,len,0x02,&h,&l)))goto err2;
	nettle_mpz_set_str_256_u(rsa->pub.e,l,pub+h);

	if(U(rsa_public_key_prepare(&rsa->pub)!=1))goto err2;

	if(U(rsa->pub.size<USICRYPT_RSA_BYTES_MIN)||
		U(rsa->pub.size>USICRYPT_RSA_BYTES_MAX))goto err2;
	if(U(!mpz_cmp_ui(rsa->pub.n,0))||U(!mpz_cmp_ui(rsa->pub.e,0)))goto err2;
	if(U(!mpz_tstbit(rsa->pub.n,0))||U(!mpz_tstbit(rsa->pub.e,0)))goto err2;
	if(U(mpz_cmp(rsa->pub.e,rsa->pub.n)>=0))goto err2;

	return rsa;

err2:	rsa_public_key_clear(&rsa->pub);
	rsa_private_key_clear(&rsa->key);
	free(rsa);
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
	unsigned char *ptr;
	unsigned char *data;
	struct nttl_rsa *rsa=key;

	ln=nttl_rsa_mpz_int_size(rsa->pub.n);
	le=nttl_rsa_mpz_int_size(rsa->pub.e);
	ld=nttl_rsa_mpz_int_size(rsa->key.d);
	lp=nttl_rsa_mpz_int_size(rsa->key.p);
	lq=nttl_rsa_mpz_int_size(rsa->key.q);
	le1=nttl_rsa_mpz_int_size(rsa->key.a);
	le2=nttl_rsa_mpz_int_size(rsa->key.b);
	lc=nttl_rsa_mpz_int_size(rsa->key.c);
	sum=ln+le+ld+lp+lq+le1+le2+lc+3;
	*len=nttl_rsa_mpz_hdr_add(sum);
	if(U(!(ptr=data=malloc(*len))))goto err1;
	ptr+=nttl_rsa_mpz_write_hdr(0x30,ptr,sum);
	*ptr++=0x02;
	*ptr++=0x01;
	*ptr++=0x00;
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->pub.n);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->pub.e);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->key.d);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->key.p);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->key.q);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->key.a);
	ptr+=nttl_rsa_mpz_write_int(ptr,rsa->key.b);
	nttl_rsa_mpz_write_int(ptr,rsa->key.c);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	struct nttl_rsa *rsa;

	if(U(!(rsa=malloc(sizeof(struct nttl_rsa)))))goto err1;
	rsa_public_key_init(&rsa->pub);
	rsa_private_key_init(&rsa->key);
	if(U(!rsa_keypair_from_der(&rsa->pub,&rsa->key,USICRYPT_RSA_BITS_MAX,
		len,key)))goto err2;
	if(U(rsa->pub.size<USICRYPT_RSA_BYTES_MIN)||
		U(rsa->pub.size>USICRYPT_RSA_BYTES_MAX))goto err2;
	if(U(!mpz_cmp_ui(rsa->pub.n,0))||U(!mpz_cmp_ui(rsa->pub.e,0)))goto err2;
	if(U(!mpz_tstbit(rsa->pub.n,0))||U(!mpz_tstbit(rsa->pub.e,0)))goto err2;
	if(U(mpz_cmp(rsa->pub.e,rsa->pub.n)>=0))goto err2;
	if(U(nttl_rsa_mpz_check(rsa)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return rsa;

err2:	rsa_public_key_clear(&rsa->pub);
	rsa_private_key_clear(&rsa->key);
	free(rsa);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(rsa_sign_v15)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return nttl_rsa_do_sign_v15(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return nttl_rsa_do_sign_v15(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return nttl_rsa_do_verify_v15(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return nttl_rsa_do_verify_v15(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return nttl_rsa_do_sign_pss(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return nttl_rsa_do_sign_pss(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return nttl_rsa_do_verify_pss(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return nttl_rsa_do_verify_pss(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int n;
	struct nttl_rsa *rsa=key;
	unsigned char *out=NULL;
	mpz_t s;

	if(U(nttl_reseed(ctx)))goto err1;
	mpz_init(s);
	if(U(rsa_encrypt(&rsa->pub,ctx,nttl_cb_random,dlen,data,s)!=1))
		goto err2;
	*olen=nettle_mpz_sizeinbase_256_u(rsa->pub.n);
	n=nettle_mpz_sizeinbase_256_u(s);
	if(U(!(out=malloc(*olen))))goto err2;
	if(n<*olen)memset(out,0,*olen-n);
	nettle_mpz_get_str_256(n,out+*olen-n,s);
err2:	mpz_clear(s);
err1:	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	size_t len;
	struct nttl_rsa *rsa=key;
	unsigned char *out=NULL;
	mpz_t s;

	if(U(nttl_reseed(ctx)))goto err1;
	len=*olen=((struct rsa_public_key *)key)->size;
	nettle_mpz_init_set_str_256_u(s,dlen,data);
	if(U(!(out=malloc(len))))goto err2;
	if(U(rsa_decrypt_tr(&rsa->pub,&rsa->key,ctx,nttl_cb_random,&len,out,s)
		!=1))goto err3;
	out=USICRYPT(do_realloc)(ctx,out,*olen,len);
	*olen=len;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	mpz_clear(s);
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
	struct nttl_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;
	struct nttl_md c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	if(U(nttl_reseed(ctx)))goto err1;
	*olen=(mpz_sizeinbase(rsa->pub.n,2)+7)>>3;
	if(U(dlen>*olen-2*nttl_md[c.idx].size-2))goto err1;
	if(U(!(tmp=malloc(*olen))))goto err1;
	if(U(!(out=malloc(*olen))))goto err2;
	if(U(nttl_add_oaep_mgf1(ctx,tmp,*olen,data,dlen,NULL,0,&c)))goto err3;
	if(L(!nttl_rsa_mpz_public(tmp,*olen,out,&l,rsa))&&L(l==*olen))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
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
	struct nttl_rsa *rsa=key;
	unsigned char *tmp;
	unsigned char *out=NULL;
	struct nttl_md c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		c.idx=md;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		c.idx=md;
		break;
#endif
	default:goto err1;
	}

	*olen=(mpz_sizeinbase(rsa->pub.n,2)+7)>>3;
	if(U(dlen!=*olen))goto err1;
	if(U(!(tmp=malloc(*olen))))goto err1;
	if(U(!(out=malloc(*olen))))goto err2;
	if(U(nttl_rsa_mpz_private(ctx,data,*olen,tmp,&l,rsa))||U(l!=*olen))
		goto err3;
	if(U(tmp[0]))goto err3;
	if(U((l=nttl_check_oaep_mgf1(ctx,out,*olen,tmp+1,*olen-1,*olen,NULL,0,
		&c))==-1))goto err3;
	out=USICRYPT(do_realloc)(ctx,out,*olen,l);
	*olen=l;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	out=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	free(tmp);
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	return out;
#else
	return NULL;
#endif
}

void USICRYPT(rsa_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	struct nttl_rsa *rsa=key;

	rsa_public_key_clear(&rsa->pub);
	rsa_private_key_clear(&rsa->key);
	free(rsa);
#endif
}

void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len)
{
#ifndef USICRYPT_NO_DH
	int l;
	int n;
	mpz_t p;
	mpz_t x;
	unsigned char *bfr;
	unsigned char *data;
	unsigned char *ptr;

	if(U(bits<USICRYPT_DH_BITS_MIN)||U(bits>USICRYPT_DH_BITS_MAX)||
		U(bits&7)||U(generator!=2&&generator!=5))goto err1;
	if(U(nttl_reseed(ctx)))goto err1;
	mpz_init(p);
	mpz_init(x);
	while(1)
	{
		if(U(nttl_dh_mpz_gen_prime(ctx,&p,bits)))goto err2;
		switch(generator)
		{
		case 2:	mpz_tdiv_r_ui(x,p,24);
			if(mpz_cmp_ui(x,11))continue;
			break;

		case 3:	mpz_tdiv_r_ui(x,p,12);
			if(mpz_cmp_ui(x,5))continue;
			break;

		case 5:	mpz_tdiv_r_ui(x,p,10);
			if(mpz_cmp_ui(x,3)&&mpz_cmp_ui(x,7))continue;
			break;
		}
		break;
	}
	l=nettle_mpz_sizeinbase_256_u(p);
	if(U(!(bfr=malloc(l))))goto err2;
	nettle_mpz_get_str_256(l,bfr,p);

	n=l+((*bfr&0x80)?1:0);
	if(n>=0x100)n+=7;
	else if(n>=0x80)n+=6;
	else n+=5;
	if(n>=0x100)n+=4;
	else if(n>=0x80)n+=3;
	else n+=2;
	*len=n;
	if(U(!(ptr=data=malloc(n))))goto err3;

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
	mpz_clear(p);
	mpz_clear(x);

	return data;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,l);
	free(bfr);
err2:	mpz_clear(p);
	mpz_clear(x);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_init)(void *ctx,void *params,int len)
{
#ifndef USICRYPT_NO_DH
	int h;
	int l;
	int plen;
	int glen;
	struct nttl_dh *dh;
	unsigned char *prms=params;
	unsigned char *p;
	unsigned char *g;
	mpz_t tmp;

	if(U(!(dh=malloc(sizeof(struct nttl_dh)))))goto err1;

	if(U(nttl_asn_next(prms,len,0x30,&h,&l)))goto err2;
	prms+=h;
	len-=h;

	if(U(nttl_asn_next(prms,len,0x02,&h,&l)))goto err2;
	p=prms+h;
	plen=l;
	prms+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(prms,len,0x02,&h,&l)))goto err2;
	g=prms+h;
	glen=l;

	if(U(!plen)||U(!glen)||U(*p&0x80)||U(*g&0x80))goto err2;

	nettle_mpz_init_set_str_256_u(dh->p,plen,p);
	nettle_mpz_init_set_str_256_u(dh->g,glen,g);
	mpz_init_set_ui(dh->key,0);

	mpz_init(tmp);
	h=mpz_sizeinbase(dh->p,2);
	if(U(h<USICRYPT_DH_BITS_MIN)||U(h>USICRYPT_DH_BITS_MAX))goto err3;
	if(U(mpz_cmp_ui(dh->p,3)<0)||U(mpz_cmp_ui(dh->g,1)<=0)||
		U(!mpz_probab_prime_p(dh->p,32)))goto err3;
	if(!mpz_cmp_ui(dh->g,2))
	{
		mpz_set_ui(tmp,24);
		mpz_mod(tmp,dh->p,tmp);
		if(U(mpz_cmp_ui(tmp,11)))goto err3;
	}
	else if(!mpz_cmp_ui(dh->g,3))
	{
		mpz_set_ui(tmp,12);
		mpz_mod(tmp,dh->p,tmp);
		if(U(mpz_cmp_ui(tmp,5)))goto err3;
	}
	else if(!mpz_cmp_ui(dh->g,5))
	{
		mpz_set_ui(tmp,10);
		mpz_mod(tmp,dh->p,tmp);
		if(U(mpz_cmp_ui(tmp,3)&&mpz_cmp_ui(tmp,7)))goto err3;
	}
	mpz_clear(tmp);

	return dh;

err3:	mpz_clear(tmp);
	mpz_clear(dh->p);
	mpz_clear(dh->g);
	mpz_clear(dh->key);
err2:	free(dh);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len)
{
#ifndef USICRYPT_NO_DH
        int bits;
	int bytes;
	struct nttl_dh *d=dh;
	unsigned char *tmp;
	unsigned char *data=NULL;
	mpz_t pub;

	if(U(nttl_reseed(ctx)))goto err1;
        if(U((bits=mpz_sizeinbase(d->p,2)-1)<=0))goto err1;
	bytes=(bits+7)>>3;
	if(U(!(tmp=malloc(bytes))))goto err1;
	yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,bytes,tmp);
	switch(bits&7)
	{
	case 0:	tmp[0]|=0x80;
		break;
	case 1:	tmp[0]|=0x01;
		tmp[0]&=0x01;
		break;
	case 2:	tmp[0]|=0x02;
		tmp[0]&=0x03;
		break;
	case 3:	tmp[0]|=0x04;
		tmp[0]&=0x07;
		break;
	case 4:	tmp[0]|=0x08;
		tmp[0]&=0x0f;
		break;
	case 5:	tmp[0]|=0x10;
		tmp[0]&=0x1f;
		break;
	case 6:	tmp[0]|=0x20;
		tmp[0]&=0x3f;
		break;
	case 7:	tmp[0]|=0x40;
		tmp[0]&=0x7f;
		break;
	}
	nettle_mpz_init_set_str_256_u(d->key,bytes,tmp);
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,bytes);
	mpz_init(pub);
	mpz_powm(pub,d->g,d->key,d->p);
	if((bits=mpz_sizeinbase(pub,2))>0)
	{
		bytes=(bits+7)>>3;
		if((data=malloc(bytes)))
		{
			nettle_mpz_get_str_256(bytes,data,pub);
			*len=bytes;
		}
	}
	mpz_clear(pub);
err1:   return data;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,int *slen)
{
#ifndef USICRYPT_NO_DH
	int bits;
	int bytes;
	struct nttl_dh *d=dh;
	unsigned char *data=NULL;
	mpz_t p;
	mpz_t s;

	if(U(plen<0))goto err1;
	else if(!plen)mpz_init(p);
	else nettle_mpz_init_set_str_256_u(p,plen,pub);
	if(U(mpz_sizeinbase(d->p,2)<=1))goto err2;
	mpz_init(s);
	if(U(mpz_cmp_ui(p,2)<0))goto err3;
	mpz_sub_ui(s,d->p,2);
	if(U(mpz_cmp(p,s)>0))goto err3;
	mpz_powm(s,p,d->key,d->p);
	if((bits=mpz_sizeinbase(s,2))>0)
	{
		bytes=(bits+7)>>3;
		if((data=malloc(bytes)))
		{
			nettle_mpz_get_str_256(bytes,data,s);
			*slen=bytes;
		}
	}
err3:	mpz_clear(s);
err2:	mpz_clear(p);
err1:	return data;
#else
	return NULL;
#endif
}

void USICRYPT(dh_free)(void *ctx,void *dh)
{
#ifndef USICRYPT_NO_DH
	struct nttl_dh *d=dh;

	mpz_clear(d->p);
	mpz_clear(d->g);
	mpz_clear(d->key);
	free(d);
#endif
}

void *USICRYPT(ec_generate)(void *ctx,int curve)
{
#ifndef USICRYPT_NO_EC
	struct nttl_ec *ec;

	if(U(nttl_reseed(ctx)))goto err1;
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
	if(U(!nttl_ec_map[curve].curve))goto err1;
	if(U(!(ec=malloc(sizeof(struct nttl_ec)))))goto err1;
	ec->curve=curve;
	ecc_scalar_init(&ec->key,nttl_ec_map[curve].curve);
	ecc_point_init(&ec->pub,nttl_ec_map[curve].curve);
	ecdsa_generate_keypair(&ec->pub,&ec->key,ctx,nttl_cb_random);
	return ec;

err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ec_identifier)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	struct nttl_ec *ec=key;

	return ec->curve;
#else
	return -1;
#endif
}

void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_EC
	int l;
	int n;
	struct nttl_ec *k=key;
	struct nttl_ec *p=pub;
	unsigned char *sec=NULL;
	struct ecc_point r;
	mpz_t x;

	if(U(k->curve!=p->curve))return NULL;
	mpz_init(x);
	ecc_point_init(&r,nttl_ec_map[k->curve].curve);
	ecc_point_mul(&r,&k->key,&p->pub);
	ecc_point_get(&r,x,NULL);
	l=nettle_mpz_sizeinbase_256_u(x);
	n=(ecc_bit_size(nttl_ec_map[k->curve].curve)+7)>>3;
	if(U(!(sec=malloc(n))))goto err1;
	*klen=n;
	if(l<n)memset(sec,0,n-l);
	nettle_mpz_get_str_256(l,sec+n-l,x);
err1:	mpz_clear(x);
	ecc_point_clear(&r);
	return sec;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	int l;
	int n;
	int xl;
	int yl;
	struct nttl_ec *ec=k;
	unsigned char *data=NULL;
	mpz_t x;
	mpz_t y;

	mpz_init(x);
	mpz_init(y);
	ecc_point_get(&ec->pub,x,y);
	n=nttl_ec_map[ec->curve].xylen>>1;
	xl=nettle_mpz_sizeinbase_256_u(x);
	yl=nettle_mpz_sizeinbase_256_u(y);
	if(U(xl>n)||U(yl>n))goto err1;
	*len=nttl_ec_map[ec->curve].publen;
	l=nttl_ec_map[ec->curve].phdrlen;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,nttl_ec_map[ec->curve].phdr,l);
	data[l]=0x04;
	memset(data+l+1,0,nttl_ec_map[ec->curve].xylen-1);
	nettle_mpz_get_str_256(xl,data+l+1+n-xl,x);
	nettle_mpz_get_str_256(yl,data+l+nttl_ec_map[ec->curve].xylen-yl,y);
err1:	mpz_clear(x);
	mpz_clear(y);
	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	struct nttl_ec *ec;
	unsigned char *pptr;
	int idx;
	int h;
	int l;
	int plen;
	mpz_t x;
	mpz_t y;

	if(U(!(ec=malloc(sizeof(struct nttl_ec)))))goto err1;

	if(U(nttl_asn_next(key,len,0x30,&h,&l)))goto err2;
	key+=h;
	len-=h;

	if(U(nttl_asn_next(key,len,0x30,&h,&l)))goto err2;
	pptr=key+h+l;
	plen=len-h-l;
	key+=h;
	len=l;

	if(U(nttl_asn_next(key,len,0x06,&h,&l)))goto err2;
	if(U(l!=7)||U(memcmp(key+h,nttl_ansi_pubkey_type,7)))goto err2;
	key+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(key,len,0x06,&h,&l)))goto err2;
	for(idx=0;idx<USICRYPT_TOT_EC_CURVES;idx++)
		if(nttl_ec_map[idx].oidlen==l&&
			!memcmp(key+h,nttl_ec_map[idx].oid,l))break;
	if(U(idx==USICRYPT_TOT_EC_CURVES)||U(!nttl_ec_map[idx].curve))goto err2;

	ec->curve=idx;

	if(U(nttl_asn_next(pptr,plen,0x03,&h,&l)))goto err2;
	if(U(l-1!=nttl_ec_map[idx].xylen)||U(pptr[h])||U(pptr[h+1]!=0x04))
		goto err2;

	ecc_scalar_init(&ec->key,nttl_ec_map[idx].curve);
	ecc_point_init(&ec->pub,nttl_ec_map[idx].curve);
	nettle_mpz_init_set_str_256_u(x,nttl_ec_map[idx].xylen>>1,pptr+h+2);
	nettle_mpz_init_set_str_256_u(y,nttl_ec_map[idx].xylen>>1,
		pptr+h+2+(nttl_ec_map[idx].xylen>>1));
	if(U(!ecc_point_set(&ec->pub,x,y)))goto err3;
	mpz_clear(x);
	mpz_clear(y);
	return ec;

err3:	ecc_scalar_clear(&ec->key);
	ecc_point_clear(&ec->pub);
	mpz_clear(x);
	mpz_clear(y);
err2:	free(ec);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	struct nttl_ec *ec=k;
	int dlen;
	int klen;
	int xlen;
	int ylen;
	int n;
	unsigned char *ptr;
	unsigned char *data=NULL;
	mpz_t x;
	mpz_t y;
	mpz_t kk;

	mpz_init(x);
	mpz_init(y);
	mpz_init(kk);
	ecc_point_get(&ec->pub,x,y);
	ecc_scalar_get(&ec->key,kk);
	klen=nettle_mpz_sizeinbase_256_u(kk);
	xlen=nettle_mpz_sizeinbase_256_u(x);
	ylen=nettle_mpz_sizeinbase_256_u(y);
	n=nttl_ec_map[ec->curve].xylen>>1;
	if(U(klen>nttl_ec_map[ec->curve].kmax)||U(xlen>n)||U(ylen>n))goto err1;
	dlen=nttl_ec_map[ec->curve].xylen+nttl_ec_map[ec->curve].k1h2len+klen+1+
		sizeof(nttl_ec_k1h1);
	*len=dlen+2;
	if(dlen>=0x80)*len+=1;
	if(dlen>=0x100)*len+=1;
	if(U(!(ptr=data=malloc(*len))))goto err1;
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
	memcpy(ptr,nttl_ec_k1h1,sizeof(nttl_ec_k1h1));
	ptr+=sizeof(nttl_ec_k1h1);
	*ptr++=(unsigned char)klen;
	nettle_mpz_get_str_256(klen,ptr,kk);
	ptr+=klen;
	memcpy(ptr,nttl_ec_map[ec->curve].k1h2,nttl_ec_map[ec->curve].k1h2len);
	ptr+=nttl_ec_map[ec->curve].k1h2len;
	*ptr++=0x04;
	memset(ptr,0,nttl_ec_map[ec->curve].xylen-1);
	nettle_mpz_get_str_256(xlen,ptr+n-xlen,x);
	nettle_mpz_get_str_256(ylen,ptr+nttl_ec_map[ec->curve].xylen-1-ylen,y);
err1:	mpz_clear(x);
	mpz_clear(y);
	mpz_clear(kk);
	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	int h;
	int l;
	int idx;
	int klen;
	int xylen;
	int synth=0;
	struct nttl_ec *ec;
	unsigned char *kptr;
	unsigned char *xptr;
	unsigned char *yptr;
	unsigned char *k=key;
	mpz_t x;
	mpz_t y;
	mpz_t kk;
	mpz_t x1;
	mpz_t y1;
	struct ecc_point tmp;

	if(U(!(ec=malloc(sizeof(struct nttl_ec)))))goto err1;

	if(U(nttl_asn_next(k,len,0x30,&h,&l)))goto err2;
	k+=h;
	len-=h;

	if(U(nttl_asn_next(k,len,0x02,&h,&l)))goto err2;
	if(U(l!=1)||U(k[h]!=0x01))goto err2;
	k+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(k,len,0x04,&h,&l)))goto err2;
	kptr=k+h;
	klen=l;
	k+=h+l;
	len-=h+l;

	if(U(nttl_asn_next(k,len,0xa0,&h,&l)))goto err2;
	k+=h;
	len-=h;

	if(U(nttl_asn_next(k,len,0x06,&h,&l)))goto err2;
	for(idx=0;idx<USICRYPT_TOT_EC_CURVES;idx++)
		if(nttl_ec_map[idx].oidlen==l&&
			!memcmp(k+h,nttl_ec_map[idx].oid,l))break;
	if(U(idx==USICRYPT_TOT_EC_CURVES)||U(!nttl_ec_map[idx].curve))goto err2;
	ec->curve=idx;
	k+=h+l;
	len-=h+l;

	if(!nttl_asn_next(k,len,0xa1,&h,&l))
	{
		k+=h;
		len-=h;

		if(U(nttl_asn_next(k,len,0x03,&h,&l)))goto err2;
		if(U(l-1!=nttl_ec_map[idx].xylen)||U(k[h])||U(k[h+1]!=0x04))
			goto err2;
		xylen=(l-1)>>1;
		xptr=k+h+2;
		yptr=xptr+xylen;
	}
	else synth=1;

	ecc_scalar_init(&ec->key,nttl_ec_map[idx].curve);
	ecc_point_init(&ec->pub,nttl_ec_map[idx].curve);
	nettle_mpz_init_set_str_256_u(kk,klen,kptr);
	if(!synth)
	{
		nettle_mpz_init_set_str_256_u(x,xylen,xptr);
		nettle_mpz_init_set_str_256_u(y,xylen,yptr);
	}
	if(U(!(ecc_scalar_set(&ec->key,kk))))goto err3;
	if(synth)ecc_point_mul_g(&ec->pub,&ec->key);
	else if(U(!ecc_point_set(&ec->pub,x,y)))goto err3;
	else
	{
		mpz_init(x1);
		mpz_init(y1);
		ecc_point_init(&tmp,nttl_ec_map[idx].curve);
		ecc_point_mul_g(&tmp,&ec->key);
		ecc_point_get(&tmp,x1,y1);
		h=mpz_cmp(x,x1);
		l=mpz_cmp(y,y1);
		ecc_point_clear(&tmp);
		mpz_clear(x1);
		mpz_clear(y1);
		if(U(h)||U(l))goto err3;
	}
	if(!synth)
	{
		mpz_clear(x);
		mpz_clear(y);
	}
	mpz_clear(kk);
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return ec;

err3:	ecc_scalar_clear(&ec->key);
	ecc_point_clear(&ec->pub);
	if(!synth)
	{
		mpz_clear(x);
		mpz_clear(y);
	}
	mpz_clear(kk);
err2:	free(ec);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_EC
	return nttl_ec_mpz_sign(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return nttl_ec_mpz_sign(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_EC
	return nttl_ec_mpz_verify(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return nttl_ec_mpz_verify(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void USICRYPT(ec_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	struct nttl_ec *ec=key;

	ecc_scalar_clear(&ec->key);
	ecc_point_clear(&ec->pub);
	free(ec);
#endif
}

void *USICRYPT(x25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_X25519
	struct nttl_x25519 *x;

	if(U(nttl_reseed(ctx)))return NULL;
	if(U(!(x=malloc(sizeof(struct nttl_x25519)))))return NULL;
	yarrow256_random(&((struct usicrypt_thread *)ctx)->rng,
		CURVE25519_SIZE,x->key);
	x->key[0]&=0xf8;
	x->key[CURVE25519_SIZE-1]&=0x7f;
	x->key[CURVE25519_SIZE-1]|=0x40;
	curve25519_mul_g(x->pub,x->key);
	return x;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_X25519
	struct nttl_x25519 *k=key;
	struct nttl_x25519 *p=pub;
	unsigned char *out;

	*klen=CURVE25519_SIZE;
	if(U(!(out=malloc(*klen))))return NULL;
	curve25519_mul(out,k->key,p->pub);
	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	unsigned char *data;

	*len=sizeof(nttl_x25519_asn1_pub)+CURVE25519_SIZE;
	if(U(!(data=malloc(*len))))return NULL;
	memcpy(data,nttl_x25519_asn1_pub,sizeof(nttl_x25519_asn1_pub));
	memcpy(data+sizeof(nttl_x25519_asn1_pub),
		((struct nttl_x25519 *)key)->pub,CURVE25519_SIZE);
	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	struct nttl_x25519 *x;

	if(U(len<sizeof(nttl_x25519_asn1_pub)+CURVE25519_SIZE)||
	    U(memcmp(key,nttl_x25519_asn1_pub,sizeof(nttl_x25519_asn1_pub))))
		goto err1;
	if(U(!(x=malloc(sizeof(struct nttl_x25519)))))goto err1;
	memcpy(x->pub,((unsigned char *)key)+sizeof(nttl_x25519_asn1_pub),
		CURVE25519_SIZE);
	return x;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	unsigned char *data;

	*len=sizeof(nttl_x25519_asn1_key)+CURVE25519_SIZE;
	if(U(!(data=malloc(*len))))return NULL;
	memcpy(data,nttl_x25519_asn1_key,sizeof(nttl_x25519_asn1_key));
	memcpy(data+sizeof(nttl_x25519_asn1_key),
		((struct nttl_x25519 *)key)->key,CURVE25519_SIZE);
	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	struct nttl_x25519 *x;

	if(U(len<sizeof(nttl_x25519_asn1_key)+CURVE25519_SIZE)||
	    U(memcmp(key,nttl_x25519_asn1_key,sizeof(nttl_x25519_asn1_key))))
		goto err1;
	if(U(!(x=malloc(sizeof(struct nttl_x25519)))))goto err1;
	memcpy(x->key,((unsigned char *)key)+sizeof(nttl_x25519_asn1_key),
		CURVE25519_SIZE);
	curve25519_mul_g(x->pub,x->key);
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return x;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void USICRYPT(x25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_X25519
	((struct usicrypt_thread *)ctx)->global->
		memclear(key,sizeof(struct nttl_x25519));
	free(key);
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

	if(U(dlen>0x3fff)||U(iter<=0)||U(digest==USICRYPT_SHA1&&bits!=128))
		goto err1;

	if(U(nttl_asn_next(data,dlen,0x30,&cidx,&didx)))goto err1;
	if(U(cidx+didx!=dlen))goto err1;

	for(didx=0;didx<4;didx++)if(nttl_digest_asn[didx].oidlen&&
		nttl_digest_asn[didx].digest==digest)break;
	if(U(didx==4))goto err1;

	for(cidx=0;cidx<24;cidx++)if(nttl_cipher_asn[cidx].oidlen&&
		nttl_cipher_asn[cidx].cipher==cipher&&
		nttl_cipher_asn[cidx].mode==mode&&
		nttl_cipher_asn[cidx].bits==bits)break;
	if(U(cidx==24))goto err1;

	if(U(USICRYPT(random)(ctx,salt,8)))goto err1;
	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,8,iter,bfr)))goto err2;

	if(nttl_cipher_asn[cidx].ivlen)
		if(U(USICRYPT(random)(ctx,iv,nttl_cipher_asn[cidx].ivlen)))
			goto err3;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,cipher,mode,bfr,bits,iv))))
		goto err4;

	if(iter>=0x800000)ilen=4;
	else if(iter>=0x8000)ilen=3;
	else if(iter>=0x80)ilen=2;
	else ilen=1;

	if(nttl_cipher_asn[cidx].pad)
		plen=usicrypt_cipher_padding_add(ctx,NULL,dlen);
	else plen=0;
	len1=nttl_asn_length(NULL,dlen+plen)+1;
	len2=nttl_cipher_asn[cidx].oidlen+nttl_cipher_asn[cidx].ivlen+6;
	len3=ilen+sizeof(nttl_pbes2_oid)+sizeof(nttl_pbkdf2_oid)+24;
	if(digest!=USICRYPT_SHA1)len3+=nttl_digest_asn[didx].oidlen+6;
	*rlen=nttl_asn_length(NULL,len1+len2+len3+dlen+plen)+
		len1+len2+len3+dlen+plen+1;

	if(U(!(ptr=out=malloc(*rlen))))goto err5;

	*ptr++=0x30;
	ptr+=nttl_asn_length(ptr,len1+len2+len3+dlen+plen);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(nttl_pbes2_oid);
	memcpy(ptr,nttl_pbes2_oid,sizeof(nttl_pbes2_oid));
	ptr+=sizeof(nttl_pbes2_oid);
	len3-=sizeof(nttl_pbes2_oid)+6;
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(nttl_pbkdf2_oid);
	memcpy(ptr,nttl_pbkdf2_oid,sizeof(nttl_pbkdf2_oid));
	ptr+=sizeof(nttl_pbkdf2_oid);
	*ptr++=0x30;
	*ptr++=(unsigned char)
	     (ilen+12+(digest!=USICRYPT_SHA1?nttl_digest_asn[didx].oidlen+6:0));
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
		*ptr++=(unsigned char)(nttl_digest_asn[didx].oidlen+4);
		*ptr++=0x06;
		*ptr++=(unsigned char)nttl_digest_asn[didx].oidlen;
		memcpy(ptr,nttl_digest_asn[didx].oid,
			nttl_digest_asn[didx].oidlen);
		ptr+=nttl_digest_asn[didx].oidlen;
		*ptr++=0x05;
		*ptr++=0x00;
	}
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)nttl_cipher_asn[cidx].oidlen;
	memcpy(ptr,nttl_cipher_asn[cidx].oid,nttl_cipher_asn[cidx].oidlen);
	ptr+=nttl_cipher_asn[cidx].oidlen;
	*ptr++=0x04;
	*ptr++=(unsigned char)nttl_cipher_asn[cidx].ivlen;
	if(nttl_cipher_asn[cidx].ivlen)
	{
		memcpy(ptr,iv,nttl_cipher_asn[cidx].ivlen);
		ptr+=nttl_cipher_asn[cidx].ivlen;
	}
	*ptr++=0x04;
	ptr+=nttl_asn_length(ptr,dlen+plen);
	memcpy(ptr,data,dlen);
	if(nttl_cipher_asn[cidx].pad)usicrypt_cipher_padding_add(ctx,ptr,dlen);

	if(U(USICRYPT(blkcipher_encrypt)(c,ptr,dlen+plen,ptr)))goto err6;
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

	if(U(dlen>0x3fff))goto err1;

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	eptr=data+h+l;
	elen=dlen-h-l;
	data+=h;
	dlen=l;

	if(U(nttl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(nttl_pbes2_oid))||
		U(memcmp(data+h,nttl_pbes2_oid,l)))goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(nttl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(nttl_pbkdf2_oid))||U(memcmp(data+h,nttl_pbkdf2_oid,l)))
		goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;
	mlen=l;

	if(U(nttl_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	salt=data+h;
	slen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(nttl_asn_next(data,dlen,0x02,&h,&l)))goto err1;
	if(U(!l)||U(l>sizeof(int)))goto err1;
	iter=data+h;
	ilen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(mlen<0))goto err1;
	else if(mlen)
	{
		if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
		data+=h;
		dlen-=h;

		if(U(nttl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
		md=data+h;
		mlen=l;
		data+=h+l;
		dlen-=h+l;

		if(U(nttl_asn_next(data,dlen,0x05,&h,&l)))goto err1;
		if(U(l))goto err1;
		data+=h;
		dlen-=h;
	}

	if(U(nttl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(nttl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	cipher=data+h;
	clen=l;
	data+=h+l;
	dlen-=h+l;

	if(U(nttl_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	iv=data+h;
	ivlen=l;
	data+=h+l;
	dlen-=h+l;
	if(U(data!=eptr))goto err1;

	if(U(nttl_asn_next(eptr,elen,0x04,&h,&l)))goto err1;
	eptr+=h;
	elen=l;

	for(l=0,h=0;h<ilen;h++)l=(l<<8)|iter[h];
	if(U(!l))goto err1;

	if(mlen)
	{
		for(h=0;h<4;h++)if(nttl_digest_asn[h].oidlen&&
			mlen==nttl_digest_asn[h].oidlen&&
			!memcmp(md,nttl_digest_asn[h].oid,mlen))break;
		if(U(h==4))goto err1;
		else digest=nttl_digest_asn[h].digest;
	}

	for(h=0;h<24;h++)if(nttl_cipher_asn[h].oidlen&&
		clen==nttl_cipher_asn[h].oidlen&&
		!memcmp(cipher,nttl_cipher_asn[h].oid,clen))break;
	if(U(h==24)||U(nttl_cipher_asn[h].ivlen!=ivlen)||
		U(nttl_cipher_asn[h].bits!=128&&digest==USICRYPT_SHA1))
		goto err1;

	if(nttl_cipher_asn[h].pad)if(U(elen&0x0f))goto err1;

	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,slen,l,bfr)))goto err1;

	if(U(!(out=malloc(elen))))goto err2;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,nttl_cipher_asn[h].cipher,
		nttl_cipher_asn[h].mode,bfr,nttl_cipher_asn[h].bits,iv))))
		goto err3;
	if(U(USICRYPT(blkcipher_decrypt)(c,eptr,elen,out)))goto err5;
	USICRYPT(blkcipher_exit)(c);

	if(nttl_cipher_asn[h].pad)
	{
		if(U((*rlen=usicrypt_cipher_padding_get(ctx,out,elen))==-1))
			goto err4;
		else *rlen=elen-*rlen;
	}
	else *rlen=elen;

	if(U(nttl_asn_next(out,*rlen,0x30,&h,&l)))goto err4;
	if(U(h+l!=*rlen))goto err4;

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
		return AES_BLOCK_SIZE;
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
		return CAMELLIA_BLOCK_SIZE;
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
		if(U(!(c=nttl_aes_ecb_init(ctx,key,klen))))break;
		c->encrypt=nttl_aes_ecb_encrypt;
		c->decrypt=nttl_aes_ecb_decrypt;
		c->reset=NULL;
		c->exit=nttl_aes_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		if(U(!(c=nttl_aes_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_cbc_encrypt;
		c->decrypt=nttl_aes_cbc_decrypt;
		c->reset=nttl_aes_cbc_reset;
		c->exit=nttl_aes_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_AES|USICRYPT_CTS:
		if(U(!(c=nttl_aes_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_cts_encrypt;
		c->decrypt=nttl_aes_cts_decrypt;
		c->reset=nttl_aes_cts_reset;
		c->exit=nttl_aes_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		if(U(!(c=nttl_aes_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_cfb_encrypt;
		c->decrypt=nttl_aes_cfb_decrypt;
		c->reset=nttl_aes_cfb_reset;
		c->exit=nttl_aes_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_AES|USICRYPT_CFB8:
		if(U(!(c=nttl_aes_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_cfb8_encrypt;
		c->decrypt=nttl_aes_cfb8_decrypt;
		c->reset=nttl_aes_cfb8_reset;
		c->exit=nttl_aes_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		if(U(!(c=nttl_aes_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_ofb_crypt;
		c->decrypt=nttl_aes_ofb_crypt;
		c->reset=nttl_aes_ofb_reset;
		c->exit=nttl_aes_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_AES|USICRYPT_CTR:
		if(U(!(c=nttl_aes_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_aes_ctr_crypt;
		c->decrypt=nttl_aes_ctr_crypt;
		c->reset=nttl_aes_ctr_reset;
		c->exit=nttl_aes_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		if(U(!(c=nttl_camellia_ecb_init(ctx,key,klen))))break;
		c->encrypt=nttl_camellia_ecb_encrypt;
		c->decrypt=nttl_camellia_ecb_decrypt;
		c->reset=NULL;
		c->exit=nttl_camellia_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		if(U(!(c=nttl_camellia_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_cbc_encrypt;
		c->decrypt=nttl_camellia_cbc_decrypt;
		c->reset=nttl_camellia_cbc_reset;
		c->exit=nttl_camellia_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_CAMELLIA|USICRYPT_CTS:
		if(U(!(c=nttl_camellia_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_cts_encrypt;
		c->decrypt=nttl_camellia_cts_decrypt;
		c->reset=nttl_camellia_cts_reset;
		c->exit=nttl_camellia_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		if(U(!(c=nttl_camellia_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_cfb_encrypt;
		c->decrypt=nttl_camellia_cfb_decrypt;
		c->reset=nttl_camellia_cfb_reset;
		c->exit=nttl_camellia_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_CAMELLIA|USICRYPT_CFB8:
		if(U(!(c=nttl_camellia_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_cfb8_encrypt;
		c->decrypt=nttl_camellia_cfb8_decrypt;
		c->reset=nttl_camellia_cfb8_reset;
		c->exit=nttl_camellia_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		if(U(!(c=nttl_camellia_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_ofb_crypt;
		c->decrypt=nttl_camellia_ofb_crypt;
		c->reset=nttl_camellia_ofb_reset;
		c->exit=nttl_camellia_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_CAMELLIA|USICRYPT_CTR:
		if(U(!(c=nttl_camellia_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_camellia_ctr_crypt;
		c->decrypt=nttl_camellia_ctr_crypt;
		c->reset=nttl_camellia_ctr_reset;
		c->exit=nttl_camellia_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20|USICRYPT_STREAM:
		if(U(!(c=nttl_chacha_init(ctx,key,klen,iv))))break;
		c->encrypt=nttl_chacha_crypt;
		c->decrypt=nttl_chacha_crypt;
		c->reset=nttl_chacha_reset;
		c->exit=nttl_chacha_exit;
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
		if(U(!(c=nttl_aes_xts_init(ctx,key,klen))))break;
		c->encrypt=nttl_aes_xts_encrypt;
		c->decrypt=nttl_aes_xts_decrypt;
		c->exit=nttl_aes_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_AES|USICRYPT_ESSIV:
		if(U(!(c=nttl_aes_essiv_init(ctx,key,klen))))break;
		c->encrypt=nttl_aes_essiv_encrypt;
		c->decrypt=nttl_aes_essiv_decrypt;
		c->exit=nttl_aes_essiv_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_XTS
	case USICRYPT_CAMELLIA|USICRYPT_XTS:
		if(U(!(c=nttl_camellia_xts_init(ctx,key,klen))))break;
		c->encrypt=nttl_camellia_xts_encrypt;
		c->decrypt=nttl_camellia_xts_decrypt;
		c->exit=nttl_camellia_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_CAMELLIA|USICRYPT_ESSIV:
		if(U(!(c=nttl_camellia_essiv_init(ctx,key,klen))))break;
		c->encrypt=nttl_camellia_essiv_encrypt;
		c->decrypt=nttl_camellia_essiv_decrypt;
		c->exit=nttl_camellia_essiv_exit;
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
		if(U(!(c=nttl_aes_gcm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=nttl_aes_gcm_encrypt;
		c->decrypt=nttl_aes_gcm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=nttl_aes_gcm_encrypt_iov;
		c->decrypt_iov=nttl_aes_gcm_decrypt_iov;
#endif
		c->exit=nttl_aes_gcm_exit;
		break;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		if(U(!(c=nttl_aes_ccm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=nttl_aes_ccm_encrypt;
		c->decrypt=nttl_aes_ccm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=nttl_aes_ccm_encrypt_iov;
		c->decrypt_iov=nttl_aes_ccm_decrypt_iov;
#endif
		c->exit=nttl_aes_ccm_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		if(U(!(c=nttl_chacha_poly_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=nttl_chacha_poly_encrypt;
		c->decrypt=nttl_chacha_poly_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=nttl_chacha_poly_encrypt_iov;
		c->decrypt_iov=nttl_chacha_poly_decrypt_iov;
#endif
		c->exit=nttl_chacha_poly_exit;
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
		return nttl_aes_cmac(ctx,key,klen,src,slen,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return nttl_camellia_cmac(ctx,key,klen,src,slen,dst);
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
		return nttl_aes_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return nttl_camellia_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(thread_init)(void *global)
{
	struct usicrypt_thread *ctx;
	unsigned char bfr[32];

	if(U(!(ctx=malloc(sizeof(struct usicrypt_thread)))))goto err1;
	ctx->global=global;
	ctx->total=0;
	yarrow256_init(&ctx->rng,2,ctx->src);
	if(U(ctx->global->rng_seed(bfr,sizeof(bfr))))goto err2;
	yarrow256_seed(&ctx->rng,sizeof(bfr),bfr);
	if(U(ctx->global->rng_seed(bfr,sizeof(bfr))))goto err2;
	yarrow256_update(&ctx->rng,0,0,sizeof(bfr),bfr);
	if(U(ctx->global->rng_seed(bfr,sizeof(bfr))))goto err2;
	yarrow256_update(&ctx->rng,1,0,sizeof(bfr),bfr);
	if(U(!yarrow256_is_seeded(&ctx->rng)))goto err2;
	return ctx;

err2:	free(ctx);
err1:	return NULL;
}

void USICRYPT(thread_exit)(void *ctx)
{
	((struct usicrypt_thread *)ctx)->global->memclear(
		&((struct usicrypt_thread *)ctx)->rng,
		sizeof(struct yarrow256_ctx));
	free(ctx);
}

void *USICRYPT(global_init)(int (*rng_seed)(void *data,int len),
	void (*memclear)(void *data,int len))
{
	struct usicrypt_global *ctx;

	USICRYPT(do_realloc)(NULL,NULL,0,0);
	if(U(!(ctx=malloc(sizeof(struct usicrypt_global)))))goto err1;
	ctx->rng_seed=(rng_seed?rng_seed:USICRYPT(get_random));
	ctx->memclear=(memclear?memclear:USICRYPT(do_memclear));
	return ctx;

err1:	return NULL;
}

void USICRYPT(global_exit)(void *ctx)
{
	free(ctx);
}

#endif
