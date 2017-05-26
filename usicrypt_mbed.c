/*
 * usicrypt, a unified simple interface crypto library wrapper
 *
 * (c) 2017 Andreas Steinmetz
 *
 * Any OSI approved license of your choice applies, see the file LICENSE
 * for details.
 *
 */

/*
enabled in include/mbedtls/config.h:

#define MBEDTLS_HAVE_SSE2
#define MBEDTLS_ZLIB_SUPPORT
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
#define MBEDTLS_CMAC_C
*/

/******************************************************************************/
/*                                 Testing                                    */
/******************************************************************************/

#ifdef USICRYPT_TEST
#ifndef USICRYPT_MBED
#define USICRYPT_MBED
#endif
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#if defined(USICRYPT_MBED)

#include <mbedtls/rsa.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <mbedtls/cmac.h>
#include <mbedtls/camellia.h>

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) mbed_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

/******************************************************************************/
/*                                 mbedTLS                                    */
/******************************************************************************/

struct mbed_aes_ecb
{
	struct usicrypt_cipher cipher;
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
};

struct mbed_aes_cbc
{
	struct usicrypt_cipher cipher;
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
	unsigned char iv[16];
};

struct mbed_aes_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
	unsigned char iv[16];
	unsigned char tmp[32];
};

struct mbed_aes_cfb
{
	struct usicrypt_cipher cipher;
	mbedtls_aes_context enc;
	size_t off;
	unsigned char iv[16];
};

struct mbed_aes_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	unsigned char iv[16];
};

struct mbed_aes_ofb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	int n;
	unsigned char iv[16];
	unsigned char zero[16];
};

struct mbed_aes_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	size_t off;
	unsigned char iv[16];
	unsigned char bfr[16];
	unsigned char zero[16];
};

struct mbed_aes_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
	mbedtls_aes_context twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct mbed_aes_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	mbedtls_aes_context enc;
	mbedtls_aes_context dec;
	mbedtls_aes_context aux;
	unsigned char iv[16];
};

struct mbed_aes_gcm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	mbedtls_gcm_context ctx;
	int ilen;
	int tlen;
};

struct mbed_aes_ccm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	mbedtls_ccm_context ctx;
	int ilen;
	int tlen;
};

struct mbed_camellia_ecb
{
	struct usicrypt_cipher cipher;
	mbedtls_camellia_context enc;
	mbedtls_camellia_context dec;
};

struct mbed_camellia_cbc
{
	struct usicrypt_cipher cipher;
	mbedtls_camellia_context enc;
	mbedtls_camellia_context dec;
	unsigned char iv[16];
};

struct mbed_camellia_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	mbedtls_camellia_context dec;
	unsigned char iv[16];
	unsigned char tmp[32];
};

struct mbed_camellia_cfb
{
	struct usicrypt_cipher cipher;
	mbedtls_camellia_context enc;
	size_t off;
	unsigned char iv[16];
};

struct mbed_camellia_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct mbed_camellia_ofb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	int n;
	unsigned char iv[16];
	unsigned char zero[16];
};

struct mbed_camellia_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	size_t off;
	unsigned char iv[16];
	unsigned char bfr[16];
	unsigned char zero[16];
};

struct mbed_camellia_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	mbedtls_camellia_context dec;
	mbedtls_camellia_context twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct mbed_camellia_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	mbedtls_camellia_context enc;
	mbedtls_camellia_context dec;
	mbedtls_camellia_context aux;
	unsigned char iv[16];
};

#ifndef USICRYPT_NO_PBKDF2

static const unsigned char const mbed_pbes2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

static const unsigned char const mbed_pbkdf2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c
};

static const struct
{
	const int const digest;
	const int const oidlen;
	const unsigned char const oid[0x08];

} const mbed_digest_asn[4]=
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
} const mbed_cipher_asn[24]=
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
#ifndef USICRYPT_NO_EC

static const int const mbed_ec_map[USICRYPT_TOT_EC_CURVES]=
{
	MBEDTLS_ECP_DP_BP512R1,
	MBEDTLS_ECP_DP_BP384R1,
	MBEDTLS_ECP_DP_BP256R1,
	MBEDTLS_ECP_DP_SECP521R1,
	MBEDTLS_ECP_DP_SECP384R1,
	MBEDTLS_ECP_DP_SECP256R1
};

#endif

static int mbed_seed(void *ctx,unsigned char *data,size_t len)
{
	return ((struct usicrypt_global *)ctx)->rng_seed(data,len);
}

#ifndef USICRYPT_NO_PBKDF2

static int mbed_asn_length(unsigned char *ptr,int len)
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

static int mbed_asn_next(unsigned char *prm,int len,unsigned char id,
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
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC)

static int mbed_reseed(void *ctx)
{
	int r=-1;
	unsigned char bfr[32];

	if(((struct usicrypt_thread *)ctx)->global->rng_seed(bfr,sizeof(bfr)))
		goto err1;
	mbedtls_hmac_drbg_update(&((struct usicrypt_thread *)ctx)->rng,
		bfr,sizeof(bfr));
	r=0;
err1:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return r;
}

#endif
#ifndef USICRYPT_NO_RSA

static void *mbed_rsa_do_sign_v15(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int i;
	int type;
	unsigned char *sig;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(mbed_reseed(ctx))goto err1;

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))goto err2;
	if(mbedtls_md_starts(&c))goto err2;
	if(!mode)
	{
		if(mbedtls_md_update(&c,data,dlen))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
			goto err2;
	if(mbedtls_md_finish(&c,hash))goto err2;

	*slen=mbedtls_pk_get_len(key);
	if(!(sig=malloc(*slen)))goto err3;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
	if(mbedtls_rsa_rsassa_pkcs1_v15_sign(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PRIVATE,MBEDTLS_MD_NONE,
		mbedtls_md_get_size(mbedtls_md_info_from_type(type)),hash,sig))
		goto err4;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mbedtls_md_free(&c);
	return sig;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
	free(sig);
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
err3:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err2:	mbedtls_md_free(&c);
err1:	return NULL;
}

static int mbed_rsa_do_verify_v15(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int r=-1;
	int i;
	int type;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(slen<mbedtls_pk_get_len(key))goto err1;

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))goto err2;
	if(mbedtls_md_starts(&c))goto err2;
	if(!mode)
	{
		if(mbedtls_md_update(&c,data,dlen))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
			goto err2;
	if(mbedtls_md_finish(&c,hash))goto err2;

	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
	r=mbedtls_rsa_rsassa_pkcs1_v15_verify(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PUBLIC,MBEDTLS_MD_NONE,
		mbedtls_md_get_size(mbedtls_md_info_from_type(type)),
		hash,sig);
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));

err2:	mbedtls_md_free(&c);
err1:	return r?-1:0;
}

static void *mbed_rsa_do_sign_pss(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int i;
	int type;
	unsigned char *sig;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(mbed_reseed(ctx))goto err1;

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))goto err2;
	if(mbedtls_md_starts(&c))goto err2;
	if(!mode)
	{
		if(mbedtls_md_update(&c,data,dlen))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
			goto err2;
	if(mbedtls_md_finish(&c,hash))goto err2;

	*slen=mbedtls_pk_get_len(key);
	if(!(sig=malloc(*slen)))goto err3;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,type);
	if(mbedtls_rsa_rsassa_pss_sign(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PRIVATE,type,0,hash,sig))goto err4;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mbedtls_md_free(&c);
	return sig;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
	free(sig);
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
err3:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err2:	mbedtls_md_free(&c);
err1:	return NULL;
}

static int mbed_rsa_do_verify_pss(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int i;
	int type;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(slen!=mbedtls_pk_get_len(key))goto err1;
	if(slen-2*mbedtls_md_get_size(mbedtls_md_info_from_type(type))-2<0)
		goto err1;

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))goto err2;
	if(mbedtls_md_starts(&c))goto err2;
	if(!mode)
	{
		if(mbedtls_md_update(&c,data,dlen))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
			goto err2;
	if(mbedtls_md_finish(&c,hash))goto err2;

	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,type);
	if(mbedtls_rsa_rsassa_pss_verify(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PUBLIC,type,0,hash,sig))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	mbedtls_md_free(&c);
	return 0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
err2:	mbedtls_md_free(&c);
err1:	return -1;
}

#endif
#ifndef USICRYPT_NO_EC

static void *mbed_ec_do_sign(void *ctx,int md,void *key,void *data,int dlen,
	int *slen,int mode)
{
	int i;
	int type;
	size_t len=1024;
	unsigned char *r=NULL;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	unsigned char sig[1024];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(mbed_reseed(ctx))goto err1;
	if(!mode)
	{
		if(mbedtls_md(mbedtls_md_info_from_type(type),data,dlen,hash))
			goto err2;
	}
	else
	{
		mbedtls_md_init(&c);
		if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))
			goto err3;
		if(mbedtls_md_starts(&c))goto err3;
		for(i=0;i<dlen;i++)
			if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
				goto err3;
		if(mbedtls_md_finish(&c,hash))goto err3;
	}
	if(mbedtls_pk_sign(key,type,hash,0,sig,&len,mbed_seed,
		((struct usicrypt_thread *)ctx)->global))goto err3;
	if(!(r=malloc(len)))goto err4;
	memcpy(r,sig,len);
	*slen=len;
err4:	((struct usicrypt_thread *)ctx)->global->memclear(sig,len);
err3:	if(mode)mbedtls_md_free(&c);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return r;
}

static int mbed_ec_do_verify(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen,int mode)
{
	int r=-1;
	int i;
	int type;
	struct usicrypt_iov *iov=data;
	mbedtls_md_context_t c;
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(!mode)
	{
		if(mbedtls_md(mbedtls_md_info_from_type(type),data,dlen,hash))
			goto err2;
	}
	else
	{
		mbedtls_md_init(&c);
		if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),0))
			goto err3;
		if(mbedtls_md_starts(&c))goto err3;
		for(i=0;i<dlen;i++)
			if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
				goto err3;
		if(mbedtls_md_finish(&c,hash))goto err3;
	}
	if(mbedtls_pk_verify(key,type,hash,0,sig,slen))goto err3;
	r=0;

err3:	if(mode)mbedtls_md_free(&c);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return r;
}

#endif
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_CMAC

static int mbed_aes_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	int type;

	switch(klen)
	{
	case 128:
		type=MBEDTLS_CIPHER_AES_128_ECB;
		break;
	case 192:
		type=MBEDTLS_CIPHER_AES_192_ECB;
		break;
	case 256:
		type=MBEDTLS_CIPHER_AES_256_ECB;
		break;
	default:return -1;
	}

	if(mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(type),
		key,klen,src,slen,dst))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int mbed_aes_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	int type;
	mbedtls_cipher_context_t c;

	switch(klen)
	{
	case 128:
		type=MBEDTLS_CIPHER_AES_128_ECB;
		break;
	case 192:
		type=MBEDTLS_CIPHER_AES_192_ECB;
		break;
	case 256:
		type=MBEDTLS_CIPHER_AES_256_ECB;
		break;
	default:return -1;
	}

	mbedtls_cipher_init(&c);
	if(mbedtls_cipher_setup(&c,mbedtls_cipher_info_from_type(type)))
		goto err1;
	if(mbedtls_cipher_cmac_starts(&c,key,klen))goto err1;
	for(i=0;i<niov;i++)if(mbedtls_cipher_cmac_update(&c,iov[i].data,
		iov[i].length))goto err1;
	if(mbedtls_cipher_cmac_finish(&c,dst))goto err1;
	mbedtls_cipher_free(&c);
	return 0;

err1:	mbedtls_cipher_free(&c);
	return -1;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int mbed_aes_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen&0xf)return -1;
	for(;slen;s+=16,d+=16,slen-=16)if(mbedtls_aes_crypt_ecb(
		&((struct mbed_aes_ecb *)ctx)->enc,
		MBEDTLS_AES_ENCRYPT,s,d))return -1;
	return 0;
}

static int mbed_aes_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen&0xf)return -1;
	for(;slen;s+=16,d+=16,slen-=16)if(mbedtls_aes_crypt_ecb(
		&((struct mbed_aes_ecb *)ctx)->dec,
		MBEDTLS_AES_DECRYPT,s,d))return -1;
	return 0;
}

static void *mbed_aes_ecb_init(void *ctx,void *key,int klen)
{
	struct mbed_aes_ecb *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_ecb))))goto err1;
	mbedtls_aes_init(&aes->enc);
	mbedtls_aes_init(&aes->dec);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	if(mbedtls_aes_setkey_dec(&aes->dec,key,klen))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	mbedtls_aes_free(&aes->dec);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_ecb_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_ecb *)ctx)->enc);
	mbedtls_aes_free(&((struct mbed_aes_ecb *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int mbed_aes_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(mbedtls_aes_crypt_cbc(&((struct mbed_aes_cbc *)ctx)->enc,
		MBEDTLS_AES_ENCRYPT,slen,((struct mbed_aes_cbc *)ctx)->iv,
		src,dst))return -1;
	return 0;
}

static int mbed_aes_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(mbedtls_aes_crypt_cbc(&((struct mbed_aes_cbc *)ctx)->dec,
		MBEDTLS_AES_DECRYPT,slen,((struct mbed_aes_cbc *)ctx)->iv,
		src,dst))return -1;
	return 0;
}

static void *mbed_aes_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_cbc *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_cbc))))goto err1;
	mbedtls_aes_init(&aes->enc);
	mbedtls_aes_init(&aes->dec);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	if(mbedtls_aes_setkey_dec(&aes->dec,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	mbedtls_aes_free(&aes->dec);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_aes_cbc *)ctx)->iv,iv,16);
}

static void mbed_aes_cbc_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_cbc *)ctx)->enc);
	mbedtls_aes_free(&((struct mbed_aes_cbc *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int mbed_aes_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct mbed_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<=16)return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(mbedtls_aes_crypt_cbc(&aes->enc,MBEDTLS_AES_ENCRYPT,slen-rem,
		aes->iv,s,d))return -1;
	s+=slen-rem;
	d+=slen-rem;
	memcpy(aes->tmp,s,rem);
	if(rem<16)memset(aes->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	if(mbedtls_aes_crypt_cbc(&aes->enc,MBEDTLS_AES_ENCRYPT,16,aes->iv,
		aes->tmp,d-16))return -1;
	return 0;
}

static int mbed_aes_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct mbed_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<=16)return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(slen-rem-16)
	{
		if(mbedtls_aes_crypt_cbc(&aes->dec,MBEDTLS_AES_DECRYPT,
			slen-rem-16,aes->iv,s,d))return -1;
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(aes->tmp+16,s,16);
	if(mbedtls_aes_crypt_ecb(&aes->dec,MBEDTLS_AES_DECRYPT,s,aes->tmp))
		return -1;
	memcpy(aes->tmp,s+16,rem);
	if(mbedtls_aes_crypt_cbc(&aes->dec,MBEDTLS_AES_DECRYPT,32,
		aes->iv,aes->tmp,aes->tmp))return -1;
	memcpy(d,aes->tmp,rem+16);
	return 0;
}

static void *mbed_aes_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_cts *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_cts))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_aes_init(&aes->enc);
	mbedtls_aes_init(&aes->dec);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	if(mbedtls_aes_setkey_dec(&aes->dec,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	mbedtls_aes_free(&aes->dec);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_aes_cts *)ctx)->iv,iv,16);
}

static void mbed_aes_cts_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_cts *)ctx)->enc);
	mbedtls_aes_free(&((struct mbed_aes_cts *)ctx)->dec);
	((struct mbed_aes_cts *)ctx)->global->
		memclear(((struct mbed_aes_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int mbed_aes_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_aes_crypt_cfb128(&((struct mbed_aes_cfb *)ctx)->enc,
		MBEDTLS_AES_ENCRYPT,slen,&((struct mbed_aes_cfb *)ctx)->off,
		((struct mbed_aes_cfb *)ctx)->iv,src,dst))return -1;
	return 0;
}

static int mbed_aes_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_aes_crypt_cfb128(&((struct mbed_aes_cfb *)ctx)->enc,
		MBEDTLS_AES_DECRYPT,slen,&((struct mbed_aes_cfb *)ctx)->off,
		((struct mbed_aes_cfb *)ctx)->iv,src,dst))return -1;
	return 0;
}

static void *mbed_aes_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_cfb *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_cfb))))goto err1;
	mbedtls_aes_init(&aes->enc);
	aes->off=0;
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_cfb_reset(void *ctx,void *iv)
{
	((struct mbed_aes_cfb *)ctx)->off=0;
	memcpy(((struct mbed_aes_cfb *)ctx)->iv,iv,16);
}

static void mbed_aes_cfb_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_cfb *)ctx)->enc);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int mbed_aes_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_aes_crypt_cfb8(&((struct mbed_aes_cfb8 *)ctx)->enc,
		MBEDTLS_AES_ENCRYPT,slen,
		((struct mbed_aes_cfb8 *)ctx)->iv,src,dst))return -1;
	return 0;
}

static int mbed_aes_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_aes_crypt_cfb8(&((struct mbed_aes_cfb8 *)ctx)->enc,
		MBEDTLS_AES_DECRYPT,slen,
		((struct mbed_aes_cfb8 *)ctx)->iv,src,dst))return -1;
	return 0;
}

static void *mbed_aes_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_cfb8 *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_cfb8))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_aes_init(&aes->enc);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_aes_cfb8 *)ctx)->iv,iv,16);
}

static void mbed_aes_cfb8_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_cfb8 *)ctx)->enc);
	((struct mbed_aes_cfb8 *)ctx)->global->memclear(
		((struct mbed_aes_cfb8 *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int mbed_aes_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct mbed_aes_ofb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!aes->n)if(mbedtls_aes_crypt_cbc(&aes->enc,
			MBEDTLS_AES_ENCRYPT,16,aes->iv,
			aes->zero,aes->iv))return -1;
		*d++=aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!aes->n)if(mbedtls_aes_crypt_cbc(&aes->enc,
			MBEDTLS_AES_ENCRYPT,16,aes->iv,
			aes->zero,aes->iv))return -1;
		*d++=*s++^aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static void *mbed_aes_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_ofb *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_ofb))))goto err1;
	mbedtls_aes_init(&aes->enc);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	memset(aes->zero,0,16);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_ofb_reset(void *ctx,void *iv)
{
	((struct mbed_aes_ofb *)ctx)->n=0;
	memcpy(((struct mbed_aes_ofb *)ctx)->iv,iv,16);
}

static void mbed_aes_ofb_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_ofb *)ctx)->enc);
	((struct mbed_aes_ofb *)ctx)->global->
		memclear(((struct mbed_aes_ofb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int mbed_aes_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct mbed_aes_ctr *aes=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			if(mbedtls_aes_crypt_ctr(&aes->enc,16,&aes->off,
				aes->iv,aes->bfr,aes->zero,dst))return -1;
		if(mbedtls_aes_crypt_ctr(&aes->enc,slen,&aes->off,
			aes->iv,aes->bfr,aes->zero,dst))return -1;
	}
	else if(mbedtls_aes_crypt_ctr(&aes->enc,slen,&aes->off,
		aes->iv,aes->bfr,src,dst))return -1;
	return 0;
}

static void *mbed_aes_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_aes_ctr *aes;

	if(!(aes=malloc(sizeof(struct mbed_aes_ctr))))goto err1;
	mbedtls_aes_init(&aes->enc);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->off=0;
	memset(aes->zero,0,16);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	memcpy(aes->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_ctr_reset(void *ctx,void *iv)
{
	((struct mbed_aes_ctr *)ctx)->off=0;
	memcpy(((struct mbed_aes_ctr *)ctx)->iv,iv,16);
}

static void mbed_aes_ctr_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_ctr *)ctx)->enc);
	((struct mbed_aes_ctr *)ctx)->global->
		memclear(((struct mbed_aes_ctr *)ctx)->bfr,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int mbed_aes_xts_encrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct mbed_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(mbedtls_aes_crypt_ecb(&aes->twe,MBEDTLS_AES_ENCRYPT,iv,aes->twk))
		return -1;

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		if(mbedtls_aes_crypt_ecb(&aes->enc,MBEDTLS_AES_ENCRYPT,
			aes->wrk,d))return -1;
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
		if(mbedtls_aes_crypt_ecb(&aes->enc,MBEDTLS_AES_ENCRYPT,
			aes->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
	}

	return 0;
}

static int mbed_aes_xts_decrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct mbed_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(mbedtls_aes_crypt_ecb(&aes->twe,MBEDTLS_AES_ENCRYPT,iv,aes->twk))
		return -1;

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		if(mbedtls_aes_crypt_ecb(&aes->dec,MBEDTLS_AES_DECRYPT,
			aes->wrk,d))return -1;
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
		if(mbedtls_aes_crypt_ecb(&aes->dec,MBEDTLS_AES_DECRYPT,
			aes->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
		memcpy(d+16,d,slen);
		memcpy(aes->wrk,s+16,slen);
		memcpy(aes->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)aes->wrk[i]^=aes->mem[i];
		if(mbedtls_aes_crypt_ecb(&aes->dec,MBEDTLS_AES_DECRYPT,
			aes->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=aes->mem[i];
	}

	return 0;
}

static void *mbed_aes_xts_init(void *ctx,void *key,int klen)
{
	struct mbed_aes_xts *aes;

	if(klen!=256&&klen!=512)goto err1;
	if(!(aes=malloc(sizeof(struct mbed_aes_xts))))goto err1;
	mbedtls_aes_init(&aes->enc);
	mbedtls_aes_init(&aes->dec);
	mbedtls_aes_init(&aes->twe);
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen>>1))goto err2;
	if(mbedtls_aes_setkey_dec(&aes->dec,key,klen>>1))goto err2;
	if(mbedtls_aes_setkey_enc(&aes->twe,key+(klen>>4),klen>>1))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	mbedtls_aes_free(&aes->enc);
	mbedtls_aes_free(&aes->dec);
	mbedtls_aes_free(&aes->twe);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_xts_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_xts *)ctx)->enc);
	mbedtls_aes_free(&((struct mbed_aes_xts *)ctx)->dec);
	mbedtls_aes_free(&((struct mbed_aes_xts *)ctx)->twe);
	((struct mbed_aes_xts *)ctx)->global->
		memclear(((struct mbed_aes_xts *)ctx)->twk,16);
	((struct mbed_aes_xts *)ctx)->global->
		memclear(((struct mbed_aes_xts *)ctx)->wrk,16);
	((struct mbed_aes_xts *)ctx)->global->
		memclear(((struct mbed_aes_xts *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int mbed_aes_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct mbed_aes_essiv *aes=ctx;

	if(slen&0xf)return -1;
	if(mbedtls_aes_crypt_ecb(&aes->aux,MBEDTLS_AES_ENCRYPT,iv,aes->iv))
		return -1;
	if(mbedtls_aes_crypt_cbc(&aes->enc,MBEDTLS_AES_ENCRYPT,slen,aes->iv,
		src,dst))return -1;
	return 0;
}

static int mbed_aes_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct mbed_aes_essiv *aes=ctx;

	if(slen&0xf)return -1;
	if(mbedtls_aes_crypt_ecb(&aes->aux,MBEDTLS_AES_ENCRYPT,iv,aes->iv))
		return -1;
	if(mbedtls_aes_crypt_cbc(&aes->dec,MBEDTLS_AES_DECRYPT,slen,aes->iv,
		src,dst))return -1;
	return 0;
}

static void *mbed_aes_essiv_init(void *ctx,void *key,int klen)
{
	struct mbed_aes_essiv *aes;
	unsigned char tmp[32];

	if(!(aes=malloc(sizeof(struct mbed_aes_essiv))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_aes_init(&aes->enc);
	mbedtls_aes_init(&aes->dec);
	mbedtls_aes_init(&aes->aux);
	if(mbedtls_aes_setkey_enc(&aes->enc,key,klen))goto err2;
	if(mbedtls_aes_setkey_dec(&aes->dec,key,klen))goto err2;
	if(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,klen>>3,
		tmp))goto err2;
	if(mbedtls_aes_setkey_enc(&aes->aux,tmp,256))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
err2:	mbedtls_aes_free(&aes->aux);
	mbedtls_aes_free(&aes->enc);
	mbedtls_aes_free(&aes->dec);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_essiv_exit(void *ctx)
{
	mbedtls_aes_free(&((struct mbed_aes_essiv *)ctx)->enc);
	mbedtls_aes_free(&((struct mbed_aes_essiv *)ctx)->dec);
	mbedtls_aes_free(&((struct mbed_aes_essiv *)ctx)->aux);
	((struct mbed_aes_essiv *)ctx)->global->memclear(
		((struct mbed_aes_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_GCM

static int mbed_aes_gcm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(mbedtls_gcm_crypt_and_tag(&((struct mbed_aes_gcm *)ctx)->ctx,
		MBEDTLS_GCM_ENCRYPT,slen,iv,((struct mbed_aes_gcm *)ctx)->ilen,
		aad,alen,src,dst,((struct mbed_aes_gcm *)ctx)->tlen,tag))
		return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int mbed_aes_gcm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(!(aad=malloc(alen)))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(mbedtls_gcm_crypt_and_tag(&((struct mbed_aes_gcm *)ctx)->ctx,
		MBEDTLS_GCM_ENCRYPT,slen,iv,((struct mbed_aes_gcm *)ctx)->ilen,
		aad,alen,src,dst,((struct mbed_aes_gcm *)ctx)->tlen,tag))
		goto err2;
	if(aad)
	{
		((struct mbed_aes_gcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct mbed_aes_gcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:	return -1;
}

#endif

static int mbed_aes_gcm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(mbedtls_gcm_crypt_and_tag(&((struct mbed_aes_gcm *)ctx)->ctx,
		MBEDTLS_GCM_DECRYPT,slen,iv,((struct mbed_aes_gcm *)ctx)->ilen,
		aad,alen,src,dst,((struct mbed_aes_gcm *)ctx)->tlen,tag))
		return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int mbed_aes_gcm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(!(aad=malloc(alen)))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(mbedtls_gcm_crypt_and_tag(&((struct mbed_aes_gcm *)ctx)->ctx,
		MBEDTLS_GCM_DECRYPT,slen,iv,((struct mbed_aes_gcm *)ctx)->ilen,
		aad,alen,src,dst,((struct mbed_aes_gcm *)ctx)->tlen,tag))
		goto err2;
	if(aad)
	{
		((struct mbed_aes_gcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct mbed_aes_gcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:	return -1;
}

#endif

static void *mbed_aes_gcm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct mbed_aes_gcm *gcm;

	if(!(gcm=malloc(sizeof(struct mbed_aes_gcm))))goto err1;
	gcm->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_gcm_init(&gcm->ctx);
	if(mbedtls_gcm_setkey(&gcm->ctx,MBEDTLS_CIPHER_ID_AES,key,klen))
		goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	gcm->ilen=ilen;
	gcm->tlen=tlen;
	return gcm;

err2:	mbedtls_gcm_free(&gcm->ctx);
	free(gcm);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_gcm_exit(void *ctx)
{
	mbedtls_gcm_free(&((struct mbed_aes_gcm *)ctx)->ctx);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CCM

static int mbed_aes_ccm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(mbedtls_ccm_encrypt_and_tag(
		&((struct mbed_aes_ccm *)ctx)->ctx,slen,iv,
		((struct mbed_aes_ccm *)ctx)->ilen,aad,alen,src,dst,tag,
		((struct mbed_aes_ccm *)ctx)->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int mbed_aes_ccm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(!(aad=malloc(alen)))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(mbedtls_ccm_encrypt_and_tag(
		&((struct mbed_aes_ccm *)ctx)->ctx,slen,iv,
		((struct mbed_aes_ccm *)ctx)->ilen,aad,alen,src,dst,tag,
		((struct mbed_aes_ccm *)ctx)->tlen))goto err2;
	if(aad)
	{
		((struct mbed_aes_ccm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct mbed_aes_ccm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:	return -1;
}

#endif

static int mbed_aes_ccm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(mbedtls_ccm_auth_decrypt(&((struct mbed_aes_ccm *)ctx)->ctx,slen,iv,
		((struct mbed_aes_ccm *)ctx)->ilen,aad,alen,src,dst,tag,
		((struct mbed_aes_ccm *)ctx)->tlen))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int mbed_aes_ccm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(!(aad=malloc(alen)))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(mbedtls_ccm_auth_decrypt(&((struct mbed_aes_ccm *)ctx)->ctx,slen,iv,
		((struct mbed_aes_ccm *)ctx)->ilen,aad,alen,src,dst,tag,
		((struct mbed_aes_ccm *)ctx)->tlen))goto err2;
	if(aad)
	{
		((struct mbed_aes_ccm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct mbed_aes_ccm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:	return -1;
}

#endif

static void *mbed_aes_ccm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct mbed_aes_ccm *ccm;

	if(!(ccm=malloc(sizeof(struct mbed_aes_ccm))))goto err1;
	ccm->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_ccm_init(&ccm->ctx);
	if(mbedtls_ccm_setkey(&ccm->ctx,MBEDTLS_CIPHER_ID_AES,key,klen))
		goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	ccm->ilen=ilen;
	ccm->tlen=tlen;
	return ccm;

err2:	mbedtls_ccm_free(&ccm->ctx);
	free(ccm);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_aes_ccm_exit(void *ctx)
{
	mbedtls_ccm_free(&((struct mbed_aes_ccm *)ctx)->ctx);
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY

static int mbed_chacha_poly_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	return -1;
}

static int mbed_chacha_poly_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	return -1;
}

static int mbed_chacha_poly_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	return -1;
}

static int mbed_chacha_poly_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	return -1;
}

static void *mbed_chacha_poly_init(void *ctx,void *key,int klen,int ilen,
	int tlen)
{
	return NULL;
}

static void mbed_chacha_poly_exit(void *ctx)
{
}

#endif
#ifndef USICRYPT_NO_STREAM

static int mbed_chacha_crypt(void *ctx,void *src,int slen,void *dst)
{
	return -1;
}

static void *mbed_chacha_init(void *ctx,void *key,int klen,void *iv)
{
	return NULL;
}

static void mbed_chacha_reset(void *ctx,void *iv)
{
}

static void mbed_chacha_exit(void *ctx)
{
}

#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_CMAC

static int mbed_camellia_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	int r=-1;
	int i;
	int n;
	unsigned char *s=src;
	mbedtls_camellia_context enc;
	unsigned char wrk[4][16];

	if(klen&7)goto err1;
	mbedtls_camellia_init(&enc);
	if(mbedtls_camellia_setkey_enc(&enc,key,klen))goto err2;
	memset(wrk,0,sizeof(wrk));
	if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
		wrk[1],wrk[1]))goto err3;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(;slen>16;slen-=16,s+=16)
	{
		for(i=0;i<16;i++)wrk[0][i]^=s[i];
		if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
			wrk[0],wrk[0]))goto err3;
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
	if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
		wrk[0],dst))goto err3;
	r=0;
err3:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
err2:	mbedtls_camellia_free(&enc);
err1:	return r;
}

#ifndef USICRYPT_NO_IOV

static int mbed_camellia_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int r=-1;
	int j;
	int r1;
	int r2;
	int x1;
	int x2;
	int i;
	int n;
	unsigned char *s;
	unsigned char *p1;
	unsigned char *p2;
	mbedtls_camellia_context enc;
	unsigned char wrk[6][16];

	if(klen&7)goto err1;
	mbedtls_camellia_init(&enc);
	if(mbedtls_camellia_setkey_enc(&enc,key,klen))goto err2;
	memset(wrk,0,sizeof(wrk));
	if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
		wrk[1],wrk[1]))goto err3;
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
				if(mbedtls_camellia_crypt_ecb(&enc,
					MBEDTLS_CAMELLIA_ENCRYPT,wrk[0],wrk[0]))
					goto err3;
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
		if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
			wrk[0],wrk[0]))goto err3;
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
	if(mbedtls_camellia_crypt_ecb(&enc,MBEDTLS_CAMELLIA_ENCRYPT,
		wrk[0],dst))goto err3;
	r=0;
err3:	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
err2:	mbedtls_camellia_free(&enc);
err1:	return r;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int mbed_camellia_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen&0xf)return -1;
	for(;slen;s+=16,d+=16,slen-=16)if(mbedtls_camellia_crypt_ecb(
		&((struct mbed_camellia_ecb *)ctx)->enc,
		MBEDTLS_CAMELLIA_ENCRYPT,s,d))return -1;
	return 0;
}

static int mbed_camellia_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen&0xf)return -1;
	for(;slen;s+=16,d+=16,slen-=16)if(mbedtls_camellia_crypt_ecb(
		&((struct mbed_camellia_ecb *)ctx)->dec,
		MBEDTLS_CAMELLIA_DECRYPT,s,d))return -1;
	return 0;
}

static void *mbed_camellia_ecb_init(void *ctx,void *key,int klen)
{
	struct mbed_camellia_ecb *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_ecb))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	mbedtls_camellia_init(&camellia->dec);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	if(mbedtls_camellia_setkey_dec(&camellia->dec,key,klen))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	mbedtls_camellia_free(&camellia->dec);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_ecb_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_ecb *)ctx)->enc);
	mbedtls_camellia_free(&((struct mbed_camellia_ecb *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int mbed_camellia_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(mbedtls_camellia_crypt_cbc(&((struct mbed_camellia_cbc *)ctx)->enc,
		MBEDTLS_CAMELLIA_ENCRYPT,slen,
		((struct mbed_camellia_cbc *)ctx)->iv,src,dst))return -1;
	return 0;
}

static int mbed_camellia_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(slen&0xf)return -1;
	if(mbedtls_camellia_crypt_cbc(&((struct mbed_camellia_cbc *)ctx)->dec,
		MBEDTLS_CAMELLIA_DECRYPT,slen,
		((struct mbed_camellia_cbc *)ctx)->iv,src,dst))return -1;
	return 0;
}

static void *mbed_camellia_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_cbc *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_cbc))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	mbedtls_camellia_init(&camellia->dec);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	if(mbedtls_camellia_setkey_dec(&camellia->dec,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	mbedtls_camellia_free(&camellia->dec);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_camellia_cbc *)ctx)->iv,iv,16);
}

static void mbed_camellia_cbc_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_cbc *)ctx)->enc);
	mbedtls_camellia_free(&((struct mbed_camellia_cbc *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int mbed_camellia_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct mbed_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<=16)return -1;
	rem=slen&0xf;
	if(!rem)rem=16;
	if(mbedtls_camellia_crypt_cbc(&camellia->enc,MBEDTLS_CAMELLIA_ENCRYPT,
		slen-rem,camellia->iv,s,d))return -1;
	s+=slen-rem;
	d+=slen-rem;
	memcpy(camellia->tmp,s,rem);
	if(rem<16)memset(camellia->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	if(mbedtls_camellia_crypt_cbc(&camellia->enc,MBEDTLS_CAMELLIA_ENCRYPT,
		16,camellia->iv,camellia->tmp,d-16))return -1;
	return 0;
}

static int mbed_camellia_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct mbed_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<=16)return -1;
	rem=slen&0xf;
	if(!rem)rem=16;
	if(slen-rem-16)
	{
		if(mbedtls_camellia_crypt_cbc(&camellia->dec,
			MBEDTLS_CAMELLIA_DECRYPT,slen-rem-16,camellia->iv,s,d))
			return -1;
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(camellia->tmp+16,s,16);
	if(mbedtls_camellia_crypt_ecb(&camellia->dec,MBEDTLS_CAMELLIA_DECRYPT,
		s,camellia->tmp))return -1;
	memcpy(camellia->tmp,s+16,rem);
	if(mbedtls_camellia_crypt_cbc(&camellia->dec,MBEDTLS_CAMELLIA_DECRYPT,
		32,camellia->iv,camellia->tmp,camellia->tmp))return -1;
	memcpy(d,camellia->tmp,rem+16);
	return 0;
}

static void *mbed_camellia_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_cts *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_cts))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_camellia_init(&camellia->enc);
	mbedtls_camellia_init(&camellia->dec);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	if(mbedtls_camellia_setkey_dec(&camellia->dec,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	mbedtls_camellia_free(&camellia->dec);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_camellia_cts *)ctx)->iv,iv,16);
}

static void mbed_camellia_cts_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_cts *)ctx)->enc);
	mbedtls_camellia_free(&((struct mbed_camellia_cts *)ctx)->dec);
	((struct mbed_camellia_cts *)ctx)->global->
		memclear(((struct mbed_camellia_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int mbed_camellia_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_camellia_crypt_cfb128(
		&((struct mbed_camellia_cfb *)ctx)->enc,
		MBEDTLS_CAMELLIA_ENCRYPT,slen,
		&((struct mbed_camellia_cfb *)ctx)->off,
		((struct mbed_camellia_cfb *)ctx)->iv,src,dst))return -1;
	return 0;
}

static int mbed_camellia_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(mbedtls_camellia_crypt_cfb128(
		&((struct mbed_camellia_cfb *)ctx)->enc,
		MBEDTLS_CAMELLIA_DECRYPT,slen,
		&((struct mbed_camellia_cfb *)ctx)->off,
		((struct mbed_camellia_cfb *)ctx)->iv,src,dst))return -1;
	return 0;
}

static void *mbed_camellia_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_cfb *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_cfb))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	camellia->off=0;
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_cfb_reset(void *ctx,void *iv)
{
	((struct mbed_camellia_cfb *)ctx)->off=0;
	memcpy(((struct mbed_camellia_cfb *)ctx)->iv,iv,16);
}

static void mbed_camellia_cfb_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_cfb *)ctx)->enc);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int mbed_camellia_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct mbed_camellia_cfb8 *camellia=ctx;

	while(slen--)
	{
		if(mbedtls_camellia_crypt_ecb(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,camellia->iv,camellia->mem))
			return -1;
		memmove(camellia->iv,camellia->iv+1,15);
		*d++=camellia->iv[15]=*s++^camellia->mem[0];
	}
	return 0;
}

static int mbed_camellia_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct mbed_camellia_cfb8 *camellia=ctx;

	while(slen--)
	{
		if(mbedtls_camellia_crypt_ecb(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,camellia->iv,camellia->mem))
			return -1;
		memmove(camellia->iv,camellia->iv+1,15);
		camellia->iv[15]=*s;
		*d++=*s++^camellia->mem[0];
	}
	return 0;
}

static void *mbed_camellia_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_cfb8 *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_cfb8))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_camellia_init(&camellia->enc);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct mbed_camellia_cfb8 *)ctx)->iv,iv,16);
}

static void mbed_camellia_cfb8_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_cfb8 *)ctx)->enc);
	((struct mbed_camellia_cfb8 *)ctx)->global->
		memclear(((struct mbed_camellia_cfb8 *)ctx)->iv,16);
	((struct mbed_camellia_cfb8 *)ctx)->global->
		memclear(((struct mbed_camellia_cfb8 *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int mbed_camellia_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct mbed_camellia_ofb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!camellia->n)if(mbedtls_camellia_crypt_cbc(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,16,camellia->iv,
			camellia->zero,camellia->iv))return -1;
		*d++=camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!camellia->n)if(mbedtls_camellia_crypt_cbc(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,16,camellia->iv,
			camellia->zero,camellia->iv))return -1;
		*d++=*s++^camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static void *mbed_camellia_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_ofb *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_ofb))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	memset(camellia->zero,0,16);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_ofb_reset(void *ctx,void *iv)
{
	((struct mbed_camellia_ofb *)ctx)->n=0;
	memcpy(((struct mbed_camellia_ofb *)ctx)->iv,iv,16);
}

static void mbed_camellia_ofb_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_ofb *)ctx)->enc);
	((struct mbed_camellia_ofb *)ctx)->global->
		memclear(((struct mbed_camellia_ofb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int mbed_camellia_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct mbed_camellia_ctr *camellia=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			if(mbedtls_camellia_crypt_ctr(
				&camellia->enc,16,&camellia->off,camellia->iv,
				camellia->bfr,camellia->zero,dst))return -1;
		if(mbedtls_camellia_crypt_ctr(&camellia->enc,slen,
			&camellia->off,camellia->iv,camellia->bfr,
			camellia->zero,dst))return -1;
	}
	else if(mbedtls_camellia_crypt_ctr(&camellia->enc,slen,&camellia->off,
		camellia->iv,camellia->bfr,src,dst))return -1;
	return 0;
}

static void *mbed_camellia_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct mbed_camellia_ctr *camellia;

	if(!(camellia=malloc(sizeof(struct mbed_camellia_ctr))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->off=0;
	memset(camellia->zero,0,16);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	memcpy(camellia->iv,iv,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_ctr_reset(void *ctx,void *iv)
{
	((struct mbed_camellia_ctr *)ctx)->off=0;
	memcpy(((struct mbed_camellia_ctr *)ctx)->iv,iv,16);
}

static void mbed_camellia_ctr_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_ctr *)ctx)->enc);
	((struct mbed_camellia_ctr *)ctx)->global->
		memclear(((struct mbed_camellia_ctr *)ctx)->bfr,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int mbed_camellia_xts_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct mbed_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(mbedtls_camellia_crypt_ecb(&camellia->twe,MBEDTLS_CAMELLIA_ENCRYPT,
		iv,camellia->twk))return -1;

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		if(mbedtls_camellia_crypt_ecb(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,camellia->wrk,d))return -1;
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
		if(mbedtls_camellia_crypt_ecb(&camellia->enc,
			MBEDTLS_CAMELLIA_ENCRYPT,camellia->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
	}

	return 0;
}

static int mbed_camellia_xts_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct mbed_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(slen<16)return -1;

	if(mbedtls_camellia_crypt_ecb(&camellia->twe,MBEDTLS_CAMELLIA_ENCRYPT,
		iv,camellia->twk))return -1;

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		if(mbedtls_camellia_crypt_ecb(&camellia->dec,
			MBEDTLS_CAMELLIA_DECRYPT,camellia->wrk,d))return -1;
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
		if(mbedtls_camellia_crypt_ecb(&camellia->dec,
			MBEDTLS_CAMELLIA_DECRYPT,camellia->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
		memcpy(d+16,d,slen);
		memcpy(camellia->wrk,s+16,slen);
		memcpy(camellia->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)camellia->wrk[i]^=camellia->mem[i];
		if(mbedtls_camellia_crypt_ecb(&camellia->dec,
			MBEDTLS_CAMELLIA_DECRYPT,camellia->wrk,d))return -1;
		for(i=0;i<16;i++)d[i]^=camellia->mem[i];
	}

	return 0;
}

static void *mbed_camellia_xts_init(void *ctx,void *key,int klen)
{
	struct mbed_camellia_xts *camellia;

	if(klen!=256&&klen!=512)goto err1;
	if(!(camellia=malloc(sizeof(struct mbed_camellia_xts))))goto err1;
	mbedtls_camellia_init(&camellia->enc);
	mbedtls_camellia_init(&camellia->dec);
	mbedtls_camellia_init(&camellia->twe);
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen>>1))goto err2;
	if(mbedtls_camellia_setkey_dec(&camellia->dec,key,klen>>1))goto err2;
	if(mbedtls_camellia_setkey_enc(&camellia->twe,key+(klen>>4),klen>>1))
			goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	mbedtls_camellia_free(&camellia->enc);
	mbedtls_camellia_free(&camellia->dec);
	mbedtls_camellia_free(&camellia->twe);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_xts_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_xts *)ctx)->enc);
	mbedtls_camellia_free(&((struct mbed_camellia_xts *)ctx)->dec);
	mbedtls_camellia_free(&((struct mbed_camellia_xts *)ctx)->twe);
	((struct mbed_camellia_xts *)ctx)->global->
		memclear(((struct mbed_camellia_xts *)ctx)->twk,16);
	((struct mbed_camellia_xts *)ctx)->global->
		memclear(((struct mbed_camellia_xts *)ctx)->wrk,16);
	((struct mbed_camellia_xts *)ctx)->global->
		memclear(((struct mbed_camellia_xts *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int mbed_camellia_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct mbed_camellia_essiv *camellia=ctx;

	if(slen&0xf)return -1;
	if(mbedtls_camellia_crypt_ecb(&camellia->aux,MBEDTLS_CAMELLIA_ENCRYPT,
		iv,camellia->iv))return -1;
	if(mbedtls_camellia_crypt_cbc(&camellia->enc,MBEDTLS_CAMELLIA_ENCRYPT,
		slen,camellia->iv,src,dst))return -1;
	return 0;
}

static int mbed_camellia_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct mbed_camellia_essiv *camellia=ctx;

	if(slen&0xf)return -1;
	if(mbedtls_camellia_crypt_ecb(&camellia->aux,MBEDTLS_CAMELLIA_ENCRYPT,
		iv,camellia->iv))return -1;
	if(mbedtls_camellia_crypt_cbc(&camellia->dec,MBEDTLS_CAMELLIA_DECRYPT,
		slen,camellia->iv,src,dst))return -1;
	return 0;
}

static void *mbed_camellia_essiv_init(void *ctx,void *key,int klen)
{
	struct mbed_camellia_essiv *camellia;
	unsigned char tmp[32];

	if(!(camellia=malloc(sizeof(struct mbed_camellia_essiv))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	mbedtls_camellia_init(&camellia->enc);
	mbedtls_camellia_init(&camellia->dec);
	mbedtls_camellia_init(&camellia->aux);
	if(mbedtls_camellia_setkey_enc(&camellia->enc,key,klen))goto err2;
	if(mbedtls_camellia_setkey_dec(&camellia->dec,key,klen))goto err2;
	if(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),key,klen>>3,
		tmp))goto err2;
	if(mbedtls_camellia_setkey_enc(&camellia->aux,tmp,256))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
err2:	mbedtls_camellia_free(&camellia->aux);
	mbedtls_camellia_free(&camellia->enc);
	mbedtls_camellia_free(&camellia->dec);
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void mbed_camellia_essiv_exit(void *ctx)
{
	mbedtls_camellia_free(&((struct mbed_camellia_essiv *)ctx)->enc);
	mbedtls_camellia_free(&((struct mbed_camellia_essiv *)ctx)->dec);
	mbedtls_camellia_free(&((struct mbed_camellia_essiv *)ctx)->aux);
	((struct mbed_camellia_essiv *)ctx)->global->memclear(
		((struct mbed_camellia_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#endif

int USICRYPT(random)(void *ctx,void *data,int len)
{
	if(mbedtls_hmac_drbg_random(&((struct usicrypt_thread *)ctx)->rng,
		data,len))return -1;
	return 0;
}

int USICRYPT(digest_size)(void *ctx,int md)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return mbedtls_md_get_size(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA1));
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return mbedtls_md_get_size(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return mbedtls_md_get_size(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA384));
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return mbedtls_md_get_size(
			mbedtls_md_info_from_type(MBEDTLS_MD_SHA512));
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
		return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
			in,len,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
			in,len,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA384),
			in,len,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
			in,len,out)?-1:0;
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
	mbedtls_md_context_t c;

	switch(md)
	{
#if !defined(USICRYPT_NO_DIGEST) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=MBEDTLS_MD_SHA512;
		break;
#endif
#endif
	default:return -1;
	}

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(digest),0))goto err1;
	if(mbedtls_md_starts(&c))goto err1;
	for(i=0;i<niov;i++)if(mbedtls_md_update(&c,iov[i].data,iov[i].length))
		goto err1;
	if(mbedtls_md_finish(&c,out))goto err1;
	r=0;
err1:	mbedtls_md_free(&c);
	return r;
}

int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,int klen,
	void *out)
{
	switch(md)
	{
#ifndef USICRYPT_NO_HMAC
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return mbedtls_md_hmac(mbedtls_md_info_from_type(
			MBEDTLS_MD_SHA1),key,klen,data,dlen,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return mbedtls_md_hmac(mbedtls_md_info_from_type(
			MBEDTLS_MD_SHA256),key,klen,data,dlen,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return mbedtls_md_hmac(mbedtls_md_info_from_type(
			MBEDTLS_MD_SHA384),key,klen,data,dlen,out)?-1:0;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return mbedtls_md_hmac(mbedtls_md_info_from_type(
			MBEDTLS_MD_SHA512),key,klen,data,dlen,out)?-1:0;
#endif
#endif
	default:return -1;
	}
}

int USICRYPT(hmac_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *key,int klen,void *out)
{
	int r=-1;
	int i;
	int digest;
	mbedtls_md_context_t c;

	switch(md)
	{
#if !defined(USICRYPT_NO_HMAC) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=MBEDTLS_MD_SHA512;
		break;
#endif
#endif
	default:return -1;
	}

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(digest),1))goto err1;
	if(mbedtls_md_hmac_starts(&c,key,klen))goto err1;
	for(i=0;i<niov;i++)if(mbedtls_md_hmac_update(&c,iov[i].data,
		iov[i].length))goto err1;
	if(mbedtls_md_hmac_finish(&c,out))goto err1;
	r=0;
err1:	mbedtls_md_free(&c);
	return r;
}

int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	int iter,void *out)
{
	int r=-1;
#ifndef USICRYPT_NO_PBKDF2
	int type;
	mbedtls_md_context_t c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),1))goto err2;
	if(mbedtls_pkcs5_pbkdf2_hmac(&c,key,klen,salt,slen,iter,
		mbedtls_md_get_size(mbedtls_md_info_from_type(type)),out))
		goto err2;
	r=0;
err2:	mbedtls_md_free(&c);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#else
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#endif
	return r;
}

int USICRYPT(hkdf)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	void *info,int ilen,void *out)
{
#ifndef USICRYPT_NO_HKDF
	int type;
	mbedtls_md_context_t c;
	unsigned char s[MBEDTLS_MD_MAX_SIZE];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	mbedtls_md_init(&c);
	if(mbedtls_md_setup(&c,mbedtls_md_info_from_type(type),1))goto err2;
	if(!salt||!slen)
	{
		slen=mbedtls_md_get_size(mbedtls_md_info_from_type(type));
		salt=s;
		memset(s,0,slen);
	}
	if(mbedtls_md_hmac(mbedtls_md_info_from_type(type),salt,slen,key,klen,
		out))goto err2;
	if(mbedtls_md_hmac_starts(&c,out,mbedtls_md_get_size(
		mbedtls_md_info_from_type(type))))goto err2;
	if(mbedtls_md_hmac_update(&c,info,ilen))goto err2;
	s[0]=1;
	if(mbedtls_md_hmac_update(&c,s,1))goto err2;
	if(mbedtls_md_hmac_finish(&c,out))goto err2;
	mbedtls_md_free(&c);
	return 0;

err2:	mbedtls_md_free(&c);
err1:	return -1;
#else
	return -1;
#endif
}

void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	size_t len;
	unsigned char *out;

	if(mbedtls_base64_encode(NULL,0,&len,in,ilen)
		!=MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)goto err1;
	if(!(out=malloc(len)))goto err1;
	if(mbedtls_base64_encode(out,len,&len,in,ilen))goto err2;
	*olen=len;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	size_t len;
	unsigned char *out;

	if(mbedtls_base64_decode(NULL,0,&len,in,ilen)
		!=MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)goto err1;
	if(!(out=malloc(len)))goto err1;
	if(mbedtls_base64_decode(out,len,&len,in,ilen))goto err2;
	*olen=len;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_generate)(void *ctx,int bits)
{
#ifndef USICRYPT_NO_RSA
	mbedtls_pk_context *key;

	if(bits<USICRYPT_RSA_BITS_MIN||bits>USICRYPT_RSA_BITS_MAX||(bits&7))
		goto err1;
	if(mbed_reseed(ctx))goto err1;
	if(!(key=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(key);
	if(mbedtls_pk_setup(key,mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
		goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*key),MBEDTLS_RSA_PKCS_V21,
		MBEDTLS_MD_SHA256);
	if(mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		bits,USICRYPT_RSA_EXPONENT))goto err2;
	return key;

err2:	mbedtls_pk_free(key);
	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(rsa_size)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	size_t n;

	if((n=mbedtls_pk_get_bitlen((mbedtls_pk_context *)key))<=0)return -1;
	return n;
#else
	return -1;
#endif
}

void *USICRYPT(rsa_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_RSA
	int l;
	unsigned char *key;
	unsigned char bfr[8192];

	if((l=mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)k,bfr,
		sizeof(bfr)))<=0)goto err1;
	if(!(key=malloc(l)))goto err2;
	memcpy(key,bfr+sizeof(bfr)-l,l);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
	*len=l;
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	size_t n;
	mbedtls_pk_context *k;

	if(!(k=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(k);
	if(mbedtls_pk_parse_public_key(k,key,len))goto err2;
	if(mbedtls_pk_get_type(k)!=MBEDTLS_PK_RSA)goto err2;
	if((n=mbedtls_pk_get_bitlen(k))<USICRYPT_RSA_BITS_MIN||
		n>USICRYPT_RSA_BITS_MAX)goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*k),MBEDTLS_RSA_PKCS_V21,
		MBEDTLS_MD_SHA256);
	return k;

err2:	mbedtls_pk_free(k);
	free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_RSA
	int l;
	unsigned char *key=NULL;
	unsigned char bfr[8192];

	if((l=mbedtls_pk_write_key_der((mbedtls_pk_context *)k,bfr,
		sizeof(bfr)))<=0)goto err1;
	if(!(key=malloc(l)))goto err2;
	memcpy(key,bfr+sizeof(bfr)-l,l);
	*len=l;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
err1:	return key;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	size_t n;
	mbedtls_pk_context *k;

	if(!(k=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(k);
	if(mbedtls_pk_parse_key(k,key,len,NULL,0))goto err2;
	if(mbedtls_pk_get_type(k)!=MBEDTLS_PK_RSA)goto err2;
	if((n=mbedtls_pk_get_bitlen(k))<USICRYPT_RSA_BITS_MIN||
		n>USICRYPT_RSA_BITS_MAX)goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*k),MBEDTLS_RSA_PKCS_V21,
		MBEDTLS_MD_SHA256);
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return k;

err2:	mbedtls_pk_free(k);
	free(k);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return mbed_rsa_do_sign_v15(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return mbed_rsa_do_sign_v15(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return mbed_rsa_do_verify_v15(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return mbed_rsa_do_verify_v15(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return mbed_rsa_do_sign_pss(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return mbed_rsa_do_sign_pss(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return mbed_rsa_do_verify_pss(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return mbed_rsa_do_verify_pss(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	unsigned char *out;

	if(mbed_reseed(ctx))goto err1;
	*olen=mbedtls_pk_get_len(key);
	if(dlen>*olen-11)goto err1;
	if(!(out=malloc(*olen)))goto err1;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
	if(mbedtls_rsa_rsaes_pkcs1_v15_encrypt(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PUBLIC,dlen,data,out))goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	size_t l;
	size_t len;
	unsigned char *out;

	if(mbed_reseed(ctx))goto err1;
	len=mbedtls_pk_get_len(key);
	if(dlen!=len)goto err1;
	if(!(out=malloc(len)))goto err1;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V15,MBEDTLS_MD_NONE);
	if(mbedtls_rsa_rsaes_pkcs1_v15_decrypt(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PRIVATE,&l,data,out,len))goto err2;
	out=USICRYPT(do_realloc)(ctx,out,len,l);
	*olen=l;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_encrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int type;
	unsigned char *out;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(mbed_reseed(ctx))goto err1;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,type);
	*olen=mbedtls_pk_get_len(key);
	if(dlen>*olen-2*mbedtls_md_get_size(
		mbedtls_md_info_from_type(type))-2)goto err1;
	if(!(out=malloc(*olen)))goto err1;
	if(mbedtls_rsa_rsaes_oaep_encrypt(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PUBLIC,NULL,0,dlen,data,out))goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
err1:	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
#endif
	return NULL;
}

void *USICRYPT(rsa_decrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int type;
	size_t l;
	size_t len;
	unsigned char *out;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=MBEDTLS_MD_SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=MBEDTLS_MD_SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=MBEDTLS_MD_SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=MBEDTLS_MD_SHA512;
		break;
#endif
	default:goto err1;
	}

	if(mbed_reseed(ctx))goto err1;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,type);
	len=mbedtls_pk_get_len(key);
	if(dlen!=len)goto err1;
	if(!(out=malloc(len)))goto err1;
	if(mbedtls_rsa_rsaes_oaep_decrypt(
		mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		mbedtls_hmac_drbg_random,&((struct usicrypt_thread *)ctx)->rng,
		MBEDTLS_RSA_PRIVATE,NULL,0,&l,data,out,len))goto err2;
	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
	out=USICRYPT(do_realloc)(ctx,out,len,l);
	*olen=l;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
err1:	mbedtls_rsa_set_padding(mbedtls_pk_rsa(*((mbedtls_pk_context *)key)),
		MBEDTLS_RSA_PKCS_V21,MBEDTLS_MD_SHA256);
#endif
	return NULL;
}

void USICRYPT(rsa_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	mbedtls_pk_free((mbedtls_pk_context *)key);
	free(key);
#endif
}

void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len)
{
#ifndef USICRYPT_NO_DH
	int l;
	int n;
	mbedtls_mpi p;
	mbedtls_mpi_uint r;
	unsigned char *bfr;
	unsigned char *data;
	unsigned char *ptr;

	if(bits<USICRYPT_DH_BITS_MIN||bits>USICRYPT_DH_BITS_MAX||
		(bits&7)||(generator!=2&&generator!=5))goto err1;
	if(mbed_reseed(ctx))goto err1;
	mbedtls_mpi_init(&p);
	while(1)
	{
		if(mbedtls_mpi_gen_prime(&p,bits,1,mbedtls_hmac_drbg_random,
			&((struct usicrypt_thread *)ctx)->rng))goto err2;
		switch(generator)
		{
		case 2:	if(mbedtls_mpi_mod_int(&r,&p,24))goto err2;
			if(r!=11)continue;
			break;

		case 3:	if(mbedtls_mpi_mod_int(&r,&p,12))goto err2;
			if(r!=5)continue;
			break;

		case 5:	if(mbedtls_mpi_mod_int(&r,&p,10))goto err2;
			if(r!=3&&r!=7)continue;
			break;
		}
		break;
	}
	l=mbedtls_mpi_size(&p);
	if(!(bfr=malloc(l)))goto err2;
	if(mbedtls_mpi_write_binary(&p,bfr,l))goto err3;

	n=l+((*bfr&0x80)?1:0);
	if(n>=0x100)n+=7;
	else if(n>=0x80)n+=6;
	else n+=5;
	if(n>=0x100)n+=4;
	else if(n>=0x80)n+=3;
	else n+=2;
	*len=n;
	if(!(ptr=data=malloc(n)))goto err3;

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
	mbedtls_mpi_free(&p);

	return data;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,l);
	free(bfr);
err2:	mbedtls_mpi_free(&p);
err1:	return NULL;
#else   
	return NULL;
#endif
}

void *USICRYPT(dh_init)(void *ctx,void *params,int len)
{
#ifndef USICRYPT_NO_DH
	mbedtls_dhm_context *dh;

	if(!(dh=malloc(sizeof(mbedtls_dhm_context))))goto err1;
	mbedtls_dhm_init(dh);
	if(mbedtls_dhm_parse_dhm(dh,params,len))goto err2;
	if(dh->len<USICRYPT_DH_BYTES_MIN||dh->len>USICRYPT_DH_BYTES_MAX)
		goto err2;
	return dh;

err2:	mbedtls_dhm_free(dh);
	free(dh);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len)
{
#ifndef USICRYPT_NO_DH
	int l;
	unsigned char *pub;

	if(mbed_reseed(ctx))goto err1;
	*len=((mbedtls_dhm_context *)dh)->len;
	if(!(pub=malloc(*len)))goto err1;
	if(mbedtls_dhm_make_public(dh,*len,pub,*len,mbedtls_hmac_drbg_random,
		&((struct usicrypt_thread *)ctx)->rng))goto err2;
	for(l=0;l<*len;l++)if(pub[l])break;
	if(l)
	{
		memmove(pub,pub+l,*len-l);
		pub=USICRYPT(do_realloc)(ctx,pub,*len,*len-l);
		*len-=l;
	}
	return pub;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(pub,*len);
	free(pub);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,int *slen)
{
#ifndef USICRYPT_NO_DH
	size_t len;
	unsigned char *sec;

	if(mbedtls_dhm_read_public(dh,pub,plen))goto err1;
	len=((mbedtls_dhm_context *)dh)->len;
	if(!(sec=malloc(len)))goto err1;
	if(mbedtls_dhm_calc_secret(dh,sec,len,&len,mbedtls_hmac_drbg_random,
		&((struct usicrypt_thread *)ctx)->rng))goto err2;
	*slen=len;
	return sec;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(sec,len);
	free(sec);
err1:	return NULL;
#else
	return NULL;
#endif
}

void USICRYPT(dh_free)(void *ctx,void *dh)
{
#ifndef USICRYPT_NO_DH
	mbedtls_dhm_free(dh);
	free(dh);
#endif
}

void *USICRYPT(ec_generate)(void *ctx,int curve)
{
#ifndef USICRYPT_NO_EC
	mbedtls_pk_context *key;

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
	curve=mbed_ec_map[curve];
	if(mbed_reseed(ctx))goto err1;
	if(!(key=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(key);
	if(mbedtls_pk_setup(key,mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
		goto err2;
	if(mbedtls_ecp_gen_key(curve,mbedtls_pk_ec(*key),
		mbedtls_hmac_drbg_random,
		&((struct usicrypt_thread *)ctx)->rng))goto err2;
	return key;

err2:	mbedtls_pk_free(key);
	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ec_identifier)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	switch(mbedtls_pk_ec(*((mbedtls_pk_context *)key))->grp.id)
	{
	case MBEDTLS_ECP_DP_BP512R1:
		return USICRYPT_BRAINPOOLP512R1;
	case MBEDTLS_ECP_DP_BP384R1:
		return USICRYPT_BRAINPOOLP384R1;
	case MBEDTLS_ECP_DP_BP256R1:
		return USICRYPT_BRAINPOOLP256R1;
	case MBEDTLS_ECP_DP_SECP521R1:
		return USICRYPT_SECP521R1;
	case MBEDTLS_ECP_DP_SECP384R1:
		return USICRYPT_SECP384R1;
	case MBEDTLS_ECP_DP_SECP256R1:
		return USICRYPT_SECP256R1;
	default:return -1;
	}
#else
	return -1;
#endif
}

void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_EC
	size_t len;
	unsigned char *sec;
	mbedtls_ecdh_context ecdh;
	unsigned char bfr[1024];

	mbedtls_ecdh_init(&ecdh);
	if(mbedtls_ecdh_get_params(&ecdh,
		mbedtls_pk_ec(*((mbedtls_pk_context *)key)),
		MBEDTLS_ECDH_OURS))goto err1;
	if(mbedtls_ecdh_get_params(&ecdh,
		mbedtls_pk_ec(*((mbedtls_pk_context *)pub)),
		MBEDTLS_ECDH_THEIRS))goto err1;
	if(mbedtls_ecdh_calc_secret(&ecdh,&len,bfr,sizeof(bfr),NULL,NULL))
		goto err1;
	*klen=len;
	if(!(sec=malloc(*klen)))goto err2;
	memcpy(sec,bfr,len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,len);
	mbedtls_ecdh_free(&ecdh);
	return sec;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,len);
err1:	mbedtls_ecdh_free(&ecdh);
#endif
	return NULL;
}

void *USICRYPT(ec_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	int l;
	unsigned char *key;
	unsigned char bfr[1024];

	if((l=mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)k,bfr,
		sizeof(bfr)))<=0)goto err1;
	if(!(key=malloc(l)))goto err2;
	memcpy(key,bfr+sizeof(bfr)-l,l);
	*len=l;
	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	mbedtls_pk_context *k;

	if(!(k=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(k);
	if(mbedtls_pk_parse_public_key(k,key,len))goto err2;
	if(mbedtls_pk_get_type(k)!=MBEDTLS_PK_ECKEY)goto err2;
	return k;

err2:	mbedtls_pk_free(k);
	free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	int l;
	unsigned char *key=NULL;
	unsigned char bfr[1024];

	if((l=mbedtls_pk_write_key_der((mbedtls_pk_context *)k,bfr,
		sizeof(bfr)))<=0)goto err1;
	if(!(key=malloc(l)))goto err2;
	memcpy(key,bfr+sizeof(bfr)-l,l);
	*len=l;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr+sizeof(bfr)-l,l);
err1:	return key;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	mbedtls_pk_context *k;

	if(!(k=malloc(sizeof(mbedtls_pk_context))))goto err1;
	mbedtls_pk_init(k);
	if(mbedtls_pk_parse_key(k,key,len,NULL,0))goto err2;
	if(mbedtls_pk_get_type(k)!=MBEDTLS_PK_ECKEY)goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return k;

err2:	mbedtls_pk_free(k);
	free(k);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_EC
	return mbed_ec_do_sign(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return mbed_ec_do_sign(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_EC
	return mbed_ec_do_verify(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return mbed_ec_do_verify(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void USICRYPT(ec_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	mbedtls_pk_free((mbedtls_pk_context *)key);
	free(key);
#endif
}

void *USICRYPT(x25519_generate)(void *ctx)
{
	return NULL;
}

void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen)
{
	return NULL;
}

void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len)
{
	return NULL;
}

void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len)
{
	return NULL;
}

void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len)
{
	return NULL;
}

void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len)
{
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return NULL;
}

void USICRYPT(x25519_free)(void *ctx,void *key)
{
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

	if(mbed_asn_next(data,dlen,0x30,&cidx,&didx))goto err1;
	if(cidx+didx!=dlen)goto err1;

	for(didx=0;didx<4;didx++)if(mbed_digest_asn[didx].oidlen&&
		mbed_digest_asn[didx].digest==digest)break;
	if(didx==4)goto err1;

	for(cidx=0;cidx<24;cidx++)if(mbed_cipher_asn[cidx].oidlen&&
		mbed_cipher_asn[cidx].cipher==cipher&&
		mbed_cipher_asn[cidx].mode==mode&&
		mbed_cipher_asn[cidx].bits==bits)break;
	if(cidx==24)goto err1;

	if(USICRYPT(random)(ctx,salt,8))goto err1;
	if(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,8,iter,bfr))goto err2;

	if(mbed_cipher_asn[cidx].ivlen)
		if(USICRYPT(random)(ctx,iv,mbed_cipher_asn[cidx].ivlen))
			goto err3;

	if(!(c=USICRYPT(blkcipher_init)(ctx,cipher,mode,bfr,bits,iv)))goto err4;

	if(iter>=0x800000)ilen=4;
	else if(iter>=0x8000)ilen=3;
	else if(iter>=0x80)ilen=2;
	else ilen=1;

	if(mbed_cipher_asn[cidx].pad)
		plen=usicrypt_cipher_padding_add(ctx,NULL,dlen);
	else plen=0;
	len1=mbed_asn_length(NULL,dlen+plen)+1;
	len2=mbed_cipher_asn[cidx].oidlen+mbed_cipher_asn[cidx].ivlen+6;
	len3=ilen+sizeof(mbed_pbes2_oid)+sizeof(mbed_pbkdf2_oid)+24;
	if(digest!=USICRYPT_SHA1)len3+=mbed_digest_asn[didx].oidlen+6;
	*rlen=mbed_asn_length(NULL,len1+len2+len3+dlen+plen)+
		len1+len2+len3+dlen+plen+1;

	if(!(ptr=out=malloc(*rlen)))goto err5;

	*ptr++=0x30;
	ptr+=mbed_asn_length(ptr,len1+len2+len3+dlen+plen);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(mbed_pbes2_oid);
	memcpy(ptr,mbed_pbes2_oid,sizeof(mbed_pbes2_oid));
	ptr+=sizeof(mbed_pbes2_oid);
	len3-=sizeof(mbed_pbes2_oid)+6;
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(mbed_pbkdf2_oid);
	memcpy(ptr,mbed_pbkdf2_oid,sizeof(mbed_pbkdf2_oid));
	ptr+=sizeof(mbed_pbkdf2_oid);
	*ptr++=0x30;
	*ptr++=(unsigned char)
	     (ilen+12+(digest!=USICRYPT_SHA1?mbed_digest_asn[didx].oidlen+6:0));
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
		*ptr++=(unsigned char)(mbed_digest_asn[didx].oidlen+4);
		*ptr++=0x06;
		*ptr++=(unsigned char)mbed_digest_asn[didx].oidlen;
		memcpy(ptr,mbed_digest_asn[didx].oid,
			mbed_digest_asn[didx].oidlen);
		ptr+=mbed_digest_asn[didx].oidlen;
		*ptr++=0x05;
		*ptr++=0x00;
	}
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)mbed_cipher_asn[cidx].oidlen;
	memcpy(ptr,mbed_cipher_asn[cidx].oid,mbed_cipher_asn[cidx].oidlen);
	ptr+=mbed_cipher_asn[cidx].oidlen;
	*ptr++=0x04;
	*ptr++=(unsigned char)mbed_cipher_asn[cidx].ivlen;
	if(mbed_cipher_asn[cidx].ivlen)
	{
		memcpy(ptr,iv,mbed_cipher_asn[cidx].ivlen);
		ptr+=mbed_cipher_asn[cidx].ivlen;
	}
	*ptr++=0x04;
	ptr+=mbed_asn_length(ptr,dlen+plen);
	memcpy(ptr,data,dlen);
	if(mbed_cipher_asn[cidx].pad)usicrypt_cipher_padding_add(ctx,ptr,dlen);

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

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	eptr=data+h+l;
	elen=dlen-h-l;
	data+=h;
	dlen=l;

	if(mbed_asn_next(data,dlen,0x06,&h,&l))goto err1;
	if(l!=sizeof(mbed_pbes2_oid)||memcmp(data+h,mbed_pbes2_oid,l))goto err1;
	data+=h+l;
	dlen-=h+l;

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(mbed_asn_next(data,dlen,0x06,&h,&l))goto err1;
	if(l!=sizeof(mbed_pbkdf2_oid)||memcmp(data+h,mbed_pbkdf2_oid,l))
		goto err1;
	data+=h+l;
	dlen-=h+l;

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;
	mlen=l;

	if(mbed_asn_next(data,dlen,0x04,&h,&l))goto err1;
	salt=data+h;
	slen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(mbed_asn_next(data,dlen,0x02,&h,&l))goto err1;
	if(!l||l>sizeof(int))goto err1;
	iter=data+h;
	ilen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(mlen<0)goto err1;
	else if(mlen)
	{
		if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
		data+=h;
		dlen-=h;

		if(mbed_asn_next(data,dlen,0x06,&h,&l))goto err1;
		md=data+h;
		mlen=l;
		data+=h+l;
		dlen-=h+l;

		if(mbed_asn_next(data,dlen,0x05,&h,&l))goto err1;
		if(l)goto err1;
		data+=h;
		dlen-=h;
	}

	if(mbed_asn_next(data,dlen,0x30,&h,&l))goto err1;
	data+=h;
	dlen-=h;

	if(mbed_asn_next(data,dlen,0x06,&h,&l))goto err1;
	cipher=data+h;
	clen=l;
	data+=h+l;
	dlen-=h+l;

	if(mbed_asn_next(data,dlen,0x04,&h,&l))goto err1;
	iv=data+h;
	ivlen=l;
	data+=h+l;
	dlen-=h+l;
	if(data!=eptr)goto err1;

	if(mbed_asn_next(eptr,elen,0x04,&h,&l))goto err1;
	eptr+=h;
	elen=l;

	for(l=0,h=0;h<ilen;h++)l=(l<<8)|iter[h];
	if(!l)goto err1;

	if(mlen)
	{
		for(h=0;h<4;h++)if(mbed_digest_asn[h].oidlen&&
			mlen==mbed_digest_asn[h].oidlen&&
			!memcmp(md,mbed_digest_asn[h].oid,mlen))break;
		if(h==4)goto err1;
		else digest=mbed_digest_asn[h].digest;
	}

	for(h=0;h<24;h++)if(mbed_cipher_asn[h].oidlen&&
		clen==mbed_cipher_asn[h].oidlen&&
		!memcmp(cipher,mbed_cipher_asn[h].oid,clen))break;
	if(h==24||mbed_cipher_asn[h].ivlen!=ivlen||
		(mbed_cipher_asn[h].bits!=128&&digest==USICRYPT_SHA1))goto err1;

	if(mbed_cipher_asn[h].pad)if(elen&0x0f)goto err1;

	if(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,slen,l,bfr))goto err1;

	if(!(out=malloc(elen)))goto err2;

	if(!(c=USICRYPT(blkcipher_init)(ctx,mbed_cipher_asn[h].cipher,
		mbed_cipher_asn[h].mode,bfr,mbed_cipher_asn[h].bits,iv)))
		goto err3;
	if(USICRYPT(blkcipher_decrypt)(c,eptr,elen,out))goto err5;
	USICRYPT(blkcipher_exit)(c);

	if(mbed_cipher_asn[h].pad)
	{
		if((*rlen=usicrypt_cipher_padding_get(ctx,out,elen))==-1)
			goto err4;
		else *rlen=elen-*rlen;
	}
	else *rlen=elen;

	if(mbed_asn_next(out,*rlen,0x30,&h,&l))goto err4;
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
		return MBEDTLS_AES_BLOCK_SIZE;
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
		return 16;
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
		if(!(c=mbed_aes_ecb_init(ctx,key,klen)))break;
		c->encrypt=mbed_aes_ecb_encrypt;
		c->decrypt=mbed_aes_ecb_decrypt;
		c->reset=NULL;
		c->exit=mbed_aes_ecb_exit;
		break;
		return c;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		if(!(c=mbed_aes_cbc_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_cbc_encrypt;
		c->decrypt=mbed_aes_cbc_decrypt;
		c->reset=mbed_aes_cbc_reset;
		c->exit=mbed_aes_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_AES|USICRYPT_CTS:
		if(!(c=mbed_aes_cts_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_cts_encrypt;
		c->decrypt=mbed_aes_cts_decrypt;
		c->reset=mbed_aes_cts_reset;
		c->exit=mbed_aes_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		if(!(c=mbed_aes_cfb_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_cfb_encrypt;
		c->decrypt=mbed_aes_cfb_decrypt;
		c->reset=mbed_aes_cfb_reset;
		c->exit=mbed_aes_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_AES|USICRYPT_CFB8:
		if(!(c=mbed_aes_cfb8_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_cfb8_encrypt;
		c->decrypt=mbed_aes_cfb8_decrypt;
		c->reset=mbed_aes_cfb8_reset;
		c->exit=mbed_aes_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		if(!(c=mbed_aes_ofb_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_ofb_crypt;
		c->decrypt=mbed_aes_ofb_crypt;
		c->reset=mbed_aes_ofb_reset;
		c->exit=mbed_aes_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_AES|USICRYPT_CTR:
		if(!(c=mbed_aes_ctr_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_aes_ctr_crypt;
		c->decrypt=mbed_aes_ctr_crypt;
		c->reset=mbed_aes_ctr_reset;
		c->exit=mbed_aes_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		if(!(c=mbed_camellia_ecb_init(ctx,key,klen)))break;
		c->encrypt=mbed_camellia_ecb_encrypt;
		c->decrypt=mbed_camellia_ecb_decrypt;
		c->reset=NULL;
		c->exit=mbed_camellia_ecb_exit;
		break;
		return c;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		if(!(c=mbed_camellia_cbc_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_cbc_encrypt;
		c->decrypt=mbed_camellia_cbc_decrypt;
		c->reset=mbed_camellia_cbc_reset;
		c->exit=mbed_camellia_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_CAMELLIA|USICRYPT_CTS:
		if(!(c=mbed_camellia_cts_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_cts_encrypt;
		c->decrypt=mbed_camellia_cts_decrypt;
		c->reset=mbed_camellia_cts_reset;
		c->exit=mbed_camellia_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		if(!(c=mbed_camellia_cfb_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_cfb_encrypt;
		c->decrypt=mbed_camellia_cfb_decrypt;
		c->reset=mbed_camellia_cfb_reset;
		c->exit=mbed_camellia_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_CAMELLIA|USICRYPT_CFB8:
		if(!(c=mbed_camellia_cfb8_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_cfb8_encrypt;
		c->decrypt=mbed_camellia_cfb8_decrypt;
		c->reset=mbed_camellia_cfb8_reset;
		c->exit=mbed_camellia_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		if(!(c=mbed_camellia_ofb_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_ofb_crypt;
		c->decrypt=mbed_camellia_ofb_crypt;
		c->reset=mbed_camellia_ofb_reset;
		c->exit=mbed_camellia_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_CAMELLIA|USICRYPT_CTR:
		if(!(c=mbed_camellia_ctr_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_camellia_ctr_crypt;
		c->decrypt=mbed_camellia_ctr_crypt;
		c->reset=mbed_camellia_ctr_reset;
		c->exit=mbed_camellia_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20|USICRYPT_STREAM:
		if(!(c=mbed_chacha_init(ctx,key,klen,iv)))break;
		c->encrypt=mbed_chacha_crypt;
		c->decrypt=mbed_chacha_crypt;
		c->reset=mbed_chacha_reset;
		c->exit=mbed_chacha_exit;
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
		if(!(c=mbed_aes_xts_init(ctx,key,klen)))break;
		c->encrypt=mbed_aes_xts_encrypt;
		c->decrypt=mbed_aes_xts_decrypt;
		c->exit=mbed_aes_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_AES|USICRYPT_ESSIV:
		if(!(c=mbed_aes_essiv_init(ctx,key,klen)))break;
		c->encrypt=mbed_aes_essiv_encrypt;
		c->decrypt=mbed_aes_essiv_decrypt;
		c->exit=mbed_aes_essiv_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_XTS
	case USICRYPT_CAMELLIA|USICRYPT_XTS:
		if(!(c=mbed_camellia_xts_init(ctx,key,klen)))break;
		c->encrypt=mbed_camellia_xts_encrypt;
		c->decrypt=mbed_camellia_xts_decrypt;
		c->exit=mbed_camellia_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_CAMELLIA|USICRYPT_ESSIV:
		if(!(c=mbed_camellia_essiv_init(ctx,key,klen)))break;
		c->encrypt=mbed_camellia_essiv_encrypt;
		c->decrypt=mbed_camellia_essiv_decrypt;
		c->exit=mbed_camellia_essiv_exit;
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
		if(!(c=mbed_aes_gcm_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=mbed_aes_gcm_encrypt;
		c->decrypt=mbed_aes_gcm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=mbed_aes_gcm_encrypt_iov;
		c->decrypt_iov=mbed_aes_gcm_decrypt_iov;
#endif
		c->exit=mbed_aes_gcm_exit;
		break;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		if(!(c=mbed_aes_ccm_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=mbed_aes_ccm_encrypt;
		c->decrypt=mbed_aes_ccm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=mbed_aes_ccm_encrypt_iov;
		c->decrypt_iov=mbed_aes_ccm_decrypt_iov;
#endif
		c->exit=mbed_aes_ccm_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		if(!(c=mbed_chacha_poly_init(ctx,key,klen,ilen,tlen)))break;
		c->encrypt=mbed_chacha_poly_encrypt;
		c->decrypt=mbed_chacha_poly_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=mbed_chacha_poly_encrypt_iov;
		c->decrypt_iov=mbed_chacha_poly_decrypt_iov;
#endif
		c->exit=mbed_chacha_poly_exit;
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
		return mbed_aes_cmac(ctx,key,klen,src,slen,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return mbed_camellia_cmac(ctx,key,klen,src,slen,dst);
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
		return mbed_aes_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return mbed_camellia_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(thread_init)(void *global)
{
	struct usicrypt_thread *ctx;
	unsigned char bfr[32];

	if(!(ctx=malloc(sizeof(struct usicrypt_thread))))goto err1;
	ctx->global=global;
	mbedtls_hmac_drbg_init(&ctx->rng);
	if(mbedtls_hmac_drbg_seed(&ctx->rng,
		mbedtls_md_info_from_type(MBEDTLS_MD_MD5),
		mbed_seed,global,NULL,0))goto err2;
	if(ctx->global->rng_seed(bfr,sizeof(bfr)))goto err2;
	mbedtls_hmac_drbg_update(&((struct usicrypt_thread *)ctx)->rng,
		bfr,sizeof(bfr));
	ctx->global->memclear(bfr,sizeof(bfr));
	return ctx;

err2:	mbedtls_hmac_drbg_free(&ctx->rng);
	free(ctx);
err1:	return NULL;
}

void USICRYPT(thread_exit)(void *ctx)
{
	mbedtls_hmac_drbg_free(&((struct usicrypt_thread *)ctx)->rng);
	free(ctx);
}

void *USICRYPT(global_init)(int (*rng_seed)(void *data,int len),
	void (*memclear)(void *data,int len))
{
	struct usicrypt_global *ctx;

	USICRYPT(do_realloc)(NULL,NULL,0,0);
	if(!(ctx=malloc(sizeof(struct usicrypt_global))))return NULL;
	ctx->rng_seed=(rng_seed?rng_seed:USICRYPT(get_random));
	ctx->memclear=(memclear?memclear:USICRYPT(do_memclear));
	return ctx;
}

void USICRYPT(global_exit)(void *ctx)
{
	free(ctx);
}

#endif
