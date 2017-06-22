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
--enable-aesccm --enable-aesni --enable-intelasm --enable-hkdf --enable-keygen --enable-pwdbased --enable-ecccustcurves --enable-cmac --enable-camellia --enable-curve25519 CFLAGS="-DHAVE_ECC_BRAINPOOL -DHAVE_AES_ECB -DWOLFSSL_AES_COUNTER"
*/

/******************************************************************************/
/*				 Testing				    */
/******************************************************************************/

#ifdef USICRYPT_TEST
#ifndef USICRYPT_WOLF
#define USICRYPT_WOLF
#endif
#endif

/******************************************************************************/
/*				 Headers				    */
/******************************************************************************/

#if defined(USICRYPT_WOLF)

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/camellia.h>

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) wolf_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

/******************************************************************************/
/*				 wolfSSL				    */
/******************************************************************************/

struct wolf_dh
{
	DhKey dh;
	word32 plen;
	byte *priv;
};

struct wolf_aes_xcb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	Aes dec;
};

struct wolf_aes_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	Aes dec;
	unsigned char tmp[32];
};

struct wolf_aes_xfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	int n;
	unsigned char iv[16];
	union
	{
		unsigned char mem[16];
		unsigned char zero[16];
	};
};

struct wolf_aes_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct wolf_aes_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	unsigned char zero[16];
};

struct wolf_aes_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	Aes dec;
	Aes twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct wolf_aes_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	Aes dec;
	Aes aux;
	unsigned char iv[16];
};

struct wolf_aes_xcm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	Aes enc;
	int ilen;
	int tlen;
};

struct wolf_chacha_poly
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	unsigned char key[CHACHA20_POLY1305_AEAD_KEYSIZE];
};

struct wolf_chacha
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	ChaCha ctx;
	int n;
	unsigned char mem[CHACHA_CHUNK_BYTES];
};

struct wolf_camellia_xcb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Camellia ctx;
};

struct wolf_camellia_cts
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Camellia ctx;
	unsigned char tmp[32];
};

struct wolf_camellia_xfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Camellia enc;
	int n;
	unsigned char iv[16];
	union
	{
		unsigned char mem[16];
		unsigned char zero[16];
	};
};

struct wolf_camellia_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Camellia enc;
	unsigned char iv[16];
	unsigned char mem[16];
};

struct wolf_camellia_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	Camellia enc;
	int n;
	unsigned char ctr[16];
	unsigned char mem[16];
};

struct wolf_camellia_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	Camellia ctx;
	Camellia twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct wolf_camellia_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	Camellia ctx;
	Camellia aux;
	unsigned char iv[16];
};

struct wolf_md
{
	int idx;
	union
	{
		Sha h;
		Sha256 h256;
		Sha384 h384;
		Sha512 h512;
	} ctx;
};

static const struct
{
	const int size;
	int (*const init)(void *ctx);
	int (*const update)(void *ctx,const byte *data,word32 len);
	int (*const digest)(void *ctx,byte *out);
} const wolf_md[4]=
{
	{
#ifndef USICRYPT_NO_SHA1
		SHA_DIGEST_SIZE,
		(void *)wc_InitSha,
		(void *)wc_ShaUpdate,
		(void *)wc_ShaFinal
#endif
	},
	{
#ifndef USICRYPT_NO_SHA256
		SHA256_DIGEST_SIZE,
		(void *)wc_InitSha256,
		(void *)wc_Sha256Update,
		(void *)wc_Sha256Final
#endif
	},
	{
#ifndef USICRYPT_NO_SHA384
		SHA384_DIGEST_SIZE,
		(void *)wc_InitSha384,
		(void *)wc_Sha384Update,
		(void *)wc_Sha384Final
#endif
	},
	{
#ifndef USICRYPT_NO_SHA512
		SHA512_DIGEST_SIZE,
		(void *)wc_InitSha512,
		(void *)wc_Sha512Update,
		(void *)wc_Sha512Final
#endif
	}
};

#ifndef USICRYPT_NO_PBKDF2

static const unsigned char const wolf_pbes2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

static const unsigned char const wolf_pbkdf2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c
};

static const struct
{
	const int const digest;
	const int const oidlen;
	const unsigned char const oid[0x08];

} const wolf_digest_asn[4]=
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
} const wolf_cipher_asn[24]=
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

static const struct
{
	const ecc_curve_id id;
	const unsigned char oidlen;
	const unsigned char const oid[9];
} const wolf_ec_map[USICRYPT_TOT_EC_CURVES]=
{
	{ECC_BRAINPOOLP512R1,0x09,
		{0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0D}},
	{ECC_BRAINPOOLP384R1,0x09,
		{0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x0B}},
	{ECC_BRAINPOOLP256R1,0x09,
		{0x2B,0x24,0x03,0x03,0x02,0x08,0x01,0x01,0x07}},
	{ECC_SECP521R1,0x05,{0x2B,0x81,0x04,0x00,0x23}},
	{ECC_SECP384R1,0x05,{0x2B,0x81,0x04,0x00,0x22}},
	{ECC_SECP256R1,0x08,{0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}}
};

#endif
#ifndef USICRYPT_NO_X25519

static const unsigned char const wolf_x25519_asn1_pub[12]=
{
	0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6e,0x03,0x21,0x00
};

static const unsigned char const wolf_x25519_asn1_key[16]=
{
	0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20
};

static const unsigned char const wolf_x25519_basepoint[32]=
{
	0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

#endif

#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_GCM
#ifdef WOLFSSL_AESNI
static int wolf_need_gcm_bugfix=0;
#endif
#endif
#endif

#ifndef USICRYPT_NO_PBKDF2

static int wolf_asn_length(unsigned char *ptr,int len)
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

static int wolf_asn_next(unsigned char *prm,int len,unsigned char id,
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
#ifndef USICRYPT_NO_RSA

static void *wolf_rsa_do_sign_v15(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
	int i;
	unsigned char *sig;
	struct usicrypt_iov *iov=data;
	struct wolf_md c;
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

	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	if(!mode)
	{
		if(U(wolf_md[c.idx].update(&c.ctx,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(wolf_md[c.idx].update(&c.ctx,iov[i].data,iov[i].length)))
			goto err2;
	if(U(wolf_md[c.idx].digest(&c.ctx,hash)))goto err2;
	*slen=wc_RsaEncryptSize(key);
	if(U(!(sig=malloc(*slen))))goto err2;
	if(U(wc_RsaSSL_Sign(hash,wolf_md[c.idx].size,sig,*slen,key,
		&((struct usicrypt_thread *)ctx)->rng)!=*slen))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return sig;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
	free(sig);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return NULL;
}

static int wolf_rsa_do_verify_v15(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
	int i;
	int res;
	unsigned char *tmp;
	struct usicrypt_iov *iov=data;
	struct wolf_md c;
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

	if(U(slen<wc_RsaEncryptSize(key)))goto err1;
	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	if(!mode)
	{
		if(U(wolf_md[c.idx].update(&c.ctx,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(wolf_md[c.idx].update(&c.ctx,iov[i].data,iov[i].length)))
			goto err2;
	if(U(wolf_md[c.idx].digest(&c.ctx,hash)))goto err2;
	res=wc_RsaEncryptSize(key);
	if(U(!(tmp=malloc(res))))goto err2;
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=&((struct usicrypt_thread *)ctx)->rng;
#endif
	if(U(wc_RsaSSL_Verify(sig,slen,tmp,res,key)!=wolf_md[c.idx].size))
		goto err3;
	if(U(memcmp(hash,tmp,wolf_md[c.idx].size)))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,res);
	free(tmp);
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return 0;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,res);
	free(tmp);
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return -1;
}

#endif
#ifndef USICRYPT_NO_EC

static void wolf_import_bugfix(ecc_key *key,unsigned char *data,int len)
{
	int i;
	int l;
	unsigned char *ptr=data;
	ecc_set_type *set;

	/* skip to curve oid in import data */

	if(U(*ptr++!=0x30))return;
	if(*ptr&0x80)if(U(*ptr++!=0x81))return;
	l=*ptr++;
	if(U(l+(ptr-data)>len)||U(*ptr++!=0x30))return;
	if(*ptr&0x80)if(U(*ptr++!=0x81))return;
	l=*ptr++;
	if(U(l+(ptr-data)>len))return;
	data=ptr;
	len=l;
	if(U(*ptr++!=0x06))return;
	if(*ptr&0x80)if(U(*ptr++!=0x81))return;
	l=*ptr++;
	if(U(l+(ptr-data)>=len))return;
	ptr+=l;
	if(U(*ptr++!=0x06))return;
	if(*ptr&0x80)if(U(*ptr++!=0x81))return;
	l=*ptr++;
	if(U(l+(ptr-data)>len))return;

	/* lookup curve oid in table */

	for(i=0;i<USICRYPT_TOT_EC_CURVES;i++)if(wolf_ec_map[i].oidlen==l)
		if(!memcmp(wolf_ec_map[i].oid,ptr,l))break;
	if(i==USICRYPT_TOT_EC_CURVES)return;

	/* check actual curve id against expected curve id */

	if(key->idx==-1)return;
	if(key->dp->id==wolf_ec_map[i].id)return;

	/* replace wrong curve data with proper one */

	set=(ecc_set_type *)key->dp;
	set-=key->idx;

	for(l=0;wc_ecc_is_valid_idx(l);l++,set++)if(set->id==wolf_ec_map[i].id)
	{
		key->dp=(const ecc_set_type *)set;
		key->idx=l;
		break;
	}
}

static void *wolf_ec_do_sign(void *ctx,int md,void *key,void *data,int dlen,
	int *slen,int mode)
{
	word32 len;
	struct usicrypt_iov *iov=data;
	unsigned char *r=NULL;
	struct wolf_md c;
	byte hash[SHA512_DIGEST_SIZE];
	byte sig[1024];

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

	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	if(!mode)
	{
		if(U(wolf_md[c.idx].update(&c.ctx,data,dlen)))goto err2;
	}
	else for(len=0;len<dlen;len++)
	    if(U(wolf_md[c.idx].update(&c.ctx,iov[len].data,iov[len].length)))
		goto err2;
	if(U(wolf_md[c.idx].digest(&c.ctx,hash)))goto err2;
	len=sizeof(sig);
	if(U(wc_ecc_sign_hash(hash,wolf_md[c.idx].size,sig,&len,
		&((struct usicrypt_thread *)ctx)->rng,key)))goto err3;
	if(U(!(r=malloc(len))))goto err3;
	memcpy(r,sig,len);
	*slen=len;
err3:	((struct usicrypt_thread *)ctx)->global->memclear(sig,len);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return r;
}

static int wolf_ec_do_verify(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen,int mode)
{
	int res;
	struct wolf_md c;
	struct usicrypt_iov *iov=data;
	byte hash[SHA512_DIGEST_SIZE];

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

	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	if(!mode)
	{
		if(U(wolf_md[c.idx].update(&c.ctx,data,dlen)))goto err2;
	}
	else for(res=0;res<dlen;res++)
	    if(U(wolf_md[c.idx].update(&c.ctx,iov[res].data,iov[res].length)))
		goto err2;
	if(U(wolf_md[c.idx].digest(&c.ctx,hash)))goto err2;
	if(U(wc_ecc_verify_hash(sig,slen,hash,wolf_md[c.idx].size,&res,key))||
		U(!res))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	return 0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
err1:	return -1;
}

#endif
#ifndef USICRYPT_NO_PBKDF2
#ifndef USICRYPT_NO_SHA384

static int wolf_pbkdf2_384(void *ctx,unsigned char *out,unsigned char *key,
	int klen,unsigned char *salt,int slen,int iter)
{
	int r=-1;
	int i;
	int j;
	Hmac h;
	unsigned char tmp[SHA384_DIGEST_SIZE];

	if(U(klen<0)||U(slen<0)||U(iter<1))goto err1;

	if(U(wc_HmacSetKey(&h,SHA384,key,klen)))goto err2;
	i=wc_HmacUpdate(&h,salt,slen);
	memset(out,0,3);
	out[3]=0x01;
	i+=wc_HmacUpdate(&h,out,4);
	if(U(wc_HmacFinal(&h,out))||U(i))goto err3;

	memcpy(tmp,out,SHA384_DIGEST_SIZE);

	for(i=1;i<iter;i++)
	{
		if(U(wc_HmacSetKey(&h,SHA384,key,klen)))goto err3;
		j=wc_HmacUpdate(&h,tmp,SHA384_DIGEST_SIZE);
		if(U(wc_HmacFinal(&h,tmp))||U(j))goto err3;
		for(j=0;j<SHA384_DIGEST_SIZE;j++)out[j]^=tmp[j];
	}

	r=0;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->
		memclear(out,SHA384_DIGEST_SIZE);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(&tmp,sizeof(tmp));
err1:	return r;
}

#endif
#endif
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_CMAC

static int wolf_aes_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	if(U(klen&7))return -1;
	if(U(wc_AesCmacGenerate(dst,NULL,src,slen,key,klen>>3)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_aes_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	Cmac c;

	if(U(klen&7))goto err1;
	if(U(wc_InitCmac(&c,key,klen>>3,WC_CMAC_AES,NULL)))goto err1;
	for(i=0;i<niov;i++)if(U(wc_CmacUpdate(&c,iov[i].data,iov[i].length)))
		goto err2;
	if(U(wc_CmacFinal(&c,dst,NULL)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(&c,sizeof(c));
	return 0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c,sizeof(c));
err1:	return -1;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int wolf_aes_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	if(U(wc_AesEcbEncrypt(&((struct wolf_aes_xcb *)ctx)->enc,dst,src,slen)))
		return -1;
	return 0;
}

static int wolf_aes_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	if(U(wc_AesEcbDecrypt(&((struct wolf_aes_xcb *)ctx)->dec,dst,src,slen)))
		return -1;
	return 0;
}

static void *wolf_aes_ecb_init(void *ctx,void *key,int klen)
{
	struct wolf_aes_xcb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xcb)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,NULL,AES_ENCRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->dec,key,klen>>3,NULL,AES_DECRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->dec,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_ecb_exit(void *ctx)
{
	((struct wolf_aes_xcb *)ctx)->global->
		memclear(&((struct wolf_aes_xcb *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_xcb *)ctx)->global->
		memclear(&((struct wolf_aes_xcb *)ctx)->dec,sizeof(Aes));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int wolf_aes_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	if(U(wc_AesCbcEncrypt(&((struct wolf_aes_xcb *)ctx)->enc,dst,src,slen)))
		return -1;
	return 0;
}

static int wolf_aes_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	if(U(wc_AesCbcDecrypt(&((struct wolf_aes_xcb *)ctx)->dec,dst,src,slen)))
		return -1;
	return 0;
}

static void *wolf_aes_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_xcb *aes;
	unsigned long long zero[2]={0,0};

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xcb)))))goto err1;
	if(!iv)iv=zero;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,iv,AES_ENCRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->dec,key,klen>>3,iv,AES_DECRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->dec,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_cbc_reset(void *ctx,void *iv)
{
	wc_AesSetIV(&((struct wolf_aes_xcb *)ctx)->enc,iv);
	wc_AesSetIV(&((struct wolf_aes_xcb *)ctx)->dec,iv);
}

static void wolf_aes_cbc_exit(void *ctx)
{
	((struct wolf_aes_xcb *)ctx)->global->
		memclear(&((struct wolf_aes_xcb *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_xcb *)ctx)->global->
		memclear(&((struct wolf_aes_xcb *)ctx)->dec,sizeof(Aes));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int wolf_aes_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct wolf_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(U(wc_AesCbcEncrypt(&aes->enc,d,s,slen-rem)))return -1;
	s+=slen-rem;
	d+=slen-rem;
	memcpy(aes->tmp,s,rem);
	if(rem<16)memset(aes->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	if(U(wc_AesCbcEncrypt(&aes->enc,d-16,aes->tmp,16)))return -1;
	return 0;
}

static int wolf_aes_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct wolf_aes_cts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(slen-rem-16)
	{
		if(U(wc_AesCbcDecrypt(&aes->dec,d,s,slen-rem-16)))return -1;
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(aes->tmp+16,s,16);
	if(U(wc_AesEcbDecrypt(&aes->dec,aes->tmp,s,16)))return -1;
	memcpy(aes->tmp,s+16,rem);
	if(U(wc_AesCbcDecrypt(&aes->dec,aes->tmp,aes->tmp,32)))return -1;
	memcpy(d,aes->tmp,rem+16);
	return 0;
}

static void *wolf_aes_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_cts *aes;
	unsigned long long zero[2]={0,0};

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_cts)))))goto err1;
	if(!iv)iv=zero;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,iv,AES_ENCRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->dec,key,klen>>3,iv,AES_DECRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->dec,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_cts_reset(void *ctx,void *iv)
{
	wc_AesSetIV(&((struct wolf_aes_cts *)ctx)->enc,iv);
	wc_AesSetIV(&((struct wolf_aes_cts *)ctx)->dec,iv);
}

static void wolf_aes_cts_exit(void *ctx)
{
	((struct wolf_aes_cts *)ctx)->global->
		memclear(&((struct wolf_aes_cts *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_cts *)ctx)->global->
		memclear(&((struct wolf_aes_cts *)ctx)->dec,sizeof(Aes));
	((struct wolf_aes_cts *)ctx)->global->
		memclear(&((struct wolf_aes_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int wolf_aes_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!aes->n)
			if(U(wc_AesEcbEncrypt(&aes->enc,aes->mem,aes->iv,16)))
				return -1;
		aes->iv[aes->n]=*d++=*s++^aes->mem[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static int wolf_aes_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!aes->n)
			if(U(wc_AesEcbEncrypt(&aes->enc,aes->mem,aes->iv,16)))
				return -1;
		aes->iv[aes->n]=*s;
		*d++=*s++^aes->mem[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static void *wolf_aes_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_xfb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xfb)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,NULL,AES_ENCRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_cfb_reset(void *ctx,void *iv)
{
	((struct wolf_aes_xfb *)ctx)->n=0;
	memcpy(((struct wolf_aes_xfb *)ctx)->iv,iv,16);
}

static void wolf_aes_cfb_exit(void *ctx)
{
	((struct wolf_aes_xfb *)ctx)->global->
		memclear(&((struct wolf_aes_xfb *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_xfb *)ctx)->global->
		memclear(&((struct wolf_aes_xfb *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int wolf_aes_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct wolf_aes_cfb8 *aes=ctx;

	while(slen--)
	{
		if(U(wc_AesEcbEncrypt(&aes->enc,aes->mem,aes->iv,16)))return -1;
		memmove(aes->iv,aes->iv+1,15);
		*d++=aes->iv[15]=*s++^aes->mem[0];
	}
	return 0;
}

static int wolf_aes_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct wolf_aes_cfb8 *aes=ctx;

	while(slen--)
	{
		if(U(wc_AesEcbEncrypt(&aes->enc,aes->mem,aes->iv,16)))return -1;
		memmove(aes->iv,aes->iv+1,15);
		aes->iv[15]=*s;
		*d++=*s++^aes->mem[0];
	}
	return 0;
}

static void *wolf_aes_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_cfb8 *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_cfb8)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,NULL,AES_ENCRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct wolf_aes_cfb8 *)ctx)->iv,iv,16);
}

static void wolf_aes_cfb8_exit(void *ctx)
{
	((struct wolf_aes_cfb8 *)ctx)->global->
		memclear(&((struct wolf_aes_cfb8 *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_cfb8 *)ctx)->global->
		memclear(((struct wolf_aes_cfb8 *)ctx)->iv,16);
	((struct wolf_aes_cfb8 *)ctx)->global->
		memclear(((struct wolf_aes_cfb8 *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int wolf_aes_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_aes_xfb *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!aes->n)
		{
			wc_AesSetIV(&aes->enc,aes->iv);
			if(U(wc_AesCbcEncrypt(&aes->enc,aes->iv,aes->zero,16)))
				return -1;
		}
		*d++=aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!aes->n)
		{
			wc_AesSetIV(&aes->enc,aes->iv);
			if(U(wc_AesCbcEncrypt(&aes->enc,aes->iv,aes->zero,16)))
				return -1;
		}
		*d++=*s++^aes->iv[aes->n];
		aes->n=(aes->n+1)&0xf;
	}
	return 0;
}

static void *wolf_aes_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_xfb *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xfb)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,NULL,AES_ENCRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->n=0;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	memset(aes->zero,0,sizeof(aes->zero));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	aes->global->memclear(aes->iv,16);
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_ofb_reset(void *ctx,void *iv)
{
	((struct wolf_aes_xfb *)ctx)->n=0;
	memcpy(((struct wolf_aes_xfb *)ctx)->iv,iv,16);
}

static void wolf_aes_ofb_exit(void *ctx)
{
	((struct wolf_aes_xfb *)ctx)->global->
		memclear(&((struct wolf_aes_xfb *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_xfb *)ctx)->global->
		memclear(&((struct wolf_aes_xfb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int wolf_aes_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_aes_ctr *aes=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			wc_AesCtrEncrypt(&((struct wolf_aes_ctr *)ctx)->enc,
				dst,aes->zero,16);
		wc_AesCtrEncrypt(&((struct wolf_aes_ctr *)ctx)->enc,
			dst,aes->zero,slen);
	}
	else wc_AesCtrEncrypt(&((struct wolf_aes_ctr *)ctx)->enc,dst,src,slen);
	return 0;
}

static void *wolf_aes_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_aes_ctr *aes;
	unsigned long long zero[2]={0,0};

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_ctr)))))goto err1;
	if(!iv)iv=zero;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,iv,AES_ENCRYPTION)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	memset(aes->zero,0,sizeof(aes->zero));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_ctr_reset(void *ctx,void *iv)
{
	wc_AesSetIV(&((struct wolf_aes_ctr *)ctx)->enc,iv);
	((struct wolf_aes_ctr *)ctx)->enc.left=0;
}

static void wolf_aes_ctr_exit(void *ctx)
{
	((struct wolf_aes_ctr *)ctx)->global->
		memclear(&((struct wolf_aes_ctr *)ctx)->enc,sizeof(Aes));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int wolf_aes_xts_encrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct wolf_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	if(U(wc_AesEcbEncrypt(&aes->twe,aes->twk,iv,16)))return -1;

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		if(U(wc_AesEcbEncrypt(&aes->enc,d,aes->wrk,16)))return -1;
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
		if(U(wc_AesEcbEncrypt(&aes->enc,d,aes->wrk,16)))return -1;
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
	}

	return 0;
}

static int wolf_aes_xts_decrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int i;
	int n;
	struct wolf_aes_xts *aes=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	if(U(wc_AesEcbEncrypt(&aes->twe,aes->twk,iv,16)))return -1;

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)aes->wrk[i]=s[i]^aes->twk[i];
		if(U(wc_AesEcbDecrypt(&aes->dec,d,aes->wrk,16)))return -1;
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
		if(U(wc_AesEcbDecrypt(&aes->dec,d,aes->wrk,16)))return -1;
		for(i=0;i<16;i++)d[i]^=aes->twk[i];
		memcpy(d+16,d,slen);
		memcpy(aes->wrk,s+16,slen);
		memcpy(aes->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)aes->wrk[i]^=aes->mem[i];
		if(U(wc_AesEcbDecrypt(&aes->dec,d,aes->wrk,16)))return -1;
		for(i=0;i<16;i++)d[i]^=aes->mem[i];
	}

	return 0;
}

static void *wolf_aes_xts_init(void *ctx,void *key,int klen)
{
	struct wolf_aes_xts *aes;

	if(U(klen!=256&&klen!=512))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xts)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>4,NULL,AES_ENCRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->dec,key,klen>>4,NULL,AES_DECRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->twe,key+(klen>>4),klen>>4,NULL,AES_ENCRYPTION)))
		goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(aes,sizeof(struct wolf_aes_xts));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_xts_exit(void *ctx)
{
	struct usicrypt_global *global=((struct wolf_aes_xts *)ctx)->global;

	global->memclear(ctx,sizeof(struct wolf_aes_xts));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int wolf_aes_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct wolf_aes_essiv *aes=ctx;

	if(U(slen&0xf))return -1;
	if(U(wc_AesEcbEncrypt(&aes->aux,aes->iv,iv,16)))return -1;
	wc_AesSetIV(&aes->enc,aes->iv);
	if(U(wc_AesCbcEncrypt(&aes->enc,dst,src,slen)))return -1;
	return 0;
}

static int wolf_aes_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct wolf_aes_essiv *aes=ctx;

	if(U(slen&0xf))return -1;
	if(U(wc_AesEcbEncrypt(&aes->aux,aes->iv,iv,16)))return -1;
	wc_AesSetIV(&aes->dec,aes->iv);
	if(U(wc_AesCbcDecrypt(&aes->dec,dst,src,slen)))return -1;
	return 0;
}

static void *wolf_aes_essiv_init(void *ctx,void *key,int klen)
{
	struct wolf_aes_essiv *aes;
	Sha256 h;
	unsigned char tmp[SHA256_DIGEST_SIZE];

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_essiv)))))goto err1;
	if(U(wc_AesSetKey(&aes->enc,key,klen>>3,NULL,AES_ENCRYPTION)))goto err2;
	if(U(wc_AesSetKey(&aes->dec,key,klen>>3,NULL,AES_DECRYPTION)))goto err2;
	if(U(wc_InitSha256(&h)))goto err2;
	if(U(wc_Sha256Update(&h,key,klen>>3)))goto err3;
	if(U(wc_Sha256Final(&h,tmp)))goto err3;
	if(U(wc_AesSetKey(&aes->aux,tmp,SHA256_DIGEST_SIZE,NULL,
		AES_ENCRYPTION)))goto err4;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err4:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->aux,sizeof(Aes));
err3:	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->dec,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_essiv_exit(void *ctx)
{
	((struct wolf_aes_essiv *)ctx)->global->
		memclear(&((struct wolf_aes_essiv *)ctx)->enc,sizeof(Aes));
	((struct wolf_aes_essiv *)ctx)->global->
		memclear(&((struct wolf_aes_essiv *)ctx)->dec,sizeof(Aes));
	((struct wolf_aes_essiv *)ctx)->global->
		memclear(&((struct wolf_aes_essiv *)ctx)->aux,sizeof(Aes));
	((struct wolf_aes_essiv *)ctx)->global->
		memclear(((struct wolf_aes_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_GCM

static int wolf_aes_gcm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
#ifdef WOLFSSL_AESNI
	unsigned char tmp[16];

	if(wolf_need_gcm_bugfix&&((struct wolf_aes_xcm *)ctx)->tlen!=16)
	{
		if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))
			return -1;
		memcpy(tag,tmp,((struct wolf_aes_xcm *)ctx)->tlen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(tmp,16);
		return 0;
	}
#endif
	if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_aes_gcm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;
#ifdef WOLFSSL_AESNI
	unsigned char tmp[16];
#endif
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
#ifdef WOLFSSL_AESNI
	if(wolf_need_gcm_bugfix&&((struct wolf_aes_xcm *)ctx)->tlen!=16)
	{
		if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))
			goto err2;
		memcpy(tag,tmp,((struct wolf_aes_xcm *)ctx)->tlen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(tmp,16);
		if(aad)
		{
			((struct wolf_aes_xcm *)ctx)->global->
				memclear(aad,alen);
			free(aad);
		}
		return 0;
	}
#endif
	if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))goto err2;
	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static int wolf_aes_gcm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
#ifdef WOLFSSL_AESNI
	int i;
	unsigned char *ptr;
	unsigned char tmp[16];

	if(wolf_need_gcm_bugfix&&((struct wolf_aes_xcm *)ctx)->tlen!=16)
	{
		if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))
			return -1;
		if(U(!(ptr=malloc(slen))))return -1;
		i=wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			ptr,dst,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(ptr,slen);
		free(ptr);
		if(U(i))return -1;
		i=memcmp(tag,tmp,((struct wolf_aes_xcm *)ctx)->tlen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(tmp,16);
		return U(i)?-1:0;
	}
#endif
	if(U(wc_AesGcmDecrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_aes_gcm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;
#ifdef WOLFSSL_AESNI
	unsigned char *ptr;
	unsigned char tmp[16];
#endif
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
#ifdef WOLFSSL_AESNI
	if(wolf_need_gcm_bugfix&&((struct wolf_aes_xcm *)ctx)->tlen!=16)
	{
		if(U(wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))
			goto err2;
		if(U(!(ptr=malloc(slen))))goto err2;
		i=wc_AesGcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
			ptr,dst,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
			tmp,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(ptr,slen);
		free(ptr);
		if(U(i))goto err2;
		i=memcmp(tag,tmp,((struct wolf_aes_xcm *)ctx)->tlen);
		((struct wolf_aes_xcm *)ctx)->global->memclear(tmp,16);
		if(aad)
		{
			((struct wolf_aes_xcm *)ctx)->global->
				memclear(aad,alen);
			free(aad);
		}
		return U(i)?-1:0;
	}
#endif
	if(wc_AesGcmDecrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen))goto err2;
	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static void *wolf_aes_gcm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct wolf_aes_xcm *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xcm)))))goto err1;
	if(U(wc_AesGcmSetKey(&aes->enc,key,klen>>3)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->ilen=ilen;
	aes->tlen=tlen;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_gcm_exit(void *ctx)
{
	((struct wolf_aes_xcm *)ctx)->global->
		memclear(&((struct wolf_aes_xcm *)ctx)->enc,sizeof(Aes));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CCM

static int wolf_aes_ccm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(U(wc_AesCcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_aes_ccm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(U(wc_AesCcmEncrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))goto err2;
	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static int wolf_aes_ccm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(U(wc_AesCcmDecrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_aes_ccm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(U(wc_AesCcmDecrypt(&((struct wolf_aes_xcm *)ctx)->enc,
		dst,src,slen,iv,((struct wolf_aes_xcm *)ctx)->ilen,
		tag,((struct wolf_aes_xcm *)ctx)->tlen,aad,alen)))goto err2;
	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_aes_xcm *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static void *wolf_aes_ccm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct wolf_aes_xcm *aes;

	if(U(klen&7))goto err1;
	if(U(!(aes=malloc(sizeof(struct wolf_aes_xcm)))))goto err1;
	if(U(wc_AesCcmSetKey(&aes->enc,key,klen>>3)))goto err2;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->ilen=ilen;
	aes->tlen=tlen;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&aes->enc,sizeof(Aes));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_aes_ccm_exit(void *ctx)
{
	((struct wolf_aes_xcm *)ctx)->global->
		memclear(&((struct wolf_aes_xcm *)ctx)->enc,sizeof(Aes));
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY

static int wolf_chacha_poly_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(U(wc_ChaCha20Poly1305_Encrypt(((struct wolf_chacha_poly *)ctx)->key,
		iv,aad,alen,src,slen,dst,tag)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_chacha_poly_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(U(wc_ChaCha20Poly1305_Encrypt(((struct wolf_chacha_poly *)ctx)->key,
		iv,aad,alen,src,slen,dst,tag)))goto err2;
	if(aad)
	{
		((struct wolf_chacha_poly *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_chacha_poly *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static int wolf_chacha_poly_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	if(U(wc_ChaCha20Poly1305_Decrypt(((struct wolf_chacha_poly *)ctx)->key,
		iv,aad,alen,src,slen,tag,dst)))return -1;
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_chacha_poly_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int i;
	int alen;
	unsigned char *aad=NULL;

	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(U(wc_ChaCha20Poly1305_Decrypt(((struct wolf_chacha_poly *)ctx)->key,
		iv,aad,alen,src,slen,tag,dst)))goto err2;
	if(aad)
	{
		((struct wolf_chacha_poly *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
	return 0;

err2:	if(aad)
	{
		((struct wolf_chacha_poly *)ctx)->global->memclear(aad,alen);
		free(aad);
	}
err1:   return -1;
}

#endif

static void *wolf_chacha_poly_init(void *ctx,void *key,int klen,int ilen,
	int tlen)
{
	struct wolf_chacha_poly *chp;

	if(U(klen!=256)||U(ilen!=12)||U(tlen!=16))goto err1;
	if(U(!(chp=malloc(sizeof(struct wolf_chacha_poly)))))goto err1;
	memcpy(chp->key,key,CHACHA20_POLY1305_AEAD_KEYSIZE);
	chp->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->
		memclear(key,CHACHA20_POLY1305_AEAD_KEYSIZE);
	return chp;

err1:	((struct usicrypt_thread *)ctx)->global->
		memclear(key,CHACHA20_POLY1305_AEAD_KEYSIZE);
	return NULL;
}

static void wolf_chacha_poly_exit(void *ctx)
{
	((struct wolf_chacha_poly *)ctx)->global->
		memclear(((struct wolf_chacha_poly *)ctx)->key,
			CHACHA20_POLY1305_AEAD_KEYSIZE);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_STREAM

static int wolf_chacha_crypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct wolf_chacha *ch=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(ch->n&&slen)
	{
		*d++=*s++^ch->mem[ch->n++];
		ch->n&=CHACHA_CHUNK_BYTES-1;
		if(!--slen)return 0;
	}
	rem=slen&(CHACHA_CHUNK_BYTES-1);
	if(slen-rem)if(U(wc_Chacha_Process(&ch->ctx,d,s,slen-rem)))return -1;
	if(rem)
	{
		d+=slen-rem;
		s+=slen-rem;
		memset(ch->mem,0,CHACHA_CHUNK_BYTES);
		if(U(wc_Chacha_Process(&ch->ctx,ch->mem,ch->mem,
			CHACHA_CHUNK_BYTES)))return -1;
		while(rem--)*d++=*s++^ch->mem[ch->n++];
	}
	return 0;
}

static void *wolf_chacha_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_chacha *ch;
	unsigned char tmp[12];

	if(U(klen!=256))goto err1;
	if(U(!(ch=malloc(sizeof(struct wolf_chacha)))))goto err1;
	memset(tmp,0,4);
	if(iv)memcpy(tmp+4,iv,8);
	else memset(tmp+4,0,8);
	if(U(wc_Chacha_SetIV(&ch->ctx,tmp,0)))goto err2;
	if(U(wc_Chacha_SetKey(&ch->ctx,key,32)))goto err2;
	ch->global=((struct usicrypt_thread *)ctx)->global;
	ch->n=0;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,12);
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return ch;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&ch->ctx,sizeof(ChaCha));
	free(ch);
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,12);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return NULL;
}

static void wolf_chacha_reset(void *ctx,void *iv)
{
	unsigned char tmp[12];

	memset(tmp,0,4);
	memcpy(tmp+4,iv,8);
	wc_Chacha_SetIV(&((struct wolf_chacha *)ctx)->ctx,tmp,0);
	((struct wolf_chacha *)ctx)->n=0;
	((struct wolf_chacha *)ctx)->global->memclear(tmp,12);
}

static void wolf_chacha_exit(void *ctx)
{
	((struct wolf_chacha *)ctx)->global->
		memclear(&((struct wolf_chacha *)ctx)->ctx,sizeof(ChaCha));
	((struct wolf_chacha *)ctx)->global->
		memclear(&((struct wolf_chacha *)ctx)->mem,CHACHA_CHUNK_BYTES);
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_CMAC

static int wolf_camellia_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	unsigned char *s=src;
	Camellia enc;
	unsigned char wrk[4][16];

	if(U(klen&7))return -1;
	if(U(wc_CamelliaSetKey(&enc,key,klen>>3,NULL)))return -1;
	memset(wrk,0,sizeof(wrk));
	wc_CamelliaEncryptDirect(&enc,wrk[1],wrk[1]);
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[2][i]=(unsigned char)(n|=(wrk[1][i]<<1));
	if(n)wrk[2][15]^=0x87;
	for(n=0,i=15;i>=0;i--,n>>=8)
		wrk[3][i]=(unsigned char)(n|=(wrk[2][i]<<1));
	if(n)wrk[3][15]^=0x87;
	for(;slen>16;slen-=16,s+=16)
	{
		for(i=0;i<16;i++)wrk[0][i]^=s[i];
		wc_CamelliaEncryptDirect(&enc,wrk[0],wrk[0]);
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
	wc_CamelliaEncryptDirect(&enc,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#ifndef USICRYPT_NO_IOV

static int wolf_camellia_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
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
	Camellia enc;
	unsigned char wrk[6][16];

	if(U(klen&7))return -1;
	if(U(wc_CamelliaSetKey(&enc,key,klen>>3,NULL)))return -1;
	memset(wrk,0,sizeof(wrk));
	wc_CamelliaEncryptDirect(&enc,wrk[1],wrk[1]);
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
				wc_CamelliaEncryptDirect(&enc,wrk[0],wrk[0]);
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
		wc_CamelliaEncryptDirect(&enc,wrk[0],wrk[0]);
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
	wc_CamelliaEncryptDirect(&enc,dst,wrk[0]);
	((struct usicrypt_thread *)ctx)->global->memclear(wrk,sizeof(wrk));
	((struct usicrypt_thread *)ctx)->global->memclear(&enc,sizeof(enc));
	return 0;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int wolf_camellia_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;slen-=16,s+=16,d+=16)wc_CamelliaEncryptDirect(
		&((struct wolf_camellia_xcb *)ctx)->ctx,d,s);
	return 0;
}

static int wolf_camellia_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;slen-=16,s+=16,d+=16)wc_CamelliaDecryptDirect(
		&((struct wolf_camellia_xcb *)ctx)->ctx,d,s);
	return 0;
}

static void *wolf_camellia_ecb_init(void *ctx,void *key,int klen)
{
	struct wolf_camellia_xcb *camellia;

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_xcb)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->ctx,key,klen>>3,NULL)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->ctx,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_ecb_exit(void *ctx)
{
	((struct wolf_camellia_xcb *)ctx)->global->
		memclear(&((struct wolf_camellia_xcb *)ctx)->ctx,
			sizeof(Camellia));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int wolf_camellia_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	wc_CamelliaCbcEncrypt(&((struct wolf_camellia_xcb *)ctx)->ctx,dst,src,
		slen);
	return 0;
}

static int wolf_camellia_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen&0xf))return -1;
	wc_CamelliaCbcDecrypt(&((struct wolf_camellia_xcb *)ctx)->ctx,dst,src,
		slen);
	return 0;
}

static void *wolf_camellia_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_xcb *camellia;
	unsigned long long zero[2]={0,0};

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_xcb)))))goto err1;
	if(!iv)iv=zero;
	if(U(wc_CamelliaSetKey(&camellia->ctx,key,klen>>3,iv)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->ctx,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_cbc_reset(void *ctx,void *iv)
{
	wc_CamelliaSetIV(&((struct wolf_camellia_xcb *)ctx)->ctx,iv);
}

static void wolf_camellia_cbc_exit(void *ctx)
{
	((struct wolf_camellia_xcb *)ctx)->global->
		memclear(&((struct wolf_camellia_xcb *)ctx)->ctx,
			sizeof(Camellia));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int wolf_camellia_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct wolf_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	wc_CamelliaCbcEncrypt(&camellia->ctx,d,s,slen-rem);
	s+=slen-rem;
	d+=slen-rem;
	memcpy(camellia->tmp,s,rem);
	if(rem<16)memset(camellia->tmp+rem,0,16-rem);
	memcpy(d,d-16,rem);
	wc_CamelliaCbcEncrypt(&camellia->ctx,d-16,camellia->tmp,16);
	return 0;
}

static int wolf_camellia_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	int rem;
	struct wolf_camellia_cts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<=16))return -1;
	if(!(rem=slen&0xf))rem=0x10;
	if(slen-rem-16)
	{
		wc_CamelliaCbcDecrypt(&camellia->ctx,d,s,slen-rem-16);
		s+=slen-rem-16;
		d+=slen-rem-16;
	}
	memcpy(camellia->tmp+16,s,16);
	wc_CamelliaDecryptDirect(&camellia->ctx,camellia->tmp,s);
	memcpy(camellia->tmp,s+16,rem);
	wc_CamelliaCbcDecrypt(&camellia->ctx,camellia->tmp,camellia->tmp,32);
	memcpy(d,camellia->tmp,rem+16);
	return 0;
}

static void *wolf_camellia_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_cts *camellia;
	unsigned long long zero[2]={0,0};

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_cts)))))goto err1;
	if(!iv)iv=zero;
	if(U(wc_CamelliaSetKey(&camellia->ctx,key,klen>>3,iv)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->ctx,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_cts_reset(void *ctx,void *iv)
{
	wc_CamelliaSetIV(&((struct wolf_camellia_cts *)ctx)->ctx,iv);
}

static void wolf_camellia_cts_exit(void *ctx)
{
	((struct wolf_camellia_cts *)ctx)->global->
		memclear(&((struct wolf_camellia_cts *)ctx)->ctx,
			sizeof(Camellia));
	((struct wolf_camellia_cts *)ctx)->global->
		memclear(&((struct wolf_camellia_cts *)ctx)->tmp,32);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int wolf_camellia_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!camellia->n)wc_CamelliaEncryptDirect(&camellia->enc,
			camellia->mem,camellia->iv);
		camellia->iv[camellia->n]=*d++=*s++^camellia->mem[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static int wolf_camellia_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	while(slen--)
	{
		if(!camellia->n)wc_CamelliaEncryptDirect(&camellia->enc,
			camellia->mem,camellia->iv);
		camellia->iv[camellia->n]=*s;
		*d++=*s++^camellia->mem[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static void *wolf_camellia_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_xfb *camellia;

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_xfb)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->enc,key,klen>>3,NULL)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->enc,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_cfb_reset(void *ctx,void *iv)
{
	((struct wolf_camellia_xfb *)ctx)->n=0;
	memcpy(((struct wolf_camellia_xfb *)ctx)->iv,iv,16);
}

static void wolf_camellia_cfb_exit(void *ctx)
{
	((struct wolf_camellia_xfb *)ctx)->global->
		memclear(&((struct wolf_camellia_xfb *)ctx)->enc,
			sizeof(Camellia));
	((struct wolf_camellia_xfb *)ctx)->global->
		memclear(&((struct wolf_camellia_xfb *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int wolf_camellia_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct wolf_camellia_cfb8 *camellia=ctx;

	while(slen--)
	{
		wc_CamelliaEncryptDirect(
			&((struct wolf_camellia_cfb8 *)ctx)->enc,
			camellia->mem,camellia->iv);
		memmove(camellia->iv,camellia->iv+1,15);
		*d++=camellia->iv[15]=*s++^camellia->mem[0];
	}
	return 0;
}

static int wolf_camellia_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct wolf_camellia_cfb8 *camellia=ctx;

	while(slen--)
	{
		wc_CamelliaEncryptDirect(
			&((struct wolf_camellia_cfb8 *)ctx)->enc,
			camellia->mem,camellia->iv);
		memmove(camellia->iv,camellia->iv+1,15);
		camellia->iv[15]=*s;
		*d++=*s++^camellia->mem[0];
	}
	return 0;
}

static void *wolf_camellia_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_cfb8 *camellia;

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_cfb8)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->enc,key,klen>>3,NULL)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->enc,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct wolf_camellia_cfb8 *)ctx)->iv,iv,16);
}

static void wolf_camellia_cfb8_exit(void *ctx)
{
	((struct wolf_camellia_cfb8 *)ctx)->global->memclear(
		&((struct wolf_camellia_cfb8 *)ctx)->enc,sizeof(Camellia));
	((struct wolf_camellia_cfb8 *)ctx)->global->
		memclear(((struct wolf_camellia_cfb8 *)ctx)->iv,16);
	((struct wolf_camellia_cfb8 *)ctx)->global->
		memclear(((struct wolf_camellia_cfb8 *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int wolf_camellia_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct wolf_camellia_xfb *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(!s)while(slen--)
	{
		if(!camellia->n)
		{
			wc_CamelliaSetIV(&camellia->enc,camellia->iv);
			wc_CamelliaCbcEncrypt(&camellia->enc,camellia->iv,
				camellia->zero,16);
		}
		*d++=camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	else while(slen--)
	{
		if(!camellia->n)
		{
			wc_CamelliaSetIV(&camellia->enc,camellia->iv);
			wc_CamelliaCbcEncrypt(&camellia->enc,camellia->iv,
				camellia->zero,16);
		}
		*d++=*s++^camellia->iv[camellia->n];
		camellia->n=(camellia->n+1)&0xf;
	}
	return 0;
}

static void *wolf_camellia_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_xfb *camellia;

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_xfb)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->enc,key,klen>>3,NULL)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	memset(camellia->zero,0,sizeof(camellia->zero));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->enc,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_ofb_reset(void *ctx,void *iv)
{
	((struct wolf_camellia_xfb *)ctx)->n=0;
	memcpy(((struct wolf_camellia_xfb *)ctx)->iv,iv,16);
}

static void wolf_camellia_ofb_exit(void *ctx)
{
	((struct wolf_camellia_xfb *)ctx)->global->
		memclear(&((struct wolf_camellia_xfb *)ctx)->enc,
			sizeof(Camellia));
	((struct wolf_camellia_xfb *)ctx)->global->
		memclear(&((struct wolf_camellia_xfb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int wolf_camellia_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	int i;
	struct wolf_camellia_ctr *camellia=ctx;
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
		wc_CamelliaEncryptDirect(&camellia->enc,d,camellia->ctr);
		for(i=15;i>=0;i--)if(++(camellia->ctr[i]))break;
		if(s)for(i=0;i<16;i++)d[i]^=*s++;
		d+=16;
		slen-=16;
	}
	if(slen)
	{
		wc_CamelliaEncryptDirect(&camellia->enc,camellia->mem,
			camellia->ctr);
		for(i=15;i>=0;i--)if(++(camellia->ctr[i]))break;
		if(s)for(i=0;i<slen;i++)d[i]=camellia->mem[camellia->n++]^*s++;
		else for(i=0;i<slen;i++)d[i]=camellia->mem[camellia->n++];
	}
	return 0;
}

static void *wolf_camellia_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct wolf_camellia_ctr *camellia;

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_ctr)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->enc,key,klen>>3,NULL)))goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->n=0;
	if(iv)memcpy(camellia->ctr,iv,16);
	else memset(camellia->ctr,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->enc,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_ctr_reset(void *ctx,void *iv)
{
	((struct wolf_camellia_ctr *)ctx)->n=0;
	memcpy(((struct wolf_camellia_ctr *)ctx)->ctr,iv,16);
}

static void wolf_camellia_ctr_exit(void *ctx)
{
	((struct wolf_camellia_ctr *)ctx)->global->
		memclear(&((struct wolf_camellia_ctr *)ctx)->enc,
			sizeof(Camellia));
	((struct wolf_camellia_ctr *)ctx)->global->
		memclear(&((struct wolf_camellia_ctr *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int wolf_camellia_xts_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct wolf_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	wc_CamelliaEncryptDirect(&camellia->twe,camellia->twk,iv);

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		wc_CamelliaEncryptDirect(&camellia->ctx,d,camellia->wrk);
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
		wc_CamelliaEncryptDirect(&camellia->ctx,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
	}

	return 0;
}

static int wolf_camellia_xts_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct wolf_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	wc_CamelliaEncryptDirect(&camellia->twe,camellia->twk,iv);

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		wc_CamelliaDecryptDirect(&camellia->ctx,d,camellia->wrk);
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
		wc_CamelliaDecryptDirect(&camellia->ctx,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
		memcpy(d+16,d,slen);
		memcpy(camellia->wrk,s+16,slen);
		memcpy(camellia->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)camellia->wrk[i]^=camellia->mem[i];
		wc_CamelliaDecryptDirect(&camellia->ctx,d,camellia->wrk);
		for(i=0;i<16;i++)d[i]^=camellia->mem[i];
	}

	return 0;
}

static void *wolf_camellia_xts_init(void *ctx,void *key,int klen)
{
	struct wolf_camellia_xts *camellia;

	if(U(klen!=256&&klen!=512))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_xts)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->ctx,key,klen>>4,NULL)))goto err2;
	if(U(wc_CamelliaSetKey(&camellia->twe,key+(klen>>4),klen>>4,NULL)))
		goto err2;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(camellia,sizeof(struct wolf_camellia_xts));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_xts_exit(void *ctx)
{
	struct usicrypt_global *global;

	global=((struct wolf_camellia_xts *)ctx)->global;
	global->memclear(ctx,sizeof(struct wolf_camellia_xts));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int wolf_camellia_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct wolf_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	wc_CamelliaEncryptDirect(&camellia->aux,camellia->iv,iv);
	wc_CamelliaSetIV(&camellia->ctx,camellia->iv);
	wc_CamelliaCbcEncrypt(&camellia->ctx,dst,src,slen);
	return 0;
}

static int wolf_camellia_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	struct wolf_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	wc_CamelliaEncryptDirect(&camellia->aux,camellia->iv,iv);
	wc_CamelliaSetIV(&camellia->ctx,camellia->iv);
	wc_CamelliaCbcDecrypt(&camellia->ctx,dst,src,slen);
	return 0;
}

static void *wolf_camellia_essiv_init(void *ctx,void *key,int klen)
{
	struct wolf_camellia_essiv *camellia;
	Sha256 h;
	unsigned char tmp[SHA256_DIGEST_SIZE];

	if(U(klen&7))goto err1;
	if(U(!(camellia=malloc(sizeof(struct wolf_camellia_essiv)))))goto err1;
	if(U(wc_CamelliaSetKey(&camellia->ctx,key,klen>>3,NULL)))goto err2;
	if(U(wc_InitSha256(&h)))goto err2;
	if(U(wc_Sha256Update(&h,key,klen>>3)))goto err3;
	if(U(wc_Sha256Final(&h,tmp)))goto err3;
	if(U(wc_CamelliaSetKey(&camellia->aux,tmp,SHA256_DIGEST_SIZE,NULL)))
		goto err4;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err4:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->aux,sizeof(Camellia));
err3:	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
err2:	((struct usicrypt_thread *)ctx)->global->
		memclear(&camellia->ctx,sizeof(Camellia));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void wolf_camellia_essiv_exit(void *ctx)
{
	struct usicrypt_global *global;

	global=((struct wolf_camellia_essiv *)ctx)->global;
	global->memclear(ctx,sizeof(struct wolf_camellia_essiv));
	free(ctx);
}

#endif
#endif

int USICRYPT(random)(void *ctx,void *data,int len)
{
	if(U(wc_RNG_GenerateBlock(&((struct usicrypt_thread *)ctx)->rng,
		data,len)))return -1;
	return 0;
}

int USICRYPT(digest_size)(void *ctx,int md)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return SHA_DIGEST_SIZE;
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
	int res;
	struct wolf_md c;

	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
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
#endif
	default:goto err1;
	}

	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	res=wolf_md[c.idx].update(&c.ctx,in,len);
	if(U(wolf_md[c.idx].digest(&c.ctx,out))||U(res))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
	return 0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	return -1;
}

int USICRYPT(digest_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *out)
{
	int r=-1;
	int i;
	struct wolf_md c;

	switch(md)
	{
#if !defined(USICRYPT_NO_DIGEST) && !defined(USICRYPT_NO_IOV)
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
#endif
	default:goto err1;
	}

	if(U(wolf_md[c.idx].init(&c.ctx)))goto err1;
	for(i=0;i<niov;i++)if(U(wolf_md[c.idx].update(&c.ctx,iov[i].data,
		iov[i].length)))goto err2;
	if(U(wolf_md[c.idx].digest(&c.ctx,out)))goto err2;
	r=0;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&c.ctx,sizeof(c.ctx));
err1:	return r;
}

int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,int klen,
	void *out)
{
	int type;
	int res;
	Hmac h;

	switch(md)
	{
#ifndef USICRYPT_NO_HMAC
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=SHA;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=SHA512;
		break;
#endif
#endif
	default:goto err1;
	}

	if(U(wc_HmacSetKey(&h,type,key,klen)))goto err2;
	res=wc_HmacUpdate(&h,data,dlen);
	if(U(wc_HmacFinal(&h,out))||U(res))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
	return 0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
err1:	return -1;
}

int USICRYPT(hmac_iov)(void *ctx,int md,struct usicrypt_iov *iov,int niov,
	void *key,int klen,void *out)
{
	int r=-1;
	int i;
	int type;
	Hmac h;

	switch(md)
	{
#if !defined(USICRYPT_NO_HMAC) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=SHA;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=SHA512;
		break;
#endif
#endif
	default:goto err1;
	}

	if(U(wc_HmacSetKey(&h,type,key,klen)))goto err2;
	for(i=0;i<niov;i++)if(U(wc_HmacUpdate(&h,iov[i].data,iov[i].length)))
		goto err2;
	if(U(wc_HmacFinal(&h,out)))goto err2;
	r=0;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(&h,sizeof(h));
err1:	return r;
}

int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	int iter,void *out)
{
	int r=-1;
#ifndef USICRYPT_NO_PBKDF2
	int type;
	int len;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=SHA;
		len=SHA_DIGEST_SIZE;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=SHA256;
		len=SHA256_DIGEST_SIZE;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		if(L(!wolf_pbkdf2_384(ctx,out,key,klen,salt,slen,iter)))r=0;
		goto err1;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=SHA512;
		len=SHA512_DIGEST_SIZE;
		break;
#endif
	default:goto err1;
	}

	if(L(!wc_PBKDF2(out,key,klen,salt,slen,iter,len,type)))r=0;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#else
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
#endif
	return r;
}

int USICRYPT(hkdf)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	void *info,int ilen,void *out)
{
	int type;
	int len;

	switch(md)
	{
#ifndef USICRYPT_NO_HKDF
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=SHA;
		len=SHA_DIGEST_SIZE;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=SHA256;
		len=SHA256_DIGEST_SIZE;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=SHA384;
		len=SHA384_DIGEST_SIZE;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=SHA512;
		len=SHA512_DIGEST_SIZE;
		break;
#endif
#endif
	default:return -1;
	}

	return U(wc_HKDF(type,key,klen,salt,slen,info,ilen,out,len))?-1:0;
}

void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	word32 len;
	unsigned char *out;

	if(U(Base64_Encode_NoNl(in,ilen,NULL,&len)!=LENGTH_ONLY_E))goto err1;
	if(U(!(out=malloc(len+1))))goto err1;
	if(U(Base64_Encode_NoNl(in,ilen,out,&len)))goto err2;
	out[len]=0;
	*olen=len;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len+1);
	free(out);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	word32 len;
	unsigned char *out;

	len=ilen;
	if(U(!(out=malloc(ilen))))goto err1;
	if(U(Base64_Decode(in,ilen,out,&len)))goto err2;
	out=USICRYPT(do_realloc)(ctx,out,ilen,len);
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
	RsaKey *key;

	if(U(bits<USICRYPT_RSA_BITS_MIN)||U(bits>USICRYPT_RSA_BITS_MAX)||
		U(bits&7))goto err1;
	if(U(!(key=malloc(sizeof(RsaKey)))))goto err1;
	if(U(wc_InitRsaKey(key,NULL)))goto err2;
	if(U(wc_MakeRsaKey(key,bits,USICRYPT_RSA_EXPONENT,
		&((struct usicrypt_thread *)ctx)->rng)))goto err3;
	return key;

err3:	wc_FreeRsaKey(key);
err2:	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(rsa_size)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	int len;

	return L((len=wc_RsaEncryptSize(key))>0)?(len<<3):-1;
#else
	return -1;
#endif
}

void *USICRYPT(rsa_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_RSA
	unsigned char *key;
	unsigned char bfr[8192];

	if(U((*len=wc_RsaKeyToPublicDer(k,bfr,sizeof(bfr)))<=0))goto err1;
	if(U(!(key=malloc(*len))))goto err2;
	memcpy(key,bfr,*len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int n;
	word32 idx=0;
	RsaKey *rsa;

	if(U(!(rsa=malloc(sizeof(RsaKey)))))goto err1;
	if(U(wc_InitRsaKey(rsa,NULL)))goto err2;
	if(U(wc_RsaPublicKeyDecode(key,&idx,rsa,len)))goto err3;
	if(U((n=wc_RsaEncryptSize(rsa))<USICRYPT_RSA_BYTES_MIN)||
		U(n>USICRYPT_RSA_BYTES_MAX))goto err3;
	return rsa;

err3:	wc_FreeRsaKey(rsa);
err2:	free(rsa);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_RSA
	unsigned char *key;
	unsigned char bfr[8192];

	if(U((*len=wc_RsaKeyToDer(k,bfr,sizeof(bfr)))<=0))goto err1;
	if(U(!(key=malloc(*len))))goto err2;
	memcpy(key,bfr,*len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int n;
	word32 idx=0;
	RsaKey *rsa;

	if(U(!(rsa=malloc(sizeof(RsaKey)))))goto err1;
	if(U(wc_InitRsaKey(rsa,NULL)))goto err2;
	if(U(wc_RsaPrivateKeyDecode(key,&idx,rsa,len)))goto err3;
	if(U((n=wc_RsaEncryptSize(rsa))<USICRYPT_RSA_BYTES_MIN)||
		U(n>USICRYPT_RSA_BYTES_MAX))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return rsa;

err3:	wc_FreeRsaKey(rsa);
err2:	free(rsa);
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
	return wolf_rsa_do_sign_v15(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return wolf_rsa_do_sign_v15(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return wolf_rsa_do_verify_v15(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return wolf_rsa_do_verify_v15(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
	return NULL;
}

void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
	return NULL;
}

int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
	return -1;
}

int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
	return -1;
}

void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	unsigned char *out;

	*olen=wc_RsaEncryptSize(key);
	if(U(dlen>*olen-11))goto err1;
	if(U(!(out=malloc(*olen))))goto err1;
	if(U((*olen=wc_RsaPublicEncrypt(data,dlen,out,*olen,key,
		&((struct usicrypt_thread *)ctx)->rng))<0))goto err2;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l;
	int len;
	unsigned char *out;

	len=wc_RsaEncryptSize(key);
	if(U(dlen!=len))goto err1;
	if(U(!(out=malloc(len))))goto err1;
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=&((struct usicrypt_thread *)ctx)->rng;
#endif
	if(U((l=wc_RsaPrivateDecrypt(data,dlen,out,len,key))<0))goto err2;
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
	out=USICRYPT(do_realloc)(ctx,out,len,l);
	*olen=l;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_encrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int len;
	int type;
	int mgf;
	unsigned char *out;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		len=SHA_DIGEST_SIZE;
		type=WC_HASH_TYPE_SHA;
		mgf=WC_MGF1SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		len=SHA256_DIGEST_SIZE;
		type=WC_HASH_TYPE_SHA256;
		mgf=WC_MGF1SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		len=SHA384_DIGEST_SIZE;
		type=WC_HASH_TYPE_SHA384;
		mgf=WC_MGF1SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		len=SHA512_DIGEST_SIZE;
		type=WC_HASH_TYPE_SHA512;
		mgf=WC_MGF1SHA512;
		break;
#endif
	default:goto err1;
	}

	*olen=wc_RsaEncryptSize(key);
	if(U(dlen>*olen-2*len-2))goto err1;
	if(U(!(out=malloc(*olen))))goto err1;
	if(U((*olen=wc_RsaPublicEncrypt_ex(data,dlen,out,*olen,key,
		&((struct usicrypt_thread *)ctx)->rng,WC_RSA_OAEP_PAD,type,
		mgf,NULL,0))<0))goto err2;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,*olen);
	free(out);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_decrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int l;
	int len;
	int type;
	int mgf;
	unsigned char *out;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=WC_HASH_TYPE_SHA;
		mgf=WC_MGF1SHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=WC_HASH_TYPE_SHA256;
		mgf=WC_MGF1SHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=WC_HASH_TYPE_SHA384;
		mgf=WC_MGF1SHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=WC_HASH_TYPE_SHA512;
		mgf=WC_MGF1SHA512;
		break;
#endif
	default:goto err1;
	}

	len=wc_RsaEncryptSize(key);
	if(U(dlen!=len))goto err1;
	if(U(!(out=malloc(len))))goto err1;
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=&((struct usicrypt_thread *)ctx)->rng;
#endif
	if(U((l=wc_RsaPrivateDecrypt_ex(data,dlen,out,len,key,WC_RSA_OAEP_PAD,
		type,mgf,NULL,0))<0))goto err2;
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
	out=USICRYPT(do_realloc)(ctx,out,len,l);
	*olen=l;
	return out;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(out,len);
	free(out);
#ifdef WC_RSA_BLINDING
	((RsaKey *)key)->rng=NULL;
#endif
err1:	return NULL;
#else
	return NULL;
#endif
}

void USICRYPT(rsa_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	wc_FreeRsaKey(key);
	free(key);
#endif
}

void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len)
{
	return NULL;
}

void *USICRYPT(dh_init)(void *ctx,void *params,int len)
{
#ifndef USICRYPT_NO_DH
	word32 idx=0;
	struct wolf_dh *dh;

	if(U(!(dh=malloc(sizeof(struct wolf_dh)))))goto err1;
	wc_InitDhKey(&dh->dh);
	if(U(wc_DhKeyDecode(params,&idx,&dh->dh,len)))goto err2;
	idx=dh->dh.p.used*sizeof(mp_digit);
	if(U(idx<USICRYPT_DH_BYTES_MIN)||U(idx>USICRYPT_DH_BYTES_MAX))goto err2;
	dh->plen=0;
	return dh;

err2:	wc_FreeDhKey(&dh->dh);
	free(dh);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len)
{
#ifndef USICRYPT_NO_DH
	word32 size;
	struct wolf_dh *d=dh;
	byte *pub;

	if(d->plen)
	{
		((struct usicrypt_thread *)ctx)->global->
			memclear(d->priv,d->plen);
		free(d->priv);
	}
	size=d->dh.p.used*sizeof(mp_digit);
	d->plen=size;
	if(U(!(d->priv=malloc(size))))goto err1;
	if(U(!(pub=malloc(size))))goto err2;
	if(U(wc_DhGenerateKeyPair(&d->dh,&((struct usicrypt_thread *)ctx)->rng,
		d->priv,&d->plen,pub,&size)))goto err3;
	*len=size;
	return pub;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(pub,size);
	free(pub);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(d->priv,size);
	free(d->priv);
err1:	d->plen=0;
#endif
	return NULL;
}

void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,int *slen)
{
#ifndef USICRYPT_NO_DH
	struct wolf_dh *d=dh;
	word32 size=d->dh.p.used*sizeof(mp_digit);
	byte *sec;

	if(U(!(sec=malloc(size))))goto err1;
	if(U(wc_DhAgree(&d->dh,sec,&size,d->priv,d->plen,pub,plen)))goto err2;
	*slen=size;
	return sec;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(sec,size);
	free(sec);
err1:	return NULL;
#else
	return NULL;
#endif
}

void USICRYPT(dh_free)(void *ctx,void *dh)
{
#ifndef USICRYPT_NO_DH
	struct wolf_dh *d=dh;

	wc_FreeDhKey(&d->dh);
	if(d->plen)
	{
		((struct usicrypt_thread *)ctx)->global->
			memclear(d->priv,d->plen);
		free(d->priv);
	}
	free(d);
#endif
}

void *USICRYPT(ec_generate)(void *ctx,int curve)
{
#ifndef USICRYPT_NO_EC
	ecc_key *key;

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
	curve=wolf_ec_map[curve].id;
	if(U(!(key=malloc(sizeof(ecc_key)))))goto err1;
	if(U(wc_ecc_init(key)))goto err2;
	if(U(wc_ecc_make_key_ex(&((struct usicrypt_thread *)ctx)->rng,0,key,
		curve)))goto err3;
	return key;

err3:	wc_ecc_free(key);
err2:	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ec_identifier)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	int id;

	if(((ecc_key *)key)->idx!=-1)
		for(id=0;id<USICRYPT_TOT_EC_CURVES;id++)
			if(wolf_ec_map[id].id==((ecc_key *)key)->dp->id)
				return id;
#endif
	return -1;
}

void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_EC
	word32 len;
	unsigned char *sec;
	byte bfr[1024];

	len=sizeof(bfr);
	if(U(wc_ecc_shared_secret(key,pub,bfr,&len)))goto err1;
	*klen=len;
	if(U(!(sec=malloc(*klen))))goto err2;
	memcpy(sec,bfr,len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,len);
	return sec;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,len);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_pub)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	unsigned char *key;
	unsigned char bfr[1024];

	if(U((*len=wc_EccPublicKeyToDer(k,bfr,sizeof(bfr),1))<=0))goto err1;
	if(U(!(key=malloc(*len))))goto err2;
	memcpy(key,bfr,*len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	word32 idx=0;
	ecc_key *ec;

	if(U(!(ec=malloc(sizeof(ecc_key)))))goto err1;
	if(U(wc_ecc_init(ec)))goto err2;
	if(U(wc_EccPublicKeyDecode(key,&idx,ec,len)))goto err3;
	wolf_import_bugfix(ec,key,len);
	return ec;

err3:	wc_ecc_free(ec);
err2:	free(ec);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_key)(void *ctx,void *k,int *len)
{
#ifndef USICRYPT_NO_EC
	unsigned char *key;
	unsigned char bfr[1024];

	if(U((*len=wc_EccKeyToDer(k,bfr,sizeof(bfr)))<=0))goto err1;
	if(U(!(key=malloc(*len))))goto err2;
	memcpy(key,bfr,*len);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
	return key;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,*len);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	word32 idx=0;
	ecc_key *ec;

	if(U(!(ec=malloc(sizeof(ecc_key)))))goto err1;
	if(U(wc_ecc_init(ec)))goto err2;
	if(U(wc_EccPrivateKeyDecode(key,&idx,ec,len)))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return ec;

err3:	wc_ecc_free(ec);
err2:	free(ec);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_EC
	return wolf_ec_do_sign(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return wolf_ec_do_sign(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_EC
	return wolf_ec_do_verify(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return wolf_ec_do_verify(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void USICRYPT(ec_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	wc_ecc_free((ecc_key *)key);
	free(key);
#endif
}

void *USICRYPT(x25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_X25519
	curve25519_key *key;

	if(U(!(key=malloc(sizeof(curve25519_key)))))goto err1;
	if(U(wc_curve25519_init(key)))goto err2;
	if(U(wc_curve25519_make_key(&((struct usicrypt_thread *)ctx)->rng,32,
		key)))goto err3;
	return key;

err3:	wc_curve25519_free(key);
err2:	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_X25519
	word32 len=32;
	unsigned char *data;
	unsigned char bfr[32];

	if(U(wc_curve25519_shared_secret_ex(key,pub,bfr,&len,
		EC25519_LITTLE_ENDIAN)))goto err1;
	if(U(!(data=malloc(len))))goto err1;
	memcpy(data,bfr,len);
	*klen=len;
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return data;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	word32 l=32;
	unsigned char *data;

	*len=sizeof(wolf_x25519_asn1_pub)+32;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,wolf_x25519_asn1_pub,sizeof(wolf_x25519_asn1_pub));
	if(U(wc_curve25519_export_public_ex(key,
		data+sizeof(wolf_x25519_asn1_pub),&l,
		EC25519_LITTLE_ENDIAN)))goto err2;
	if(U(l!=32))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	curve25519_key *k;

	if(U(len<sizeof(wolf_x25519_asn1_pub)+32)||
	    U(memcmp(key,wolf_x25519_asn1_pub,sizeof(wolf_x25519_asn1_pub))))
		goto err1;
	if(U(!(k=malloc(sizeof(curve25519_key)))))goto err1;
	if(U(wc_curve25519_init(k)))goto err2;
	if(U(wc_curve25519_import_public_ex(
		((unsigned char *)key)+sizeof(wolf_x25519_asn1_pub),32,k,
		EC25519_LITTLE_ENDIAN)))goto err3;
	return k;

err3:	wc_curve25519_free(k);
err2:	free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
	word32 l=32;
	unsigned char *data;

	*len=sizeof(wolf_x25519_asn1_key)+32;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,wolf_x25519_asn1_key,sizeof(wolf_x25519_asn1_key));
	if(U(wc_curve25519_export_private_raw_ex(key,
		data+sizeof(wolf_x25519_asn1_key),&l,
		EC25519_LITTLE_ENDIAN)))goto err2;
	if(U(l!=32))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
	word32 l=32;
	curve25519_key *k;
	unsigned char bfr[32];

	if(U(len<sizeof(wolf_x25519_asn1_key)+32)||
	    U(memcmp(key,wolf_x25519_asn1_key,sizeof(wolf_x25519_asn1_key))))
		goto err1;
	if(U(!(k=malloc(sizeof(curve25519_key)))))goto err1;
	if(U(wc_curve25519_init(k)))goto err2;
	if(U(wc_curve25519_import_private_ex(
		((unsigned char *)key)+sizeof(wolf_x25519_asn1_key),32,k,
		EC25519_LITTLE_ENDIAN)))goto err3;
	if(U(wc_curve25519_import_public_ex(wolf_x25519_basepoint,32,k,
		EC25519_LITTLE_ENDIAN)))goto err3;
	if(U(wc_curve25519_shared_secret_ex(k,k,bfr,&l,
		EC25519_LITTLE_ENDIAN)))goto err3;
	if(U(l!=32))goto err4;
	if(U(wc_curve25519_import_public_ex(bfr,32,k,
		EC25519_LITTLE_ENDIAN)))goto err4;
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return k;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
err3:	wc_curve25519_free(k);
err2:	free(k);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void USICRYPT(x25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_X25519
	wc_curve25519_free(key);
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

	if(U(wolf_asn_next(data,dlen,0x30,&cidx,&didx)))goto err1;
	if(U(cidx+didx!=dlen))goto err1;

	for(didx=0;didx<4;didx++)if(wolf_digest_asn[didx].oidlen&&
		wolf_digest_asn[didx].digest==digest)break;
	if(U(didx==4))goto err1;

	for(cidx=0;cidx<24;cidx++)if(wolf_cipher_asn[cidx].oidlen&&
		wolf_cipher_asn[cidx].cipher==cipher&&
		wolf_cipher_asn[cidx].mode==mode&&
		wolf_cipher_asn[cidx].bits==bits)break;
	if(U(cidx==24))goto err1;

	if(U(USICRYPT(random)(ctx,salt,8)))goto err1;
	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,8,iter,bfr)))goto err2;

	if(wolf_cipher_asn[cidx].ivlen)
		if(U(USICRYPT(random)(ctx,iv,wolf_cipher_asn[cidx].ivlen)))
			goto err3;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,cipher,mode,bfr,bits,iv))))
		goto err4;

	if(iter>=0x800000)ilen=4;
	else if(iter>=0x8000)ilen=3;
	else if(iter>=0x80)ilen=2;
	else ilen=1;

	if(wolf_cipher_asn[cidx].pad)
		plen=usicrypt_cipher_padding_add(ctx,NULL,dlen);
	else plen=0;
	len1=wolf_asn_length(NULL,dlen+plen)+1;
	len2=wolf_cipher_asn[cidx].oidlen+wolf_cipher_asn[cidx].ivlen+6;
	len3=ilen+sizeof(wolf_pbes2_oid)+sizeof(wolf_pbkdf2_oid)+24;
	if(digest!=USICRYPT_SHA1)len3+=wolf_digest_asn[didx].oidlen+6;
	*rlen=wolf_asn_length(NULL,len1+len2+len3+dlen+plen)+
		len1+len2+len3+dlen+plen+1;

	if(U(!(ptr=out=malloc(*rlen))))goto err5;

	*ptr++=0x30;
	ptr+=wolf_asn_length(ptr,len1+len2+len3+dlen+plen);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(wolf_pbes2_oid);
	memcpy(ptr,wolf_pbes2_oid,sizeof(wolf_pbes2_oid));
	ptr+=sizeof(wolf_pbes2_oid);
	len3-=sizeof(wolf_pbes2_oid)+6;
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(wolf_pbkdf2_oid);
	memcpy(ptr,wolf_pbkdf2_oid,sizeof(wolf_pbkdf2_oid));
	ptr+=sizeof(wolf_pbkdf2_oid);
	*ptr++=0x30;
	*ptr++=(unsigned char)
	     (ilen+12+(digest!=USICRYPT_SHA1?wolf_digest_asn[didx].oidlen+6:0));
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
		*ptr++=(unsigned char)(wolf_digest_asn[didx].oidlen+4);
		*ptr++=0x06;
		*ptr++=(unsigned char)wolf_digest_asn[didx].oidlen;
		memcpy(ptr,wolf_digest_asn[didx].oid,
			wolf_digest_asn[didx].oidlen);
		ptr+=wolf_digest_asn[didx].oidlen;
		*ptr++=0x05;
		*ptr++=0x00;
	}
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)wolf_cipher_asn[cidx].oidlen;
	memcpy(ptr,wolf_cipher_asn[cidx].oid,wolf_cipher_asn[cidx].oidlen);
	ptr+=wolf_cipher_asn[cidx].oidlen;
	*ptr++=0x04;
	*ptr++=(unsigned char)wolf_cipher_asn[cidx].ivlen;
	if(wolf_cipher_asn[cidx].ivlen)
	{
		memcpy(ptr,iv,wolf_cipher_asn[cidx].ivlen);
		ptr+=wolf_cipher_asn[cidx].ivlen;
	}
	*ptr++=0x04;
	ptr+=wolf_asn_length(ptr,dlen+plen);
	memcpy(ptr,data,dlen);
	if(wolf_cipher_asn[cidx].pad)usicrypt_cipher_padding_add(ctx,ptr,dlen);

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

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	eptr=data+h+l;
	elen=dlen-h-l;
	data+=h;
	dlen=l;

	if(U(wolf_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(wolf_pbes2_oid))||
		U(memcmp(data+h,wolf_pbes2_oid,l)))goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(wolf_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(wolf_pbkdf2_oid))||U(memcmp(data+h,wolf_pbkdf2_oid,l)))
		goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;
	mlen=l;

	if(U(wolf_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	salt=data+h;
	slen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(wolf_asn_next(data,dlen,0x02,&h,&l)))goto err1;
	if(U(!l)||U(l>sizeof(int)))goto err1;
	iter=data+h;
	ilen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(mlen<0))goto err1;
	else if(mlen)
	{
		if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
		data+=h;
		dlen-=h;

		if(U(wolf_asn_next(data,dlen,0x06,&h,&l)))goto err1;
		md=data+h;
		mlen=l;
		data+=h+l;
		dlen-=h+l;

		if(U(wolf_asn_next(data,dlen,0x05,&h,&l)))goto err1;
		if(l)goto err1;
		data+=h;
		dlen-=h;
	}

	if(U(wolf_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(wolf_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	cipher=data+h;
	clen=l;
	data+=h+l;
	dlen-=h+l;

	if(U(wolf_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	iv=data+h;
	ivlen=l;
	data+=h+l;
	dlen-=h+l;
	if(data!=eptr)goto err1;

	if(U(wolf_asn_next(eptr,elen,0x04,&h,&l)))goto err1;
	eptr+=h;
	elen=l;

	for(l=0,h=0;h<ilen;h++)l=(l<<8)|iter[h];
	if(U(!l))goto err1;

	if(mlen)
	{
		for(h=0;h<4;h++)if(wolf_digest_asn[h].oidlen&&
			mlen==wolf_digest_asn[h].oidlen&&
			!memcmp(md,wolf_digest_asn[h].oid,mlen))break;
		if(U(h==4))goto err1;
		else digest=wolf_digest_asn[h].digest;
	}

	for(h=0;h<24;h++)if(wolf_cipher_asn[h].oidlen&&
		clen==wolf_cipher_asn[h].oidlen&&
		!memcmp(cipher,wolf_cipher_asn[h].oid,clen))break;
	if(U(h==24)||U(wolf_cipher_asn[h].ivlen!=ivlen)||
		U(wolf_cipher_asn[h].bits!=128&&digest==USICRYPT_SHA1))
			goto err1;

	if(wolf_cipher_asn[h].pad)if(U(elen&0x0f))goto err1;

	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,slen,l,bfr)))goto err1;

	if(U(!(out=malloc(elen))))goto err2;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,wolf_cipher_asn[h].cipher,
		wolf_cipher_asn[h].mode,bfr,wolf_cipher_asn[h].bits,iv))))
		goto err3;
	if(U(USICRYPT(blkcipher_decrypt)(c,eptr,elen,out)))goto err5;
	USICRYPT(blkcipher_exit)(c);

	if(wolf_cipher_asn[h].pad)
	{
		if(U((*rlen=usicrypt_cipher_padding_get(ctx,out,elen))==-1))
			goto err4;
		else *rlen=elen-*rlen;
	}
	else *rlen=elen;

	if(U(wolf_asn_next(out,*rlen,0x30,&h,&l)))goto err4;
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
		if(U(!(c=wolf_aes_ecb_init(ctx,key,klen))))break;
		c->encrypt=wolf_aes_ecb_encrypt;
		c->decrypt=wolf_aes_ecb_decrypt;
		c->reset=NULL;
		c->exit=wolf_aes_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		if(U(!(c=wolf_aes_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_cbc_encrypt;
		c->decrypt=wolf_aes_cbc_decrypt;
		c->reset=wolf_aes_cbc_reset;
		c->exit=wolf_aes_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_AES|USICRYPT_CTS:
		if(U(!(c=wolf_aes_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_cts_encrypt;
		c->decrypt=wolf_aes_cts_decrypt;
		c->reset=wolf_aes_cts_reset;
		c->exit=wolf_aes_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		if(U(!(c=wolf_aes_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_cfb_encrypt;
		c->decrypt=wolf_aes_cfb_decrypt;
		c->reset=wolf_aes_cfb_reset;
		c->exit=wolf_aes_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_AES|USICRYPT_CFB8:
		if(U(!(c=wolf_aes_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_cfb8_encrypt;
		c->decrypt=wolf_aes_cfb8_decrypt;
		c->reset=wolf_aes_cfb8_reset;
		c->exit=wolf_aes_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		if(U(!(c=wolf_aes_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_ofb_crypt;
		c->decrypt=wolf_aes_ofb_crypt;
		c->reset=wolf_aes_ofb_reset;
		c->exit=wolf_aes_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_AES|USICRYPT_CTR:
		if(U(!(c=wolf_aes_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_aes_ctr_crypt;
		c->decrypt=wolf_aes_ctr_crypt;
		c->reset=wolf_aes_ctr_reset;
		c->exit=wolf_aes_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		if(U(!(c=wolf_camellia_ecb_init(ctx,key,klen))))break;
		c->encrypt=wolf_camellia_ecb_encrypt;
		c->decrypt=wolf_camellia_ecb_decrypt;
		c->reset=NULL;
		c->exit=wolf_camellia_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		if(U(!(c=wolf_camellia_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_cbc_encrypt;
		c->decrypt=wolf_camellia_cbc_decrypt;
		c->reset=wolf_camellia_cbc_reset;
		c->exit=wolf_camellia_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_CAMELLIA|USICRYPT_CTS:
		if(U(!(c=wolf_camellia_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_cts_encrypt;
		c->decrypt=wolf_camellia_cts_decrypt;
		c->reset=wolf_camellia_cts_reset;
		c->exit=wolf_camellia_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		if(U(!(c=wolf_camellia_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_cfb_encrypt;
		c->decrypt=wolf_camellia_cfb_decrypt;
		c->reset=wolf_camellia_cfb_reset;
		c->exit=wolf_camellia_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_CAMELLIA|USICRYPT_CFB8:
		if(U(!(c=wolf_camellia_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_cfb8_encrypt;
		c->decrypt=wolf_camellia_cfb8_decrypt;
		c->reset=wolf_camellia_cfb8_reset;
		c->exit=wolf_camellia_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		if(U(!(c=wolf_camellia_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_ofb_crypt;
		c->decrypt=wolf_camellia_ofb_crypt;
		c->reset=wolf_camellia_ofb_reset;
		c->exit=wolf_camellia_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_CAMELLIA|USICRYPT_CTR:
		if(U(!(c=wolf_camellia_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_camellia_ctr_crypt;
		c->decrypt=wolf_camellia_ctr_crypt;
		c->reset=wolf_camellia_ctr_reset;
		c->exit=wolf_camellia_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20|USICRYPT_STREAM:
		if(U(!(c=wolf_chacha_init(ctx,key,klen,iv))))break;
		c->encrypt=wolf_chacha_crypt;
		c->decrypt=wolf_chacha_crypt;
		c->reset=wolf_chacha_reset;
		c->exit=wolf_chacha_exit;
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
		if(U(!(c=wolf_aes_xts_init(ctx,key,klen))))break;
		c->encrypt=wolf_aes_xts_encrypt;
		c->decrypt=wolf_aes_xts_decrypt;
		c->exit=wolf_aes_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_AES|USICRYPT_ESSIV:
		if(U(!(c=wolf_aes_essiv_init(ctx,key,klen))))break;
		c->encrypt=wolf_aes_essiv_encrypt;
		c->decrypt=wolf_aes_essiv_decrypt;
		c->exit=wolf_aes_essiv_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_XTS
	case USICRYPT_CAMELLIA|USICRYPT_XTS:
		if(U(!(c=wolf_camellia_xts_init(ctx,key,klen))))break;
		c->encrypt=wolf_camellia_xts_encrypt;
		c->decrypt=wolf_camellia_xts_decrypt;
		c->exit=wolf_camellia_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_CAMELLIA|USICRYPT_ESSIV:
		if(U(!(c=wolf_camellia_essiv_init(ctx,key,klen))))break;
		c->encrypt=wolf_camellia_essiv_encrypt;
		c->decrypt=wolf_camellia_essiv_decrypt;
		c->exit=wolf_camellia_essiv_exit;
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
		if(U(!(c=wolf_aes_gcm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=wolf_aes_gcm_encrypt;
		c->decrypt=wolf_aes_gcm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=wolf_aes_gcm_encrypt_iov;
		c->decrypt_iov=wolf_aes_gcm_decrypt_iov;
#endif
		c->exit=wolf_aes_gcm_exit;
		break;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		if(U(!(c=wolf_aes_ccm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=wolf_aes_ccm_encrypt;
		c->decrypt=wolf_aes_ccm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=wolf_aes_ccm_encrypt_iov;
		c->decrypt_iov=wolf_aes_ccm_decrypt_iov;
#endif
		c->exit=wolf_aes_ccm_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		if(U(!(c=wolf_chacha_poly_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=wolf_chacha_poly_encrypt;
		c->decrypt=wolf_chacha_poly_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=wolf_chacha_poly_encrypt_iov;
		c->decrypt_iov=wolf_chacha_poly_decrypt_iov;
#endif
		c->exit=wolf_chacha_poly_exit;
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
		return wolf_aes_cmac(ctx,key,klen,src,slen,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return wolf_camellia_cmac(ctx,key,klen,src,slen,dst);
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
		return wolf_aes_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return wolf_camellia_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(thread_init)(void *global)
{
	struct usicrypt_thread *ctx;

	if(U(!(ctx=malloc(sizeof(struct usicrypt_thread)))))goto err1;
	ctx->global=global;
	if(U(wc_InitRng(&ctx->rng)))goto err2;
	return ctx;

err2:	free(ctx);
err1:	return NULL;
}

void USICRYPT(thread_exit)(void *ctx)
{
	wc_FreeRng(&((struct usicrypt_thread *)ctx)->rng);
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
	if(U(wolfSSL_Init()!=SSL_SUCCESS))goto err2;
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_GCM
#ifdef WOLFSSL_AESNI
	if(USICRYPT(get_features)()&1)wolf_need_gcm_bugfix=1;
#endif
#endif
#endif
	return ctx;

err2:	free(ctx);
err1:	return NULL;
}

void USICRYPT(global_exit)(void *ctx)
{
	wolfSSL_Cleanup();
	free(ctx);
}

#endif
