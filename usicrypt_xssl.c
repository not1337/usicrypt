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
#ifndef USICRYPT_XSSL
#define USICRYPT_XSSL
#endif
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#if defined(USICRYPT_XSSL)

#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#if defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/chacha.h>
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
#include <openssl/curve25519.h>
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
#include <openssl/kdf.h>
#include <openssl/pkcs12.h>
#endif
#include <openssl/camellia.h>
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3020000fL
#include <openssl/hkdf.h>
#endif
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(_WIN64) || defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
#define XSSL_HAS_CURVE448
#endif

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) xssl_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

/******************************************************************************/
/*                            OpenSSL and LibreSSL                            */
/******************************************************************************/

struct xssl_aes_ecb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	AES_KEY dec;
};

struct xssl_aes_cbc
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	AES_KEY dec;
	unsigned char iv[16];
};

struct xssl_aes_cfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	int num;
	unsigned char iv[16];
};

struct xssl_aes_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	unsigned char iv[16];
};

struct xssl_aes_ofb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	int n;
	unsigned char iv[16];
	unsigned char zero[16];
};

struct xssl_aes_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	unsigned int n;
	unsigned char iv[16];
	unsigned char bfr[16];
	unsigned char zero[16];
};

struct xssl_aes_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	EVP_CIPHER_CTX *enc;
	EVP_CIPHER_CTX *dec;
};

struct xssl_aes_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	AES_KEY enc;
	AES_KEY dec;
	AES_KEY aux;
	unsigned char iv[16];
};

struct xssl_aes_xcm
{
	struct usicrypt_aeadcipher cipher;
	struct usicrypt_global *global;
	EVP_CIPHER_CTX *enc;
	EVP_CIPHER_CTX *dec;
	int ilen;
	int tlen;
};

#if defined(LIBRESSL_VERSION_NUMBER)
struct xssl_chacha_poly
{
	struct usicrypt_aeadcipher cipher;
	EVP_AEAD_CTX enc;
};

struct xssl_chacha
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	ChaCha_ctx ctx;
};
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
struct xssl_chacha_poly
{
	struct usicrypt_aeadcipher cipher;
	EVP_CIPHER_CTX *enc;
	EVP_CIPHER_CTX *dec;
};

struct xssl_chacha
{
	struct usicrypt_cipher cipher;
	EVP_CIPHER_CTX *ctx;
};
#endif

struct xssl_camellia_ecb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY ctx;
};

struct xssl_camellia_cbc
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY ctx;
	unsigned char iv[16];
};

struct xssl_camellia_cfb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY enc;
	int num;
	unsigned char iv[16];
};

struct xssl_camellia_cfb8
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY enc;
	unsigned char iv[16];
};

struct xssl_camellia_ofb
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY enc;
	int n;
	unsigned char iv[16];
	unsigned char zero[16];
};

struct xssl_camellia_ctr
{
	struct usicrypt_cipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY enc;
	unsigned int n;
	unsigned char iv[16];
	unsigned char bfr[16];
	unsigned char zero[16];
};

struct xssl_camellia_xts
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY ctx;
	CAMELLIA_KEY twe;
	unsigned char twk[16];
	unsigned char wrk[16];
	unsigned char mem[16];
};

struct xssl_camellia_essiv
{
	struct usicrypt_dskcipher cipher;
	struct usicrypt_global *global;
	CAMELLIA_KEY ctx;
	CAMELLIA_KEY aux;
	unsigned char iv[16];
};

#if defined(LIBRESSL_VERSION_NUMBER) && !defined(USICRYPT_NO_PBKDF2)

static const unsigned char xssl_pbes2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0d
};

static const unsigned char xssl_pbkdf2_oid[9]=
{
	0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x05,0x0c
};

static const struct
{
	const int digest;
	const int oidlen;
	const unsigned char oid[0x08];

} xssl_digest_asn[4]=
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
} xssl_cipher_asn[24]=
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

#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20500000L

struct xssl_x25519
{
	unsigned char pub[X25519_KEY_LENGTH];
	unsigned char key[X25519_KEY_LENGTH];
};

#endif
#if ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20500000L ) || ( !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L )

static const unsigned char xssl_x25519_asn1_pub[12]=
{
	0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6e,0x03,0x21,0x00
};

static const unsigned char xssl_x25519_asn1_key[16]=
{
	0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20
};

#endif
#endif

#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)

static const unsigned char xssl_x448_asn1_pub[12]=
{
	0x30,0x42,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6f,0x03,0x39,0x00
};

static const unsigned char xssl_x448_asn1_key[16]=
{
	0x30,0x46,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6f,0x04,0x3a,0x04,0x38
};

#endif

static int xssl_reseed(void *ctx)
{
	int r=-1;
	unsigned char bfr[32];

	if(U(((struct usicrypt_thread *)ctx)->global->
		rng_seed(bfr,sizeof(bfr))))goto err1;
	RAND_add(bfr,sizeof(bfr),sizeof(bfr));
	r=0;
err1:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return r;
}

#if !defined(USICRYPT_NO_THREADS)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L

#if defined(_WIN64) || defined(_WIN32)
static HANDLE *xssl_lock;
#else
static pthread_mutex_t *xssl_lock;
#endif

#if defined(_WIN64) || defined(_WIN32)

static void xssl_locker(int mode,int type,const char *file,int line)
{
	if(mode&CRYPTO_LOCK)WaitForSingleObject(xssl_lock[type]);
	else ReleaseMutex(xssl_lock[type]);
}

#else

static void xssl_locker(int mode,int type,const char *file,int line)
{
	if(mode&CRYPTO_LOCK)pthread_mutex_lock(&xssl_lock[type]);
	else pthread_mutex_unlock(&xssl_lock[type]);
}

static void xssl_gettid(CRYPTO_THREADID *tid)
{
	CRYPTO_THREADID_set_numeric(tid,(unsigned long)pthread_self());
}

#endif

#endif
#endif

#if defined(LIBRESSL_VERSION_NUMBER) && !defined(USICRYPT_NO_PBKDF2)

static int xssl_asn_length(unsigned char *ptr,int len)
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

static int xssl_asn_next(unsigned char *prm,int len,unsigned char id,
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
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3020000fL

#define RSA_padding_add_PKCS1_OAEP_mgf1(a,b,c,d,e,f,g,h) \
	xssl_add_oaep_mgf1(a,b,c,d,e,f,(void *)g)

static int xssl_add_oaep_mgf1(unsigned char *dst,int dlen,
	unsigned char *src,int slen,unsigned char *p,int plen,
	void *md)
{
	int i;
	int len;
	unsigned char *dm;
	unsigned char sm[SHA512_DIGEST_LENGTH];

	len=EVP_MD_size(md);
	if(U(dlen-1<2*len+1))goto err1;
	dst[0]=0x00;
	if(U(RAND_bytes(dst+1,len)!=1))goto err1;
	if(U(!EVP_Digest(p,plen,dst+len+1,NULL,md,NULL)))goto err1;
	memset(dst+2*len+1,0,dlen-slen-2*len-2);
	dst[dlen-slen-1]=0x01;
	memcpy(dst+dlen-slen,src,slen);
	if(U(!(dm=malloc(dlen-len-1))))goto err1;
	if(U(PKCS1_MGF1(dm,dlen-len-1,dst+1,len,md)))goto err2;
	for(i=0;i<dlen-len-1;i++)dst[i+len+1]^=dm[i];
	if(U(PKCS1_MGF1(sm,len,dst+len+1,dlen-len-1,md)))goto err3;
	for(i=0;i<len;i++)dst[i+1]^=sm[i];
	OPENSSL_cleanse(sm,sizeof(sm));
	OPENSSL_cleanse(dm,dlen-len-1);
	free(dm);
	return 1;

err3:	OPENSSL_cleanse(sm,sizeof(sm));
err2:	OPENSSL_cleanse(dm,dlen-len-1);
	free(dm);
err1:	return 0;
}

#define RSA_padding_check_PKCS1_OAEP_mgf1(a,b,c,d,e,f,g,h,i) \
	xssl_check_oaep_mgf1(a,b,c,d,e,f,g,(void *)h)

static int xssl_check_oaep_mgf1(unsigned char *dst,int dlen,
	unsigned char *src,int slen,int n,unsigned char *p,
	int plen,void *md)
{
	int i;
	int l;
	int len;
	unsigned char *mem;
	unsigned char wrk[SHA512_DIGEST_LENGTH];

	len=EVP_MD_size(md);
	if(U(n<2*len+2)||U(n-1<slen))goto err1;
	if(U(!(mem=malloc(2*n-len-2))))goto err1;
	memset(mem+n-len-1,0,n-slen-1);
	memcpy(mem+2*n-slen-len-2,src,slen);
	if(U(PKCS1_MGF1(wrk,len,mem+n-1,n-len-1,md)))goto err2;
	for(i=0;i<len;i++)wrk[i]^=mem[i+n-len-1];
	if(U(PKCS1_MGF1(mem,n-len-1,wrk,len,md)))goto err2;
	for(i=0;i<n-len-1;i++)mem[i]^=mem[i+n-1];
	if(!EVP_Digest(p,plen,wrk,NULL,md,NULL))goto err2;
	if(memcmp(mem,wrk,len))goto err2;
	for(i=len;i<n-len-1;i++)if(mem[i])break;
	if(U(i==n-len-1)||U(mem[i]!=0x01))goto err2;
	if(U(dlen<(l=n-i-len-2)))goto err2;
	memcpy(dst,mem+i+1,l);
	OPENSSL_cleanse(wrk,sizeof(wrk));
	OPENSSL_cleanse(mem,2*n-len-2);
	free(mem);
	return l;

err2:	OPENSSL_cleanse(wrk,sizeof(wrk));
	OPENSSL_cleanse(mem,2*n-len-2);
	free(mem);
err1:	return -1;
}

#endif

static void *xssl_rsa_do_sign_v15(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
#ifndef USICRYPT_NO_RSA
	int i;
	int len;
	struct usicrypt_iov *iov=data;
	EVP_MD_CTX *c;
	const EVP_MD *digest;
	RSA *rsa;
	unsigned char *sig=NULL;
	unsigned char *tmp;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(!EVP_DigestInit_ex(c,digest,NULL)))goto err2;
	if(!mode)
	{
		if(U(!EVP_DigestUpdate(c,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(!EVP_DigestUpdate(c,iov[i].data,iov[i].length)))
			goto err2;
	if(U(!EVP_DigestFinal_ex(c,hash,NULL)))goto err2;

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err2;
	*slen=RSA_size(rsa);
	if(U(!(tmp=malloc(*slen))))goto err3;
	if(U(!(sig=malloc(*slen))))goto err4;
	if(U(!(RSA_padding_add_PKCS1_type_1(tmp,*slen,hash,len))))goto err6;
	if(L(RSA_private_encrypt(*slen,tmp,sig,rsa,RSA_NO_PADDING)==*slen))
		goto err5;

	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
err6:	free(sig);
	sig=NULL;
err5:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*slen);
err4:	free(tmp);
err3:	RSA_free(rsa);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	EVP_MD_CTX_destroy(c);
err1:	return sig;
#else
	return NULL;
#endif
}

static int xssl_rsa_do_verify_v15(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
#ifndef USICRYPT_NO_RSA
	int r=-1;
	int i;
	int len;
	struct usicrypt_iov *iov=data;
	EVP_MD_CTX *c;
	const EVP_MD *digest;
	RSA *rsa;
	unsigned char *tmp;
	unsigned char hash[SHA512_DIGEST_LENGTH];
	unsigned char cmp[SHA512_DIGEST_LENGTH];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(!EVP_DigestInit_ex(c,digest,NULL)))goto err2;
	if(!mode)
	{
		if(U(!EVP_DigestUpdate(c,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(!EVP_DigestUpdate(c,iov[i].data,iov[i].length)))
			goto err2;
	if(U(!EVP_DigestFinal_ex(c,hash,NULL)))goto err2;

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err2;
	if(U(RSA_size(rsa)!=slen))goto err3;
	if(U(!(tmp=malloc(slen))))goto err3;
	if(U(RSA_public_decrypt(slen,sig,tmp,rsa,RSA_NO_PADDING)!=slen))
		goto err4;
	if(U(tmp[0]))goto err4;
	if(U(RSA_padding_check_PKCS1_type_1(cmp,sizeof(cmp),tmp+1,slen-1,slen)
		!=len))goto err5;
	if(U(memcmp(hash,cmp,len)))goto err5;
	r=0;

err5:	((struct usicrypt_thread *)ctx)->global->memclear(cmp,sizeof(cmp));
err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,slen);
	free(tmp);
err3:	RSA_free(rsa);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	EVP_MD_CTX_destroy(c);
err1:	return r;
#else
	return -1;
#endif
}

static void *xssl_rsa_do_sign_pss(void *ctx,int md,void *key,void *data,
	int dlen,int *slen,int mode)
{
#ifndef USICRYPT_NO_RSA
	int i;
	int len;
	struct usicrypt_iov *iov=data;
	EVP_MD_CTX *c;
	RSA *rsa;
	void *type;
	unsigned char *tmp;
	unsigned char *sig=NULL;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(!EVP_DigestInit_ex(c,type,NULL)))goto err2;
	if(!mode)
	{
		if(U(!EVP_DigestUpdate(c,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(!EVP_DigestUpdate(c,iov[i].data,iov[i].length)))
			goto err2;
	if(U(!EVP_DigestFinal_ex(c,hash,NULL)))goto err2;

	if(U(xssl_reseed(ctx)))goto err2;
	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err2;
	*slen=RSA_size(rsa);
	if(U(*slen-2*len-2<0))goto err3;
	if(U(!(tmp=malloc(*slen))))goto err3;
	if(U(!(sig=malloc(*slen))))goto err4;
	if(U(!(RSA_padding_add_PKCS1_PSS(rsa,tmp,hash,type,-2))))goto err5;
	if(L(RSA_private_encrypt(*slen,tmp,sig,rsa,RSA_NO_PADDING)==*slen))
		goto err4;

	((struct usicrypt_thread *)ctx)->global->memclear(sig,*slen);
err5:	free(sig);
	sig=NULL;
err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*slen);
	free(tmp);
err3:	RSA_free(rsa);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	EVP_MD_CTX_destroy(c);
err1:	return sig;
#else
	return NULL;
#endif
}

static int xssl_rsa_do_verify_pss(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen,int mode)
{
#ifndef USICRYPT_NO_RSA
	int r=-1;
	int i;
	int len;
	struct usicrypt_iov *iov=data;
	EVP_MD_CTX *c;
	RSA *rsa;
	void *type;
	unsigned char *tmp;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(!EVP_DigestInit_ex(c,type,NULL)))goto err2;
	if(!mode)
	{
		if(U(!EVP_DigestUpdate(c,data,dlen)))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(!EVP_DigestUpdate(c,iov[i].data,iov[i].length)))
			goto err2;
	if(U(!EVP_DigestFinal_ex(c,hash,NULL)))goto err2;

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err2;
	if(U(RSA_size(rsa)!=slen))goto err2;
	if(U(slen-2*len-2<0))goto err2;
	if(U(!(tmp=malloc(slen))))goto err3;
	if(U(RSA_public_decrypt(slen,sig,tmp,rsa,RSA_NO_PADDING)!=slen))
		goto err4;
	if(U(RSA_verify_PKCS1_PSS(rsa,hash,type,tmp,-2)!=1))goto err4;
	r=0;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,slen);
	free(tmp);
err3:	RSA_free(rsa);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(hash,sizeof(hash));
	EVP_MD_CTX_destroy(c);
err1:	return r;
#else
	return -1;
#endif
}

#endif
#ifndef USICRYPT_NO_EC

static void *xssl_ec_do_sign(void *ctx,int md,void *key,void *data,int dlen,
	int *slen,int mode)
{
	size_t l;
	struct usicrypt_iov *iov=data;
	void *sig;
	void *type;
	EVP_MD_CTX *c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		break;
#endif
	default:goto err1;
	}

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(EVP_DigestSignInit(c,NULL,type,NULL,key)!=1))goto err2;
	if(!mode)
	{
		if(U(EVP_DigestSignUpdate(c,data,dlen)!=1))goto err2;
	}
	else for(l=0;l<dlen;l++)
		if(U(EVP_DigestSignUpdate(c,iov[l].data,iov[l].length)!=1))
			goto err2;
	if(U(EVP_DigestSignFinal(c,NULL,&l)!=1))goto err2;
	if(U(!(sig=malloc(l))))goto err2;
	if(U(EVP_DigestSignFinal(c,sig,&l)!=1))goto err3;
	EVP_MD_CTX_destroy(c);
	*slen=l;
	return sig;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(sig,l);
	free(sig);
err2:	EVP_MD_CTX_destroy(c);
err1:	return NULL;
}

static int xssl_ec_do_verify(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen,int mode)
{
	int r=-1;
	int i;
	struct usicrypt_iov *iov=data;
	void *type;
	EVP_MD_CTX *c;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		break;
#endif
	default:goto err1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(EVP_DigestVerifyInit(c,NULL,type,NULL,key)!=1))goto err2;
	if(!mode)
	{
		if(U(EVP_DigestVerifyUpdate(c,data,dlen)!=1))goto err2;
	}
	else for(i=0;i<dlen;i++)
		if(U(EVP_DigestVerifyUpdate(c,iov[i].data,iov[i].length))!=1)
			goto err2;
	if(U(EVP_DigestVerifyFinal(c,sig,slen)!=1))goto err2;
	r=0;
err2:	EVP_MD_CTX_destroy(c);
err1:	return r;
}

#endif
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_CMAC

static int xssl_aes_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	size_t unused;
	CMAC_CTX *c;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 256:
		type=EVP_aes_256_cbc();
		break;
	case 192:
		type=EVP_aes_192_cbc();
		break;
	case 128:
		type=EVP_aes_128_cbc();
		break;
	default:goto err1;
	}
	if(U(!(c=CMAC_CTX_new())))goto err1;
	if(U(CMAC_Init(c,key,klen>>3,type,NULL)!=1))goto err2;
	if(U(CMAC_Update(c,src,slen)!=1))goto err2;
	if(U(CMAC_Final(c,dst,&unused)!=1))goto err2;
	CMAC_CTX_free(c);
	return 0;

err2:	CMAC_CTX_free(c);
err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_aes_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	size_t unused;
	CMAC_CTX *c;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 256:
		type=EVP_aes_256_cbc();
		break;
	case 192:
		type=EVP_aes_192_cbc();
		break;
	case 128:
		type=EVP_aes_128_cbc();
		break;
	default:goto err1;
	}
	if(U(!(c=CMAC_CTX_new())))goto err1;
	if(U(CMAC_Init(c,key,klen>>3,type,NULL)!=1))goto err2;
	for(i=0;i<niov;i++)if(U(CMAC_Update(c,iov[i].data,iov[i].length)!=1))
		goto err2;
	if(U(CMAC_Final(c,dst,&unused)!=1))goto err2;
	CMAC_CTX_free(c);
	return 0;

err2:	CMAC_CTX_free(c);
err1:	return -1;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int xssl_aes_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)AES_ecb_encrypt(s,d,
		&((struct xssl_aes_ecb *)ctx)->enc,AES_ENCRYPT);
	return 0;
}

static int xssl_aes_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)AES_ecb_encrypt(s,d,
		&((struct xssl_aes_ecb *)ctx)->dec,AES_DECRYPT);
	return 0;
}

static void *xssl_aes_ecb_init(void *ctx,void *key,int klen)
{
	struct xssl_aes_ecb *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_ecb)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(U(AES_set_decrypt_key(key,klen,&aes->dec)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	aes->global->memclear(&aes->dec,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_ecb_exit(void *ctx)
{
	((struct xssl_aes_ecb *)ctx)->global->memclear(
		&((struct xssl_aes_ecb *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_ecb *)ctx)->global->memclear(
		&((struct xssl_aes_ecb *)ctx)->dec,sizeof(AES_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int xssl_aes_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)AES_cbc_encrypt(s,d,16,
		&((struct xssl_aes_cbc *)ctx)->enc,
		((struct xssl_aes_cbc *)ctx)->iv,AES_ENCRYPT);
	return 0;
}

static int xssl_aes_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)AES_cbc_encrypt(s,d,16,
		&((struct xssl_aes_cbc *)ctx)->dec,
		((struct xssl_aes_cbc *)ctx)->iv,AES_DECRYPT);
	return 0;
}

static void *xssl_aes_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_cbc *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_cbc)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(U(AES_set_decrypt_key(key,klen,&aes->dec)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	aes->global->memclear(&aes->dec,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_aes_cbc *)ctx)->iv,iv,16);
}

static void xssl_aes_cbc_exit(void *ctx)
{
	((struct xssl_aes_cbc *)ctx)->global->memclear(
		&((struct xssl_aes_cbc *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_cbc *)ctx)->global->memclear(
		&((struct xssl_aes_cbc *)ctx)->dec,sizeof(AES_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int xssl_aes_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen<=16))return -1;
	CRYPTO_cts128_encrypt(src,dst,slen,&((struct xssl_aes_cbc *)ctx)->enc,
		((struct xssl_aes_cbc *)ctx)->iv,(void *)AES_cbc_encrypt);
	return 0;
}

static int xssl_aes_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen<=16))return -1;
	CRYPTO_cts128_decrypt(src,dst,slen,&((struct xssl_aes_cbc *)ctx)->dec,
		((struct xssl_aes_cbc *)ctx)->iv,(void *)AES_cbc_encrypt);
	return 0;
}

static void *xssl_aes_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_cbc *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_cbc)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(U(AES_set_decrypt_key(key,klen,&aes->dec)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	aes->global->memclear(&aes->dec,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_aes_cbc *)ctx)->iv,iv,16);
}

static void xssl_aes_cts_exit(void *ctx)
{
	((struct xssl_aes_cbc *)ctx)->global->memclear(
		&((struct xssl_aes_cbc *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_cbc *)ctx)->global->memclear(
		&((struct xssl_aes_cbc *)ctx)->dec,sizeof(AES_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int xssl_aes_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	AES_cfb128_encrypt(src,dst,slen,&((struct xssl_aes_cfb *)ctx)->enc,
		((struct xssl_aes_cfb *)ctx)->iv,
		&((struct xssl_aes_cfb *)ctx)->num,AES_ENCRYPT);
	return 0;
}

static int xssl_aes_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	AES_cfb128_encrypt(src,dst,slen,&((struct xssl_aes_cfb *)ctx)->enc,
		((struct xssl_aes_cfb *)ctx)->iv,
		&((struct xssl_aes_cfb *)ctx)->num,AES_DECRYPT);
	return 0;
}

static void *xssl_aes_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_cfb *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_cfb)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	aes->num=0;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_cfb_reset(void *ctx,void *iv)
{
	((struct xssl_aes_cfb *)ctx)->num=0;
	memcpy(((struct xssl_aes_cfb *)ctx)->iv,iv,16);
}

static void xssl_aes_cfb_exit(void *ctx)
{
	((struct xssl_aes_cfb *)ctx)->global->memclear(
		&((struct xssl_aes_cfb *)ctx)->enc,sizeof(AES_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int xssl_aes_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	AES_cfb8_encrypt(src,dst,slen,&((struct xssl_aes_cfb8 *)ctx)->enc,
		((struct xssl_aes_cfb8 *)ctx)->iv,NULL,AES_ENCRYPT);
	return 0;
}

static int xssl_aes_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	AES_cfb8_encrypt(src,dst,slen,&((struct xssl_aes_cfb8 *)ctx)->enc,
		((struct xssl_aes_cfb8 *)ctx)->iv,NULL,AES_DECRYPT);
	return 0;
}

static void *xssl_aes_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_cfb8 *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_cfb8)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_aes_cfb8 *)ctx)->iv,iv,16);
}

static void xssl_aes_cfb8_exit(void *ctx)
{
	((struct xssl_aes_cfb8 *)ctx)->global->memclear(
		&((struct xssl_aes_cfb8 *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_cfb8 *)ctx)->global->memclear(
		((struct xssl_aes_cfb8 *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int xssl_aes_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct xssl_aes_ofb *aes=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			AES_ofb128_encrypt(aes->zero,dst,16,&aes->enc,
				aes->iv,&aes->n);
		AES_ofb128_encrypt(aes->zero,dst,slen,&aes->enc,
			aes->iv,&aes->n);
	}
	else AES_ofb128_encrypt(src,dst,slen,&aes->enc,aes->iv,&aes->n);
	return 0;
}

static void *xssl_aes_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_ofb *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_ofb)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	memset(aes->zero,0,16);
	aes->n=0;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_ofb_reset(void *ctx,void *iv)
{
	((struct xssl_aes_ofb *)ctx)->n=0;
	memcpy(((struct xssl_aes_ofb *)ctx)->iv,iv,16);
}

static void xssl_aes_ofb_exit(void *ctx)
{
	((struct xssl_aes_ofb *)ctx)->global->memclear(
		&((struct xssl_aes_ofb *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_ofb *)ctx)->global->memclear(
		((struct xssl_aes_ofb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int xssl_aes_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct xssl_aes_ctr *aes=ctx;

#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			AES_ctr128_encrypt(aes->zero,dst,16,&aes->enc,
				aes->iv,aes->bfr,&aes->n);
		AES_ctr128_encrypt(aes->zero,dst,slen,&aes->enc,
			aes->iv,aes->bfr,&aes->n);
	}
	else AES_ctr128_encrypt(src,dst,slen,&aes->enc,
		aes->iv,aes->bfr,&aes->n);
#else
	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			CRYPTO_ctr128_encrypt(aes->zero,dst,16,&aes->enc,
				aes->iv,aes->bfr,&aes->n,
				(block128_f)AES_encrypt);
		CRYPTO_ctr128_encrypt(aes->zero,dst,slen,&aes->enc,
			aes->iv,aes->bfr,&aes->n,(block128_f)AES_encrypt);
	}
	else CRYPTO_ctr128_encrypt(src,dst,slen,&aes->enc,
		aes->iv,aes->bfr,&aes->n,(block128_f)AES_encrypt);
#endif
	return 0;
}

static void *xssl_aes_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_aes_ctr *aes;

	if(U(!(aes=malloc(sizeof(struct xssl_aes_ctr)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	memset(aes->zero,0,16);
	aes->n=0;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(iv)memcpy(aes->iv,iv,16);
	else memset(aes->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_ctr_reset(void *ctx,void *iv)
{
	((struct xssl_aes_ctr *)ctx)->n=0;
	memcpy(((struct xssl_aes_ctr *)ctx)->iv,iv,16);
}

static void xssl_aes_ctr_exit(void *ctx)
{
	((struct xssl_aes_ctr *)ctx)->global->memclear(
		&((struct xssl_aes_ctr *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_ctr *)ctx)->global->memclear(
		&((struct xssl_aes_ctr *)ctx)->bfr,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int xssl_aes_xts_encrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int len;

	if(U(slen<16))goto err1;
	if(U(EVP_EncryptInit_ex(((struct xssl_aes_xts *)ctx)->enc,NULL,NULL,
		NULL,iv)!=1))goto err1;
	if(U(EVP_EncryptUpdate(((struct xssl_aes_xts *)ctx)->enc,dst,&len,
		src,slen)!=1))goto err1;
	if(U(EVP_EncryptFinal_ex(((struct xssl_aes_xts *)ctx)->enc,
		((unsigned char *)dst)+len,&len)!=1))goto err1;
	return 0;

err1:	return -1;
}

static int xssl_aes_xts_decrypt(void *ctx,void *iv,void *src,int slen,void *dst)
{
	int len;

	if(U(slen<16))goto err1;
	if(U(EVP_DecryptInit_ex(((struct xssl_aes_xts *)ctx)->dec,NULL,NULL,
		NULL,iv)!=1))goto err1;
	if(U(EVP_DecryptUpdate(((struct xssl_aes_xts *)ctx)->dec,dst,&len,
		src,slen)!=1))goto err1;
	if(U(EVP_DecryptFinal_ex(((struct xssl_aes_xts *)ctx)->dec,
		((unsigned char *)dst)+len,&len)!=1))goto err1;
	return 0;

err1:	return -1;
}

static void *xssl_aes_xts_init(void *ctx,void *key,int klen)
{
	struct xssl_aes_xts *xts;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 512:
		type=EVP_aes_256_xts();
		break;
	case 256:
		type=EVP_aes_128_xts();
		break;
	default:goto err1;
	}
	if(U(!(xts=malloc(sizeof(struct xssl_aes_xts)))))goto err1;
	if(U(!(xts->enc=EVP_CIPHER_CTX_new())))goto err2;
	if(U(EVP_EncryptInit_ex(xts->enc,type,NULL,key,NULL)!=1))goto err3;
	if(U(!(xts->dec=EVP_CIPHER_CTX_new())))goto err3;
	if(U(EVP_DecryptInit_ex(xts->dec,type,NULL,key,NULL)!=1))goto err4;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return xts;

err4:	EVP_CIPHER_CTX_free(xts->dec);
err3:	EVP_CIPHER_CTX_free(xts->enc);
err2:	free(xts);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_xts_exit(void *ctx)
{
	EVP_CIPHER_CTX_free(((struct xssl_aes_xts *)ctx)->enc);
	EVP_CIPHER_CTX_free(((struct xssl_aes_xts *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int xssl_aes_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct xssl_aes_essiv *aes=ctx;

	if(slen&0xf)return -1;
	AES_ecb_encrypt(iv,aes->iv,&aes->aux,AES_ENCRYPT);
	for(;slen;s+=16,d+=16,slen-=16)AES_cbc_encrypt(s,d,16,&aes->enc,
		aes->iv,AES_ENCRYPT);
	return 0;
}

static int xssl_aes_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct xssl_aes_essiv *aes=ctx;

	if(slen&0xf)return -1;
	AES_ecb_encrypt(iv,aes->iv,&aes->aux,AES_ENCRYPT);
	for(;slen;s+=16,d+=16,slen-=16)AES_cbc_encrypt(s,d,16,&aes->dec,
		aes->iv,AES_DECRYPT);
	return 0;
}

static void *xssl_aes_essiv_init(void *ctx,void *key,int klen)
{
	struct xssl_aes_essiv *aes;
	unsigned char tmp[SHA256_DIGEST_LENGTH];

	if(U(!(aes=malloc(sizeof(struct xssl_aes_essiv)))))goto err1;
	aes->global=((struct usicrypt_thread *)ctx)->global;
	if(U(AES_set_encrypt_key(key,klen,&aes->enc)))goto err2;
	if(U(AES_set_decrypt_key(key,klen,&aes->dec)))goto err2;
	if(U(!SHA256(key,klen>>3,tmp)))goto err2;
	if(U(AES_set_encrypt_key(tmp,256,&aes->aux)))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return aes;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	aes->global->memclear(&aes->aux,sizeof(AES_KEY));
err2:	aes->global->memclear(&aes->enc,sizeof(AES_KEY));
	aes->global->memclear(&aes->dec,sizeof(AES_KEY));
	free(aes);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_essiv_exit(void *ctx)
{
	((struct xssl_aes_essiv *)ctx)->global->memclear(
		&((struct xssl_aes_essiv *)ctx)->enc,sizeof(AES_KEY));
	((struct xssl_aes_essiv *)ctx)->global->memclear(
		&((struct xssl_aes_essiv *)ctx)->dec,sizeof(AES_KEY));
	((struct xssl_aes_essiv *)ctx)->global->memclear(
		&((struct xssl_aes_essiv *)ctx)->aux,sizeof(AES_KEY));
	((struct xssl_aes_essiv *)ctx)->global->memclear(
		((struct xssl_aes_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_GCM

static int xssl_aes_gcm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int l;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(aad&&alen)if(U(EVP_EncryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_aes_gcm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int l;
	int i;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	for(i=0;i<niov;i++)if(U(EVP_EncryptUpdate(c,NULL,&l,iov[i].data,
		iov[i].length)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#endif

static int xssl_aes_gcm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int l;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->dec;

	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(aad&&alen)if(U(EVP_DecryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(!EVP_DecryptUpdate(c,dst,&l,src,slen)))goto err1;
	dlen=l;
	if(U(!EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)))goto err1;
	if(U(EVP_DecryptFinal_ex(c,((unsigned char *)dst)+l,&l)<=0))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_aes_gcm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int l;
	int i;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->dec;

	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	for(i=0;i<niov;i++)if(U(EVP_DecryptUpdate(c,NULL,&l,iov[i].data,
		iov[i].length)!=1))goto err1;
	if(U(!EVP_DecryptUpdate(c,dst,&l,src,slen)))goto err1;
	dlen=l;
	if(U(!EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)))goto err1;
	if(U(EVP_DecryptFinal_ex(c,((unsigned char *)dst)+l,&l)<=0))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#endif

static void *xssl_aes_gcm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct xssl_aes_xcm *gcm;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 256:
		type=EVP_aes_256_gcm();
		break;
	case 192:
		type=EVP_aes_192_gcm();
		break;
	case 128:
		type=EVP_aes_128_gcm();
		break;
	default:goto err1;
	}
	if(U(!(gcm=malloc(sizeof(struct xssl_aes_xcm)))))goto err1;
	if(U(!(gcm->enc=EVP_CIPHER_CTX_new())))goto err2;
	if(U(EVP_EncryptInit_ex(gcm->enc,type,NULL,key,NULL)!=1))goto err3;
	if(U(EVP_CIPHER_CTX_ctrl(gcm->enc,EVP_CTRL_GCM_SET_IVLEN,ilen,NULL)!=1))
		goto err3;
	if(U(!(gcm->dec=EVP_CIPHER_CTX_new())))goto err3;
	if(U(EVP_DecryptInit_ex(gcm->dec,type,NULL,key,NULL)!=1))goto err4;
	if(U(EVP_CIPHER_CTX_ctrl(gcm->dec,EVP_CTRL_GCM_SET_IVLEN,ilen,NULL)!=1))
		goto err4;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	gcm->ilen=ilen;
	gcm->tlen=tlen;
	return gcm;

err4:	EVP_CIPHER_CTX_free(gcm->dec);
err3:	EVP_CIPHER_CTX_free(gcm->enc);
err2:	free(gcm);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_gcm_exit(void *ctx)
{
	EVP_CIPHER_CTX_free(((struct xssl_aes_xcm *)ctx)->enc);
	EVP_CIPHER_CTX_free(((struct xssl_aes_xcm *)ctx)->dec);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CCM

static int xssl_aes_ccm_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int l;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,NULL,&l,NULL,slen)!=1))goto err1;
	if(aad&&alen)if(U(EVP_EncryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_GET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_aes_ccm_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int l;
	int i;
	int dlen;
	int alen;
	unsigned char *aad;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,NULL,&l,NULL,slen)!=1))goto err1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
		if(U(EVP_EncryptUpdate(c,NULL,&l,aad,alen)!=1))goto err2;
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_GET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err2:	OPENSSL_cleanse(aad,alen);
	free(aad);
err1:	return -1;
}

#endif

static int xssl_aes_ccm_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
	int l;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->dec;

	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(U(EVP_DecryptUpdate(c,NULL,&l,NULL,slen)!=1))goto err1;
	if(aad&&alen)if(U(EVP_DecryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(EVP_DecryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	if(U(l!=slen))goto err1;
	return 0;

err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_aes_ccm_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
	int l;
	int i;
	int alen;
	unsigned char *aad;
	EVP_CIPHER_CTX *c=((struct xssl_aes_xcm *)ctx)->dec;

	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_CCM_SET_TAG,
		((struct xssl_aes_xcm *)ctx)->tlen,tag)!=1))goto err1;
	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(U(EVP_DecryptUpdate(c,NULL,&l,NULL,slen)!=1))goto err1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err1;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
		if(U(EVP_DecryptUpdate(c,NULL,&l,aad,alen)!=1))goto err2;
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	if(U(EVP_DecryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	if(U(l!=slen))goto err1;
	return 0;

err2:	OPENSSL_cleanse(aad,alen);
	free(aad);
err1:	return -1;
}

#endif

static void *xssl_aes_ccm_init(void *ctx,void *key,int klen,int ilen,int tlen)
{
	struct xssl_aes_xcm *ccm;
	const EVP_CIPHER *type;
	unsigned char dummy[16];	/* libreSSL bugfix */

	switch(klen)
	{
	case 256:
		type=EVP_aes_256_ccm();
		break;
	case 192:
		type=EVP_aes_192_ccm();
		break;
	case 128:
		type=EVP_aes_128_ccm();
		break;
	default:goto err1;
	}
	if(U(!(ccm=malloc(sizeof(struct xssl_aes_xcm)))))goto err1;
	if(U(!(ccm->enc=EVP_CIPHER_CTX_new())))goto err2;
	if(U(EVP_EncryptInit_ex(ccm->enc,type,NULL,NULL,NULL)!=1))goto err3;
	if(U(EVP_CIPHER_CTX_ctrl(ccm->enc,EVP_CTRL_CCM_SET_IVLEN,ilen,NULL)!=1))
		goto err3;
	if(U(EVP_CIPHER_CTX_ctrl(ccm->enc,EVP_CTRL_CCM_SET_TAG,tlen,NULL)!=1))
		goto err3;
	if(U(EVP_EncryptInit_ex(ccm->enc,NULL,NULL,key,NULL)!=1))goto err3;
	if(U(!(ccm->dec=EVP_CIPHER_CTX_new())))goto err3;
	if(U(EVP_DecryptInit_ex(ccm->dec,type,NULL,NULL,NULL)!=1))goto err4;
	if(U(EVP_CIPHER_CTX_ctrl(ccm->dec,EVP_CTRL_CCM_SET_IVLEN,ilen,NULL)!=1))
		goto err4;
	/* libreSSL refuses to prepare tag length without a dummy tag, doh */
	if(U(EVP_CIPHER_CTX_ctrl(ccm->dec,EVP_CTRL_CCM_SET_TAG,tlen,&dummy)!=1))
		goto err4;
	if(U(EVP_DecryptInit_ex(ccm->dec,NULL,NULL,key,NULL)!=1))goto err4;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	ccm->ilen=ilen;
	ccm->tlen=tlen;
	return ccm;

err4:	EVP_CIPHER_CTX_free(ccm->dec);
err3:	EVP_CIPHER_CTX_free(ccm->enc);
err2:	free(ccm);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_aes_ccm_exit(void *ctx)
{
	EVP_CIPHER_CTX_free(((struct xssl_aes_xcm *)ctx)->enc);
	EVP_CIPHER_CTX_free(((struct xssl_aes_xcm *)ctx)->dec);
	free(ctx);
}

#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY

static int xssl_chacha_poly_encrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	size_t l=0;
	unsigned char *tmp;

	if(U(!(tmp=malloc(slen+16))))goto err1;
	if(U(!EVP_AEAD_CTX_seal(&((struct xssl_chacha_poly *)ctx)->enc,
		tmp,&l,slen+16,iv,12,src,slen,aad,alen)))goto err2;
	memcpy(dst,tmp,slen);
	memcpy(tag,tmp+slen,16);
	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
	return 0;

err2:	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
err1:	return -1;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int l;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_chacha_poly *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(aad&&alen)if(U(EVP_EncryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
#else
        return -1;
#endif
}

#ifndef USICRYPT_NO_IOV

static int xssl_chacha_poly_encrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	size_t l=0;
	int i;
	int alen;
	unsigned char *tmp;
	unsigned char *aad=NULL;

	if(U(!(tmp=malloc(slen+16))))goto err1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err2;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	if(U(!EVP_AEAD_CTX_seal(&((struct xssl_chacha_poly *)ctx)->enc,
		tmp,&l,slen+16,iv,12,src,slen,aad,alen)))goto err3;
	memcpy(dst,tmp,slen);
	memcpy(tag,tmp+slen,16);
	if(aad)
	{
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
	return 0;

err3:	if(aad)
	{
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	OPENSSL_cleanse(tmp,slen+16);
err2:	free(tmp);
err1:	return -1;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int l;
	int i;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_chacha_poly *)ctx)->enc;

	if(U(EVP_EncryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	for(i=0;i<niov;i++)if(U(EVP_EncryptUpdate(c,NULL,&l,iov[i].data,
		iov[i].length)!=1))goto err1;
	if(U(EVP_EncryptUpdate(c,dst,&l,src,slen)!=1))goto err1;
	dlen=l;
	if(U(EVP_EncryptFinal_ex(c,((unsigned char *)dst)+l,&l)!=1))goto err1;
	if(U(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,tag)!=1))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
#else
        return -1;
#endif
}

#endif

static int xssl_chacha_poly_decrypt(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	size_t l=0;
	unsigned char *tmp;

	if(U(!(tmp=malloc(slen+16))))goto err1;
	memcpy(tmp,src,slen);
	memcpy(tmp+slen,tag,16);
	if(U(!EVP_AEAD_CTX_open(&((struct xssl_chacha_poly *)ctx)->enc,
		dst,&l,slen,iv,12,tmp,slen+16,aad,alen)))goto err2;
	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
	return 0;

err2:	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
err1:	return -1;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int l;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_chacha_poly *)ctx)->dec;

	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	if(aad&&alen)if(U(EVP_DecryptUpdate(c,NULL,&l,aad,alen)!=1))goto err1;
	if(U(!EVP_DecryptUpdate(c,dst,&l,src,slen)))goto err1;
	dlen=l;
	if(U(!EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,tag)))goto err1;
	if(U(EVP_DecryptFinal_ex(c,((unsigned char *)dst)+l,&l)<=0))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
#else
        return -1;
#endif
}

#ifndef USICRYPT_NO_IOV

static int xssl_chacha_poly_decrypt_iov(void *ctx,void *iv,void *src,int slen,
	struct usicrypt_iov *iov,int niov,void *dst,void *tag)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	size_t l=0;
	int i;
	int alen;
	unsigned char *tmp;
	unsigned char *aad=NULL;

	if(U(!(tmp=malloc(slen+16))))goto err1;
	for(i=0,alen=0;i<niov;i++)alen+=iov[i].length;
	if(alen)
	{
		if(U(!(aad=malloc(alen))))goto err2;
		for(i=0,alen=0;i<niov;i++)
		{
			memcpy(aad+alen,iov[i].data,iov[i].length);
			alen+=iov[i].length;
		}
	}
	memcpy(tmp,src,slen);
	memcpy(tmp+slen,tag,16);
	if(U(!EVP_AEAD_CTX_open(&((struct xssl_chacha_poly *)ctx)->enc,
		dst,&l,slen,iv,12,tmp,slen+16,aad,alen)))goto err3;
	if(aad)
	{
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	OPENSSL_cleanse(tmp,slen+16);
	free(tmp);
	return 0;

err3:	if(aad)
	{
		OPENSSL_cleanse(aad,alen);
		free(aad);
	}
	OPENSSL_cleanse(tmp,slen+16);
err2:	free(tmp);
err1:	return -1;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int l;
	int i;
	int dlen;
	EVP_CIPHER_CTX *c=((struct xssl_chacha_poly *)ctx)->dec;

	if(U(EVP_DecryptInit_ex(c,NULL,NULL,NULL,iv)!=1))goto err1;
	for(i=0;i<niov;i++)if(U(EVP_DecryptUpdate(c,NULL,&l,iov[i].data,
		iov[i].length)!=1))goto err1;
	if(U(!EVP_DecryptUpdate(c,dst,&l,src,slen)))goto err1;
	dlen=l;
	if(U(!EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,tag)))goto err1;
	if(U(EVP_DecryptFinal_ex(c,((unsigned char *)dst)+l,&l)<=0))goto err1;
	if(U(dlen+l!=slen))goto err1;
	return 0;

err1:	return -1;
#else
        return -1;
#endif
}

#endif

static void *xssl_chacha_poly_init(void *ctx,void *key,int klen,int ilen,
	int tlen)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	struct xssl_chacha_poly *chp;

	if(U(klen!=256)||U(ilen!=12)||U(tlen!=16))goto err1;
	if(U(!(chp=malloc(sizeof(struct xssl_chacha_poly)))))goto err1;
	if(U(!EVP_AEAD_CTX_init(&chp->enc,EVP_aead_chacha20_poly1305(),key,
		32,16,NULL)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return chp;

err2:	free(chp);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	struct xssl_chacha_poly *chp;

	if(U(klen!=256)||U(ilen!=12)||U(tlen!=16))goto err1;
	if(U(!(chp=malloc(sizeof(struct xssl_chacha_poly)))))goto err1;
	if(U(!(chp->enc=EVP_CIPHER_CTX_new())))goto err2;
	if(U(EVP_EncryptInit_ex(chp->enc,EVP_chacha20_poly1305(),NULL,key,
		NULL)!=1))goto err3;
	if(U(!(chp->dec=EVP_CIPHER_CTX_new())))goto err3;
	if(U(EVP_DecryptInit_ex(chp->dec,EVP_chacha20_poly1305(),NULL,key,
		NULL)!=1))goto err4;
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return chp;

err4:	EVP_CIPHER_CTX_free(chp->dec);
err3:	EVP_CIPHER_CTX_free(chp->enc);
err2:	free(chp);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
#endif
	return NULL;
}

static void xssl_chacha_poly_exit(void *ctx)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	EVP_AEAD_CTX_cleanup(&((struct xssl_chacha_poly *)ctx)->enc);
	free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(((struct xssl_chacha_poly *)ctx)->enc);
	EVP_CIPHER_CTX_free(((struct xssl_chacha_poly *)ctx)->dec);
	free(ctx);
#endif
}

#endif
#ifndef USICRYPT_NO_STREAM

static int xssl_chacha_crypt(void *ctx,void *src,int slen,void *dst)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	ChaCha(&((struct xssl_chacha *)ctx)->ctx,dst,src,slen);
	return 0;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int len;

	if(U(EVP_EncryptUpdate(((struct xssl_chacha *)ctx)->ctx,dst,&len,
		src,slen)!=1))return -1;
	return 0;
#else
	return -1;
#endif
}

static void *xssl_chacha_init(void *ctx,void *key,int klen,void *iv)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	struct xssl_chacha *ch;
	unsigned long long zero=0ULL;

	if(U(klen!=256))goto err1;
	if(U(!(ch=malloc(sizeof(struct xssl_chacha)))))goto err1;
	ChaCha_set_key(&ch->ctx,key,256);
	ChaCha_set_iv(&ch->ctx,iv?iv:(unsigned char *)(&zero),
		(unsigned char *)(&zero));
	ch->global=((struct usicrypt_thread *)ctx)->global;
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return ch;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	struct xssl_chacha *ch;
	unsigned char tmp[16];

	if(U(klen!=256))goto err1;
	if(U(!(ch=malloc(sizeof(struct xssl_chacha)))))goto err1;
	if(U(!(ch->ctx=EVP_CIPHER_CTX_new())))goto err2;
	memset(tmp,0,8);
	if(iv)memcpy(tmp+8,iv,8);
	else memset(tmp+8,0,8);
	if(U(EVP_EncryptInit_ex(ch->ctx,EVP_chacha20(),NULL,key,tmp)!=1))
		goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
	return ch;

err3:	EVP_CIPHER_CTX_free(ch->ctx);
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,16);
err2:	free(ch);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,32);
#endif
	return NULL;
}

static void xssl_chacha_reset(void *ctx,void *iv)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	unsigned long long zero=0ULL;

	ChaCha_set_iv(&((struct xssl_chacha *)ctx)->ctx,iv,
		(unsigned char *)(&zero));
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	unsigned char tmp[16];

	memset(tmp,0,8);
	memcpy(tmp+8,iv,8);
	EVP_EncryptInit_ex(((struct xssl_chacha *)ctx)->ctx,NULL,NULL,NULL,tmp);
	OPENSSL_cleanse(tmp,16);
#endif
}

static void xssl_chacha_exit(void *ctx)
{
#if defined(LIBRESSL_VERSION_NUMBER)
	((struct xssl_chacha *)ctx)->global->
		memclear(&((struct xssl_chacha *)ctx)->ctx,sizeof(ChaCha_ctx));
	free(ctx);
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_CIPHER_CTX_free(((struct xssl_chacha *)ctx)->ctx);
#endif
}

#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_CMAC

static int xssl_camellia_cmac(void *ctx,void *key,int klen,void *src,int slen,
	void *dst)
{
	size_t unused;
	CMAC_CTX *c;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 256:
		type=EVP_camellia_256_cbc();
		break;
	case 192:
		type=EVP_camellia_192_cbc();
		break;
	case 128:
		type=EVP_camellia_128_cbc();
		break;
	default:goto err1;
	}
	if(U(!(c=CMAC_CTX_new())))goto err1;
	if(U(CMAC_Init(c,key,klen>>3,type,NULL)!=1))goto err2;
	if(U(CMAC_Update(c,src,slen)!=1))goto err2;
	if(U(CMAC_Final(c,dst,&unused)!=1))goto err2;
	CMAC_CTX_free(c);
	return 0;

err2:	CMAC_CTX_free(c);
err1:	return -1;
}

#ifndef USICRYPT_NO_IOV

static int xssl_camellia_cmac_iov(void *ctx,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst)
{
	int i;
	size_t unused;
	CMAC_CTX *c;
	const EVP_CIPHER *type;

	switch(klen)
	{
	case 256:
		type=EVP_camellia_256_cbc();
		break;
	case 192:
		type=EVP_camellia_192_cbc();
		break;
	case 128:
		type=EVP_camellia_128_cbc();
		break;
	default:goto err1;
	}
	if(U(!(c=CMAC_CTX_new())))goto err1;
	if(U(CMAC_Init(c,key,klen>>3,type,NULL)!=1))goto err2;
	for(i=0;i<niov;i++)if(U(CMAC_Update(c,iov[i].data,iov[i].length)!=1))
		goto err2;
	if(U(CMAC_Final(c,dst,&unused)!=1))goto err2;
	CMAC_CTX_free(c);
	return 0;

err2:	CMAC_CTX_free(c);
err1:	return -1;
}

#endif
#endif
#ifndef USICRYPT_NO_ECB

static int xssl_camellia_ecb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)Camellia_ecb_encrypt(s,d,
		&((struct xssl_camellia_ecb *)ctx)->ctx,CAMELLIA_ENCRYPT);
	return 0;
}

static int xssl_camellia_ecb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)Camellia_ecb_encrypt(s,d,
		&((struct xssl_camellia_ecb *)ctx)->ctx,CAMELLIA_DECRYPT);
	return 0;
}

static void *xssl_camellia_ecb_init(void *ctx,void *key,int klen)
{
	struct xssl_camellia_ecb *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_ecb)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen,&camellia->ctx)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->ctx,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_ecb_exit(void *ctx)
{
	((struct xssl_camellia_ecb *)ctx)->global->memclear(
		&((struct xssl_camellia_ecb *)ctx)->ctx,sizeof(CAMELLIA_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CBC

static int xssl_camellia_cbc_encrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)Camellia_cbc_encrypt(s,d,16,
		&((struct xssl_camellia_cbc *)ctx)->ctx,
		((struct xssl_camellia_cbc *)ctx)->iv,CAMELLIA_ENCRYPT);
	return 0;
}

static int xssl_camellia_cbc_decrypt(void *ctx,void *src,int slen,void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen&0xf))return -1;
	for(;slen;s+=16,d+=16,slen-=16)Camellia_cbc_encrypt(s,d,16,
		&((struct xssl_camellia_cbc *)ctx)->ctx,
		((struct xssl_camellia_cbc *)ctx)->iv,CAMELLIA_DECRYPT);
	return 0;
}

static void *xssl_camellia_cbc_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_cbc *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_cbc)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen,&camellia->ctx)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->ctx,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_cbc_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_camellia_cbc *)ctx)->iv,iv,16);
}

static void xssl_camellia_cbc_exit(void *ctx)
{
	((struct xssl_camellia_cbc *)ctx)->global->memclear(
		&((struct xssl_camellia_cbc *)ctx)->ctx,sizeof(CAMELLIA_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTS

static int xssl_camellia_cts_encrypt(void *ctx,void *src,int slen,void *dst)
{
	if(U(slen<=16))return -1;
	CRYPTO_cts128_encrypt(src,dst,slen,
		&((struct xssl_camellia_cbc *)ctx)->ctx,
		((struct xssl_camellia_cbc *)ctx)->iv,
		(void *)Camellia_cbc_encrypt);
	return 0;
}

static int xssl_camellia_cts_decrypt(void *ctx,void *src,int slen,void *dst)
{
	if((slen<=16))return -1;
	CRYPTO_cts128_decrypt(src,dst,slen,
		&((struct xssl_camellia_cbc *)ctx)->ctx,
		((struct xssl_camellia_cbc *)ctx)->iv,
		(void *)Camellia_cbc_encrypt);
	return 0;
}

static void *xssl_camellia_cts_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_cbc *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_cbc)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen,&camellia->ctx)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->ctx,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_cts_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_camellia_cbc *)ctx)->iv,iv,16);
}

static void xssl_camellia_cts_exit(void *ctx)
{
	((struct xssl_camellia_cbc *)ctx)->global->memclear(
		&((struct xssl_camellia_cbc *)ctx)->ctx,sizeof(CAMELLIA_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB

static int xssl_camellia_cfb_encrypt(void *ctx,void *src,int slen,void *dst)
{
	Camellia_cfb128_encrypt(src,dst,slen,
		&((struct xssl_camellia_cfb *)ctx)->enc,
		((struct xssl_camellia_cfb *)ctx)->iv,
		&((struct xssl_camellia_cfb *)ctx)->num,CAMELLIA_ENCRYPT);
	return 0;
}

static int xssl_camellia_cfb_decrypt(void *ctx,void *src,int slen,void *dst)
{
	Camellia_cfb128_encrypt(src,dst,slen,
		&((struct xssl_camellia_cfb *)ctx)->enc,
		((struct xssl_camellia_cfb *)ctx)->iv,
		&((struct xssl_camellia_cfb *)ctx)->num,CAMELLIA_DECRYPT);
	return 0;
}

static void *xssl_camellia_cfb_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_cfb *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_cfb)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	camellia->num=0;
	if(U(Camellia_set_key(key,klen,&camellia->enc)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->enc,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_cfb_reset(void *ctx,void *iv)
{
	((struct xssl_camellia_cfb *)ctx)->num=0;
	memcpy(((struct xssl_camellia_cfb *)ctx)->iv,iv,16);
}

static void xssl_camellia_cfb_exit(void *ctx)
{
	((struct xssl_camellia_cfb *)ctx)->global->memclear(
		&((struct xssl_camellia_cfb *)ctx)->enc,sizeof(CAMELLIA_KEY));
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CFB8

static int xssl_camellia_cfb8_encrypt(void *ctx,void *src,int slen,void *dst)
{
	Camellia_cfb8_encrypt(src,dst,slen,
		&((struct xssl_camellia_cfb8 *)ctx)->enc,
		((struct xssl_camellia_cfb8 *)ctx)->iv,
		NULL,CAMELLIA_ENCRYPT);
	return 0;
}

static int xssl_camellia_cfb8_decrypt(void *ctx,void *src,int slen,void *dst)
{
	Camellia_cfb8_encrypt(src,dst,slen,
		&((struct xssl_camellia_cfb8 *)ctx)->enc,
		((struct xssl_camellia_cfb8 *)ctx)->iv,
		NULL,CAMELLIA_DECRYPT);
	return 0;
}

static void *xssl_camellia_cfb8_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_cfb8 *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_cfb8)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen,&camellia->enc)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->enc,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_cfb8_reset(void *ctx,void *iv)
{
	memcpy(((struct xssl_camellia_cfb8 *)ctx)->iv,iv,16);
}

static void xssl_camellia_cfb8_exit(void *ctx)
{
	((struct xssl_camellia_cfb8 *)ctx)->global->memclear(
		&((struct xssl_camellia_cfb8 *)ctx)->enc,sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_cfb8 *)ctx)->global->memclear(
		((struct xssl_camellia_cfb8 *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_OFB

static int xssl_camellia_ofb_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct xssl_camellia_ofb *camellia=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			Camellia_ofb128_encrypt(camellia->zero,dst,16,
				&camellia->enc,camellia->iv,&camellia->n);
		Camellia_ofb128_encrypt(camellia->zero,dst,slen,&camellia->enc,
			camellia->iv,&camellia->n);
	}
	else Camellia_ofb128_encrypt(src,dst,slen,&camellia->enc,camellia->iv,
		&camellia->n);
	return 0;
}

static void *xssl_camellia_ofb_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_ofb *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_ofb)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	memset(camellia->zero,0,16);
	camellia->n=0;
	if((Camellia_set_key(key,klen,&camellia->enc)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->enc,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_ofb_reset(void *ctx,void *iv)
{
	((struct xssl_camellia_ofb *)ctx)->n=0;
	memcpy(((struct xssl_camellia_ofb *)ctx)->iv,iv,16);
}

static void xssl_camellia_ofb_exit(void *ctx)
{
	((struct xssl_camellia_ofb *)ctx)->global->memclear(
		&((struct xssl_camellia_ofb *)ctx)->enc,sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_ofb *)ctx)->global->memclear(
		((struct xssl_camellia_ofb *)ctx)->iv,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_CTR

static int xssl_camellia_ctr_crypt(void *ctx,void *src,int slen,void *dst)
{
	struct xssl_camellia_ctr *camellia=ctx;

	if(!src)
	{
		for(;slen>16;slen-=16,dst+=16)
			Camellia_ctr128_encrypt(camellia->zero,dst,16,
				&camellia->enc,camellia->iv,camellia->bfr,
				&camellia->n);
		Camellia_ctr128_encrypt(camellia->zero,dst,slen,&camellia->enc,
			camellia->iv,camellia->bfr,&camellia->n);
	}
	else Camellia_ctr128_encrypt(src,dst,slen,&camellia->enc,
		camellia->iv,camellia->bfr,&camellia->n);
	return 0;
}

static void *xssl_camellia_ctr_init(void *ctx,void *key,int klen,void *iv)
{
	struct xssl_camellia_ctr *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_ctr)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	memset(camellia->zero,0,16);
	camellia->n=0;
	if(U(Camellia_set_key(key,klen,&camellia->enc)))goto err2;
	if(iv)memcpy(camellia->iv,iv,16);
	else memset(camellia->iv,0,16);
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->enc,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_ctr_reset(void *ctx,void *iv)
{
	((struct xssl_camellia_ctr *)ctx)->n=0;
	memcpy(((struct xssl_camellia_ctr *)ctx)->iv,iv,16);
}

static void xssl_camellia_ctr_exit(void *ctx)
{
	((struct xssl_camellia_ctr *)ctx)->global->memclear(
		&((struct xssl_camellia_ctr *)ctx)->enc,sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_ctr *)ctx)->global->memclear(
		&((struct xssl_camellia_ctr *)ctx)->bfr,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_XTS

static int xssl_camellia_xts_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct xssl_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	Camellia_ecb_encrypt(iv,camellia->twk,&camellia->twe,CAMELLIA_ENCRYPT);

	for(;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		Camellia_ecb_encrypt(camellia->wrk,d,&camellia->ctx,
			CAMELLIA_ENCRYPT);
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
		Camellia_ecb_encrypt(camellia->wrk,d,&camellia->ctx,
			CAMELLIA_ENCRYPT);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
	}

	return 0;
}

static int xssl_camellia_xts_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	int i;
	int n;
	struct xssl_camellia_xts *camellia=ctx;
	unsigned char *s=src;
	unsigned char *d=dst;

	if(U(slen<16))return -1;

	Camellia_ecb_encrypt(iv,camellia->twk,&camellia->twe,CAMELLIA_ENCRYPT);

	for(slen-=(slen&0xf)?16:0;slen>=16;slen-=16,s+=16,d+=16)
	{
		for(i=0;i<16;i++)camellia->wrk[i]=s[i]^camellia->twk[i];
		Camellia_ecb_encrypt(camellia->wrk,d,&camellia->ctx,
			CAMELLIA_DECRYPT);
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
		Camellia_ecb_encrypt(camellia->wrk,d,&camellia->ctx,
			CAMELLIA_DECRYPT);
		for(i=0;i<16;i++)d[i]^=camellia->twk[i];
		memcpy(d+16,d,slen);
		memcpy(camellia->wrk,s+16,slen);
		memcpy(camellia->wrk+slen,d+slen,16-slen);
		for(i=0;i<16;i++)camellia->wrk[i]^=camellia->mem[i];
		Camellia_ecb_encrypt(camellia->wrk,d,&camellia->ctx,
			CAMELLIA_DECRYPT);
		for(i=0;i<16;i++)d[i]^=camellia->mem[i];
	}

	return 0;
}

static void *xssl_camellia_xts_init(void *ctx,void *key,int klen)
{
	struct xssl_camellia_xts *camellia;

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_xts)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen>>1,&camellia->ctx)))goto err2;
	if(U(Camellia_set_key(key+(klen>>4),klen>>1,&camellia->twe)))goto err2;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err2:	camellia->global->memclear(&camellia->ctx,sizeof(CAMELLIA_KEY));
	camellia->global->memclear(&camellia->twe,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_xts_exit(void *ctx)
{
	((struct xssl_camellia_xts *)ctx)->global->
		memclear(&((struct xssl_camellia_xts *)ctx)->ctx,
		sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_xts *)ctx)->global->
		memclear(&((struct xssl_camellia_xts *)ctx)->twe,
		sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_xts *)ctx)->global->
		memclear(((struct xssl_camellia_xts *)ctx)->twk,16);
	((struct xssl_camellia_xts *)ctx)->global->
		memclear(((struct xssl_camellia_xts *)ctx)->wrk,16);
	((struct xssl_camellia_xts *)ctx)->global->
		memclear(((struct xssl_camellia_xts *)ctx)->mem,16);
	free(ctx);
}

#endif
#ifndef USICRYPT_NO_ESSIV

static int xssl_camellia_essiv_encrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct xssl_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	Camellia_ecb_encrypt(iv,camellia->iv,&camellia->aux,CAMELLIA_ENCRYPT);
	for(;slen;s+=16,d+=16,slen-=16)Camellia_cbc_encrypt(s,d,16,
		&camellia->ctx,camellia->iv,CAMELLIA_ENCRYPT);
	return 0;
}

static int xssl_camellia_essiv_decrypt(void *ctx,void *iv,void *src,int slen,
	void *dst)
{
	unsigned char *s=src;
	unsigned char *d=dst;
	struct xssl_camellia_essiv *camellia=ctx;

	if(U(slen&0xf))return -1;
	Camellia_ecb_encrypt(iv,camellia->iv,&camellia->aux,CAMELLIA_ENCRYPT);
	for(;slen;s+=16,d+=16,slen-=16)Camellia_cbc_encrypt(s,d,16,
		&camellia->ctx,camellia->iv,CAMELLIA_DECRYPT);
	return 0;
}

static void *xssl_camellia_essiv_init(void *ctx,void *key,int klen)
{
	struct xssl_camellia_essiv *camellia;
	unsigned char tmp[SHA256_DIGEST_LENGTH];

	if(U(!(camellia=malloc(sizeof(struct xssl_camellia_essiv)))))goto err1;
	camellia->global=((struct usicrypt_thread *)ctx)->global;
	if(U(Camellia_set_key(key,klen,&camellia->ctx)))goto err2;
	if(U(!SHA256(key,klen>>3,tmp)))goto err2;
	if(U(Camellia_set_key(tmp,256,&camellia->aux)))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return camellia;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,sizeof(tmp));
	camellia->global->memclear(&camellia->aux,sizeof(CAMELLIA_KEY));
err2:	camellia->global->memclear(&camellia->ctx,sizeof(CAMELLIA_KEY));
	free(camellia);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen>>3);
	return NULL;
}

static void xssl_camellia_essiv_exit(void *ctx)
{
	((struct xssl_camellia_essiv *)ctx)->global->memclear(
		&((struct xssl_camellia_essiv *)ctx)->ctx,sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_essiv *)ctx)->global->memclear(
		&((struct xssl_camellia_essiv *)ctx)->aux,sizeof(CAMELLIA_KEY));
	((struct xssl_camellia_essiv *)ctx)->global->memclear(
		((struct xssl_camellia_essiv *)ctx)->iv,16);
	free(ctx);
}

#endif
#endif

int USICRYPT(random)(void *ctx,void *data,int len)
{
	if(U((((struct usicrypt_thread *)ctx)->total+=1)>=10000))
	{
		if(U(xssl_reseed(ctx)))return -1;
		((struct usicrypt_thread *)ctx)->total=0;
	}
	if(U(RAND_bytes(data,len)!=1))return -1;
	return 0;
}

int USICRYPT(digest_size)(void *ctx,int md)
{
	switch(md)
	{
#ifndef USICRYPT_NO_DIGEST
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return SHA_DIGEST_LENGTH;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return SHA256_DIGEST_LENGTH;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return SHA384_DIGEST_LENGTH;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return SHA512_DIGEST_LENGTH;
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
		return U(!SHA1(in,len,out))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return U(!SHA256(in,len,out))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return U(!SHA384(in,len,out))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return U(!SHA512(in,len,out))?-1:0;
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
	EVP_MD_CTX *c;
	const EVP_MD *digest;

	switch(md)
	{
#if !defined(USICRYPT_NO_DIGEST) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=EVP_sha1();
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=EVP_sha256();
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=EVP_sha384();
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=EVP_sha512();
		break;
#endif
#endif
	default:return -1;
	}

	if(U(!(c=EVP_MD_CTX_create())))goto err1;
	if(U(!EVP_DigestInit_ex(c,digest,NULL)))goto err2;
	for(i=0;i<niov;i++)if(U(!EVP_DigestUpdate(c,iov[i].data,iov[i].length)))
		goto err2;
	if(U(!EVP_DigestFinal_ex(c,out,NULL)))goto err2;
	r=0;
err2:	EVP_MD_CTX_destroy(c);
err1:	return r;
}

int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,int klen,
	void *out)
{
	switch(md)
	{
#ifndef USICRYPT_NO_HMAC
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		return U(!HMAC(EVP_sha1(),key,klen,data,dlen,out,NULL))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		return U(!HMAC(EVP_sha256(),key,klen,data,dlen,out,NULL))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		return U(!HMAC(EVP_sha384(),key,klen,data,dlen,out,NULL))?-1:0;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		return U(!HMAC(EVP_sha512(),key,klen,data,dlen,out,NULL))?-1:0;
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
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX hmac;
	HMAC_CTX *c=&hmac;
#else
	HMAC_CTX *c;
#endif
	const EVP_MD *digest;

	switch(md)
	{
#if !defined(USICRYPT_NO_HMAC) && !defined(USICRYPT_NO_IOV)
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		digest=EVP_sha1();
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		digest=EVP_sha256();
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		digest=EVP_sha384();
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		digest=EVP_sha512();
		break;
#endif
#endif
	default:return -1;
	}

#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_init(c);
#else
	if(U(!(c=HMAC_CTX_new())))goto err1;
#endif
	if(U(!HMAC_Init_ex(c,key,klen,digest,NULL)))goto err2;
	for(i=0;i<niov;i++)if(U(!HMAC_Update(c,iov[i].data,iov[i].length)))
		goto err2;
	if(U(!HMAC_Final(c,out,NULL)))goto err2;
	r=0;
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
err2:	HMAC_CTX_cleanup(c);
	return r;
#else
err2:	HMAC_CTX_free(c);
err1:	return r;
#endif
}

int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	int iter,void *out)
{
#ifndef USICRYPT_NO_PBKDF2
	int r=0;
	int len;
	void *type;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:return -1;
	}

	if(U(!(PKCS5_PBKDF2_HMAC(key,klen,salt,slen,iter,type,len,out))))r=-1;
	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
	return r;
#else
	return -1;
#endif
}

int USICRYPT(hkdf)(void *ctx,int md,void *key,int klen,void *salt,int slen,
	void *info,int ilen,void *out)
{
#ifndef USICRYPT_NO_HKDF
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3020000fL
	unsigned char s[SHA512_DIGEST_LENGTH];
#elif defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX hm;
	unsigned char s[SHA512_DIGEST_LENGTH];
#else
	EVP_PKEY_CTX *p;
#endif
	size_t len;
	void *type;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=(void *)EVP_sha1();
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3020000fL

	if(!salt||!slen)
	{
		slen=len;
		salt=s;
		memset(s,0,len);
	}
	if(!HKDF(out,len,type,key,klen,salt,slen,info,ilen))goto err1;
	return 0;
err1:	return -1;

#elif defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	if(!salt||!slen)
	{
		slen=len;
		salt=s;
		memset(s,0,len);
	}
	if(U(!HMAC(type,salt,slen,key,klen,out,NULL)))goto err1;
	HMAC_CTX_init(&hm);
	if(U(HMAC_Init_ex(&hm,out,len,type,NULL)!=1))goto err2;
	if(U(HMAC_Update(&hm,info,ilen)!=1))goto err2;
	s[0]=1;
	if(U(HMAC_Update(&hm,s,1)!=1))goto err2;
	if(U(HMAC_Final(&hm,out,NULL)!=1))goto err2;
	HMAC_CTX_cleanup(&hm);
	return 0;

err2:	HMAC_CTX_cleanup(&hm);
err1:	return -1;
#else
	if(U(!(p=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL))))goto err1;
	if(U(EVP_PKEY_derive_init(p)!=1))goto err2;
	if(U(EVP_PKEY_CTX_set_hkdf_md(p,type)!=1))goto err2;
	if(U(EVP_PKEY_CTX_set1_hkdf_salt(p,salt,slen)!=1))goto err2;
	if(U(EVP_PKEY_CTX_set1_hkdf_key(p,key,klen)!=1))goto err2;
	if(U(EVP_PKEY_CTX_add1_hkdf_info(p,info,ilen)!=1))goto err2;
	if(U(EVP_PKEY_derive(p,out,&len)!=1))goto err2;
	EVP_PKEY_CTX_free(p);
	return 0;

err2:	EVP_PKEY_CTX_free(p);
err1:	return -1;
#endif
#else
	return -1;
#endif
}

void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	BIO *b64;
	BIO *bio;
	char *tmp;
	char *out;

	if(U(!(b64=BIO_new(BIO_f_base64()))))goto err1;
	if(U(!(bio=BIO_new(BIO_s_mem()))))goto err2;
	bio=BIO_push(b64,bio);
	BIO_set_flags(bio,BIO_FLAGS_BASE64_NO_NL);
	if(U(BIO_write(bio,in,ilen)!=ilen))goto err3;
	if(U(BIO_flush(bio)!=1))goto err3;
	*olen=(int)BIO_get_mem_data(bio,&tmp);
	if(U(!(out=malloc(*olen+1))))goto err3;
	memcpy(out,tmp,*olen);
	out[*olen]=0;
	BIO_free_all(bio);
	return out;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,*olen);
	BIO_free(bio);
err2:	BIO_free(b64);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen)
{
#ifndef USICRYPT_NO_BASE64
	BIO *b64;
	BIO *bio;
	char *out;

	if(U(!(b64=BIO_new(BIO_f_base64()))))goto err1;
	if(U(!(bio=BIO_new_mem_buf(in,ilen))))goto err2;
	bio=BIO_push(b64,bio);
	BIO_set_flags(bio,BIO_FLAGS_BASE64_NO_NL);
	if(U(!(out=malloc(ilen))))goto err3;
	if(U((*olen=BIO_read(bio,out,ilen))<=0))goto err4;
	BIO_free_all(bio);
	out=USICRYPT(do_realloc)(ctx,out,ilen,*olen);
	return out;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(out,ilen);
	free(out);
err3:	BIO_free(bio);
err2:	BIO_free(b64);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_generate)(void *ctx,int bits)
{
#ifndef USICRYPT_NO_RSA
	RSA *k;
	EVP_PKEY *key;
	BIGNUM *b;

	if(U(bits<USICRYPT_RSA_BITS_MIN)||U(bits>USICRYPT_RSA_BITS_MAX)||
		U(bits&7))goto err1;
	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(k=RSA_new())))goto err1;
	if(U(!(b=BN_new())))goto err2;
	if(U(!BN_set_word(b,USICRYPT_RSA_EXPONENT)))goto err3;
	if(U(RSA_generate_key_ex(k,bits,b,NULL)!=1))goto err3;
	if(U(!RSA_blinding_on(k,NULL)))goto err3;
	if(U(!(key=EVP_PKEY_new())))goto err3;
	if(U(!(EVP_PKEY_assign_RSA(key,k))))goto err4;
	BN_free(b);
	return key;

err4:	EVP_PKEY_free(key);
err3:	BN_free(b);
err2:	RSA_free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(rsa_size)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	int res=-1;
	int n;
	RSA *rsa;

	if(U(!(rsa=EVP_PKEY_get1_RSA((EVP_PKEY *)key))))goto err1;
	if(U((n=RSA_size(rsa))<=0))goto err2;
	res=n<<3;

err2:	RSA_free(rsa);
err1:	return res;
#else
	return -1;
#endif
}

void *USICRYPT(rsa_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_RSA
	int l;
	RSA *k;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U(!(k=EVP_PKEY_get1_RSA((EVP_PKEY *)key))))goto err1;
	if(U((l=i2d_RSA_PUBKEY(k,NULL))<=0))goto err2;
	if(U(!(m=p=malloc(l))))goto err2;
	if(U((*len=i2d_RSA_PUBKEY(k,&m))<=0))goto err3;
	if(L(*len==l))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err2:	RSA_free(k);
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int n;
	const unsigned char *pp=key;
	RSA *k;
	EVP_PKEY *kk;

	if(U(!(k=d2i_RSA_PUBKEY(NULL,&pp,(long)len))))goto err1;
	if(U((n=RSA_size(k))<USICRYPT_RSA_BYTES_MIN)||
		U(n>USICRYPT_RSA_BYTES_MAX))goto err2;
	if(U(!(kk=EVP_PKEY_new())))goto err2;
	if(U(!(EVP_PKEY_assign_RSA(kk,k))))goto err3;
	return kk;

err3:	EVP_PKEY_free(kk);
err2:	RSA_free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_RSA
	int l;
	RSA *k;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U(!(k=EVP_PKEY_get1_RSA((EVP_PKEY *)key))))goto err1;
	if(U((l=i2d_RSAPrivateKey(k,NULL))<=0))goto err2;
	if(U(!(m=p=malloc(l))))goto err2;
	if(U((*len=i2d_RSAPrivateKey(k,&m))<=0))goto err3;
	if(L(*len==l))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err2:	RSA_free(k);
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_RSA
	int n;
	const unsigned char *pp=key;
	RSA *k;
	EVP_PKEY *kk;

	if(U(!(k=d2i_RSAPrivateKey(NULL,&pp,(long)len))))goto err1;
	if(U((n=RSA_size(k))<USICRYPT_RSA_BYTES_MIN)||
		U(n>USICRYPT_RSA_BYTES_MAX))goto err2;
	if(U(!RSA_blinding_on(k,NULL)))goto err2;
	if(U(!(kk=EVP_PKEY_new())))goto err2;
	if(U(!(EVP_PKEY_assign_RSA(kk,k))))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return kk;

err3:	EVP_PKEY_free(kk);
err2:	RSA_free(k);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(rsa_sign_v15)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return xssl_rsa_do_sign_v15(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return xssl_rsa_do_sign_v15(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return xssl_rsa_do_verify_v15(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return xssl_rsa_do_verify_v15(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_RSA
	return xssl_rsa_do_sign_pss(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return xssl_rsa_do_sign_pss(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_RSA
	return xssl_rsa_do_verify_pss(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_RSA) && !defined(USICRYPT_NO_IOV)
	return xssl_rsa_do_verify_pss(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	RSA *rsa;
	unsigned char *out=NULL;

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err1;
	*olen=RSA_size(rsa);
	if(U(dlen>*olen-11))goto err2;
	if(U(!(out=malloc(*olen))))goto err2;
	if(L(RSA_public_encrypt(dlen,data,out,rsa,RSA_PKCS1_PADDING)==*olen))
		goto err2;

	((struct usicrypt_thread *)ctx)->global->memclear(out,RSA_size(rsa));
	free(out);
	out=NULL;
err2:	RSA_free(rsa);
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
	RSA *rsa;
	unsigned char *out=NULL;

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err1;
	*olen=RSA_size(rsa);
	if(U(dlen!=*olen))goto err2;
	if(U(!(out=malloc(*olen))))goto err2;
	if(U((l=RSA_private_decrypt(dlen,data,out,rsa,RSA_PKCS1_PADDING))==-1))
		goto err3;
	out=USICRYPT(do_realloc)(ctx,out,*olen,l);
	*olen=l;
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(out,RSA_size(rsa));
	free(out);
	out=NULL;
err2:	RSA_free(rsa);
err1:	return out;
#else
	return NULL;
#endif
}

void *USICRYPT(rsa_encrypt_oaep)(void *ctx,int md,void *key,void *data,int dlen,
	int *olen)
{
#ifndef USICRYPT_NO_RSA
	int len;
	RSA *rsa;
	void *type;
	unsigned char *tmp;
	unsigned char *out=NULL;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=NULL;
		len=SHA_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		len=SHA256_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		len=SHA384_DIGEST_LENGTH;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		len=SHA512_DIGEST_LENGTH;
		break;
#endif
	default:goto err1;
	}

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err1;
	*olen=RSA_size(rsa);
	if(U(dlen>*olen-2*len-2))goto err2;
	if(U(!(tmp=malloc(*olen))))goto err2;
	if(U(!(out=malloc(*olen))))goto err3;
	if(type)
	{
		if(U(!RSA_padding_add_PKCS1_OAEP_mgf1(tmp,*olen,data,dlen,NULL,
			0,type,type)))goto err4;
	}
	else if(U(!RSA_padding_add_PKCS1_OAEP(tmp,*olen,data,dlen,NULL,0)))
		goto err4;
	if(L(RSA_public_encrypt(*olen,tmp,out,rsa,RSA_NO_PADDING)==*olen))
		goto err3;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(out,RSA_size(rsa));
	free(out);
	out=NULL;
err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,RSA_size(rsa));
	free(tmp);
err2:	RSA_free(rsa);
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
	void *type;
	RSA *rsa;
	unsigned char *tmp;
	unsigned char *out=NULL;

	switch(md)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		type=NULL;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		type=(void *)EVP_sha256();
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		type=(void *)EVP_sha384();
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		type=(void *)EVP_sha512();
		break;
#endif
	default:goto err1;
	}

	if(U(!(rsa=EVP_PKEY_get1_RSA(key))))goto err1;
	*olen=RSA_size(rsa);
	if(U(dlen!=*olen))goto err2;
	if(U(!(tmp=malloc(*olen))))goto err2;
	if(U(!(out=malloc(*olen))))goto err3;
	if(U(RSA_private_decrypt(dlen,data,tmp,rsa,RSA_NO_PADDING)!=*olen))
		goto err4;
	if(U(tmp[0]))goto err4;
	if(type)
	{
		if(U((l=RSA_padding_check_PKCS1_OAEP_mgf1(out,*olen,tmp+1,
			*olen-1,*olen,NULL,0,type,type))==-1))goto err4;
	}
	else if(U((l=RSA_padding_check_PKCS1_OAEP(out,*olen,tmp+1,*olen-1,*olen,
		NULL,0))==-1))goto err4;
	out=USICRYPT(do_realloc)(ctx,out,*olen,l);
	*olen=l;
	goto err3;

err4:	((struct usicrypt_thread *)ctx)->global->memclear(out,RSA_size(rsa));
	free(out);
	out=NULL;
err3:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,RSA_size(rsa));
	free(tmp);
err2:	RSA_free(rsa);
err1:	return out;
#else
	return NULL;
#endif
}

void USICRYPT(rsa_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_RSA
	EVP_PKEY_free((EVP_PKEY *)key);
#endif
}

void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len)
{
#ifndef USICRYPT_NO_DH
	int l;
	DH *dh;
	unsigned char *data=NULL;
	unsigned char *m;

	if(U(bits<USICRYPT_DH_BITS_MIN)||U(bits>USICRYPT_DH_BITS_MAX)||
		U(bits&7)||U(generator!=2&&generator!=5))goto err1;
	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(dh=DH_new())))goto err1;
	if(U(!DH_generate_parameters_ex(dh,bits,generator,NULL)))goto err2;
	if(U((l=i2d_DHparams(dh,NULL))<=0))goto err2;
	if(U(!(m=data=malloc(l))))goto err2;
	if(U((*len=i2d_DHparams(dh,&m))<=0))goto err3;
	if(L(l==*len))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(data,l);
	free(data);
	data=NULL;
err2:	DH_free(dh);
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_init)(void *ctx,void *params,int len)
{
#ifndef USICRYPT_NO_DH
	int c;
	int msk;
	void *r;
	const BIGNUM *g;

	if(U(!(r=d2i_DHparams(NULL,(const unsigned char **)&params,len))))
		goto err1;
	if(U(DH_size(r)<USICRYPT_DH_BYTES_MIN)||
		U(DH_size(r)>USICRYPT_DH_BYTES_MAX))goto err2;
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	g=((DH *)r)->g;
#else
	DH_get0_pqg(r,NULL,NULL,&g);
#endif
	if(BN_is_word(g,2)||BN_is_word(g,5))msk=-1;
	else msk=~(DH_CHECK_P_NOT_SAFE_PRIME|DH_UNABLE_TO_CHECK_GENERATOR);
	if(U(!DH_check(r,&c))||U(c&msk))goto err2;
	return r;

err2:	DH_free(r);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len)
{
#ifndef USICRYPT_NO_DH
	DH *d=dh;
	const BIGNUM *pub;
	unsigned char *num;

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(DH_generate_key(d)!=1))goto err1;
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	pub=d->pub_key;
#else
	DH_get0_key(d,&pub,NULL);
#endif
	*len=BN_num_bytes(pub);
	if(U(!(num=malloc(*len))))goto err1;
	BN_bn2bin(pub,num);
	return num;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,int *slen)
{
#ifndef USICRYPT_NO_DH
	BIGNUM *bn;
	unsigned char *sec;

	if(U(!(bn=BN_bin2bn(pub,plen,NULL))))goto err1;
	if(U(!(sec=malloc(DH_size(dh)))))goto err2;
	if(U((*slen=DH_compute_key(sec,bn,dh))==-1))goto err3;
	BN_free(bn);
	return sec;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(sec,DH_size(dh));
	free(sec);
err2:	BN_free(bn);
err1:	return NULL;
#else
	return NULL;
#endif
}

void USICRYPT(dh_free)(void *ctx,void *dh)
{
#ifndef USICRYPT_NO_DH
	DH_free(dh);
#endif
}

void *USICRYPT(ec_generate)(void *ctx,int curve)
{
#ifndef USICRYPT_NO_EC
	int nid;
	EC_KEY *k;
	EVP_PKEY *key;
	char *name;

        switch(curve)
        {
        case USICRYPT_BRAINPOOLP512R1:
		name="brainpoolP512r1";
		break;
        case USICRYPT_BRAINPOOLP384R1:
		name="brainpoolP384r1";
		break;
        case USICRYPT_BRAINPOOLP256R1:
		name="brainpoolP256r1";
		break;
        case USICRYPT_SECP521R1:
		name="secp521r1";
		break;
        case USICRYPT_SECP384R1:
		name="secp384r1";
		break;
        case USICRYPT_SECP256R1:
		name="prime256v1";
                break;
        default:goto err1;
        }
	if(U(xssl_reseed(ctx)))goto err1;
	if(U((nid=OBJ_txt2nid((const char *)name))==NID_undef))goto err1;
	if(U(!(k=EC_KEY_new_by_curve_name(nid))))goto err1;
	EC_KEY_set_asn1_flag(k,OPENSSL_EC_NAMED_CURVE);
	if(U(!EC_KEY_generate_key(k)))goto err2;
	if(U(!(key=EVP_PKEY_new())))goto err2;
	if(U(!(EVP_PKEY_assign_EC_KEY(key,k))))goto err3;
	return key;

err3:	EVP_PKEY_free(key);
err2:	EC_KEY_free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ec_identifier)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	int nid;
	EC_KEY *ec;
	const EC_GROUP *grp;
	ASN1_OBJECT *obj;
	int res=-1;
	char bfr[32];

	if(U(!(ec=EVP_PKEY_get1_EC_KEY((EVP_PKEY *)key))))goto err1;
	if(U(!(grp=EC_KEY_get0_group(ec))))goto err2;
	if(U(!(nid=EC_GROUP_get_curve_name(grp))))goto err2;
	if(U(!(obj=OBJ_nid2obj(nid))))goto err2;
	OBJ_obj2txt(bfr,sizeof(bfr),obj,0);
	if(!strcmp(bfr,"brainpoolP512r1"))res=USICRYPT_BRAINPOOLP512R1;
	else if(!strcmp(bfr,"brainpoolP384r1"))res=USICRYPT_BRAINPOOLP384R1;
	else if(!strcmp(bfr,"brainpoolP256r1"))res=USICRYPT_BRAINPOOLP256R1;
	else if(!strcmp(bfr,"secp521r1"))res=USICRYPT_SECP521R1;
	else if(!strcmp(bfr,"secp384r1"))res=USICRYPT_SECP384R1;
	else if(!strcmp(bfr,"prime256v1"))res=USICRYPT_SECP256R1;

err2:	EC_KEY_free(ec);
err1:	return res;
#else
	return -1;
#endif
}

void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_EC
	size_t len;
	EVP_PKEY_CTX *pkey;
	unsigned char *s=NULL;

	if(U(!(pkey=EVP_PKEY_CTX_new((EVP_PKEY *)key,NULL))))goto err1;
	if(U(EVP_PKEY_derive_init(pkey)!=1))goto err2;
	if(U(EVP_PKEY_derive_set_peer(pkey,(EVP_PKEY *)pub)!=1))goto err2;
	if(U(EVP_PKEY_derive(pkey,NULL,&len)!=1))goto err2;
	if(U(!(s=malloc(len))))goto err2;
	*klen=len;
	if(U(EVP_PKEY_derive(pkey,s,&len)==1))goto err2;

	((struct usicrypt_thread *)ctx)->global->memclear(s,len);
	free(s);
	s=NULL;
err2:	EVP_PKEY_CTX_free(pkey);
err1:	return s;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_EC
	int l;
	EC_KEY *k;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U(!(k=EVP_PKEY_get1_EC_KEY((EVP_PKEY *)key))))goto err1;
	if(U((l=i2d_EC_PUBKEY(k,NULL))<=0))goto err2;
	if(U(!(m=p=malloc(l))))goto err2;
	if(U((*len=i2d_EC_PUBKEY(k,&m))<=0))goto err3;
	if(L(*len==l))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err2:	EC_KEY_free(k);
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	const unsigned char *pp=key;
	EC_KEY *k;
	EVP_PKEY *kk;

	if(U(!(k=d2i_EC_PUBKEY(NULL,&pp,(long)len))))goto err1;
	if(U(!(kk=EVP_PKEY_new())))goto err2;
	if(U(!(EVP_PKEY_assign_EC_KEY(kk,k))))goto err3;
	return kk;

err3:	EVP_PKEY_free(kk);
err2:	EC_KEY_free(k);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_EC
	int l;
	EC_KEY *k;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U(!(k=EVP_PKEY_get1_EC_KEY((EVP_PKEY *)key))))goto err1;
	if(U((l=i2d_ECPrivateKey(k,NULL))<=0))goto err2;
	if(U(!(m=p=malloc(l))))goto err2;
	if(U((*len=i2d_ECPrivateKey(k,&m))<=0))goto err3;
	if(L(*len==l))goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err2:	EC_KEY_free(k);
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ec_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_EC
	const unsigned char *pp=key;
	EC_KEY *k;
	EVP_PKEY *kk;

	if(U(!(k=d2i_ECPrivateKey(NULL,&pp,(long)len))))goto err1;
	if(U(!(kk=EVP_PKEY_new())))goto err2;
	if(U(!(EVP_PKEY_assign_EC_KEY(kk,k))))goto err3;
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return kk;

err3:	EVP_PKEY_free(kk);
err2:	EC_KEY_free(k);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
}

void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen)
{
#ifndef USICRYPT_NO_EC
	return xssl_ec_do_sign(ctx,md,key,data,dlen,slen,0);
#else
	return NULL;
#endif
}

void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return xssl_ec_do_sign(ctx,md,key,iov,niov,slen,1);
#else
	return NULL;
#endif
}

int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen)
{
#ifndef USICRYPT_NO_EC
	return xssl_ec_do_verify(ctx,md,key,data,dlen,sig,slen,0);
#else
	return -1;
#endif
}

int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_EC) && !defined(USICRYPT_NO_IOV)
	return xssl_ec_do_verify(ctx,md,key,iov,niov,sig,slen,1);
#else
	return -1;
#endif
}

void USICRYPT(ec_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_EC
	EVP_PKEY_free((EVP_PKEY *)key);
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)

void *USICRYPT(ed25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_ED25519
	EVP_PKEY *pkey=NULL;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);

	if(U(!pctx))goto err1;
	if(U(EVP_PKEY_keygen_init(pctx)!=1))goto err2;
	if(U(EVP_PKEY_keygen(pctx,&pkey)!=1))goto err2;
	EVP_PKEY_CTX_free(pctx);
	return pkey;

err2:	EVP_PKEY_CTX_free(pctx);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED25519
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PUBKEY(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PUBKEY(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
err2:	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED25519
	return d2i_PUBKEY(NULL,(const unsigned char **)&key,len);
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED25519
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PrivateKey(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PrivateKey(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
err2:	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED25519
	return d2i_PrivateKey(NID_ED25519,NULL,(const unsigned char **)&key,
		len);
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_sign)(void *ctx,void *key,void *data,int dlen,int *slen)
{
#ifndef USICRYPT_NO_ED25519
	size_t olen=64;
	void *sig;
	EVP_MD_CTX *c;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
	EVP_PKEY_CTX *pctxx=pctx;

	if(U(!pctx))goto err1;
	if(U(!(sig=malloc(olen))))goto err2;
	if(U(!(c=EVP_MD_CTX_create())))goto err3;
	if(U(EVP_DigestSignInit(c,&pctxx,NULL,NULL,key)!=1))goto err4;
	if(U(EVP_DigestSign(c,sig,&olen,data,dlen)!=1))goto err4;
	EVP_MD_CTX_destroy(c);
	EVP_PKEY_CTX_free(pctx);
	*slen=64;
	return sig;

err4:	EVP_MD_CTX_destroy(c);
err3:	free(sig);
err2:	EVP_PKEY_CTX_free(pctx);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_sign_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,int *slen)
{
#if !defined(USICRYPT_NO_ED25519) && !defined(USICRYPT_NO_IOV)
	unsigned char *sig;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(sig=malloc(*slen))))goto err1;
	if(U(!(data=malloc(len))))goto err2;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	sig=USICRYPT(ed25519_sign)(ctx,key,data,len,slen);
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
	return sig;

err2:	free(sig);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ed25519_verify)(void *ctx,void *key,void *data,int dlen,void *sig,
	int slen)
{
#ifndef USICRYPT_NO_ED25519
	int err=-1;
	EVP_MD_CTX *c;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);
	EVP_PKEY_CTX *pctxx=pctx;

	if(U(!pctx))goto err1;
	if(U(!(c=EVP_MD_CTX_create())))goto err2;
	if(U(EVP_DigestVerifyInit(c,&pctxx,NULL,NULL,key)!=1))goto err3;
	if(U(EVP_DigestVerify(c,sig,slen,data,dlen)!=1))goto err3;
	err=0;
err3:	EVP_MD_CTX_destroy(c);
err2:	EVP_PKEY_CTX_free(pctx);
err1:	return err;
#else
	return -1;
#endif
}

int USICRYPT(ed25519_verify_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_ED25519) && !defined(USICRYPT_NO_IOV)
	int err=-1;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(data=malloc(len))))goto err1;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	err=USICRYPT(ed25519_verify)(ctx,key,data,len,sig,slen);
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
err1:	return err;
#else
	return -1;
#endif
}

void USICRYPT(ed25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_ED25519
	EVP_PKEY_free(key);
#endif
}

#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)

void *USICRYPT(ed448_generate)(void *ctx)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	EVP_PKEY *pkey=NULL;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED448,NULL);

	if(U(!pctx))goto err1;
	if(U(EVP_PKEY_keygen_init(pctx)!=1))goto err2;
	if(U(EVP_PKEY_keygen(pctx,&pkey)!=1))goto err2;
	EVP_PKEY_CTX_free(pctx);
	return pkey;

err2:	EVP_PKEY_CTX_free(pctx);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_get_pub)(void *ctx,void *key,int *len)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PUBKEY(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PUBKEY(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
err2:	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_set_pub)(void *ctx,void *key,int len)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	return d2i_PUBKEY(NULL,(const unsigned char **)&key,len);
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_get_key)(void *ctx,void *key,int *len)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PrivateKey(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PrivateKey(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
err2:	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_set_key)(void *ctx,void *key,int len)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	return d2i_PrivateKey(NID_ED448,NULL,(const unsigned char **)&key,
		len);
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_sign)(void *ctx,void *key,void *data,int dlen,int *slen)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	size_t olen=114;
	void *sig;
	EVP_MD_CTX *c;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED448,NULL);
	EVP_PKEY_CTX *pctxx=pctx;

	if(U(!pctx))goto err1;
	if(U(!(sig=malloc(olen))))goto err2;
	if(U(!(c=EVP_MD_CTX_create())))goto err3;
	if(U(EVP_DigestSignInit(c,&pctxx,NULL,NULL,key)!=1))goto err4;
	if(U(EVP_DigestSign(c,sig,&olen,data,dlen)!=1))goto err4;
	EVP_MD_CTX_destroy(c);
	EVP_PKEY_CTX_free(pctx);
	*slen=114;
	return sig;

err4:	EVP_MD_CTX_destroy(c);
err3:	free(sig);
err2:	EVP_PKEY_CTX_free(pctx);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_sign_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,int *slen)
{
#if !defined(USICRYPT_NO_ED448) && !defined(USICRYPT_NO_IOV) && \
	defined(XSSL_HAS_CURVE448)
	unsigned char *sig;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(sig=malloc(*slen))))goto err1;
	if(U(!(data=malloc(len))))goto err2;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	sig=USICRYPT(ed448_sign)(ctx,key,data,len,slen);
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
	return sig;

err2:	free(sig);
err1:	return NULL;
#else
	return NULL;
#endif
}

int USICRYPT(ed448_verify)(void *ctx,void *key,void *data,int dlen,void *sig,
	int slen)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	int err=-1;
	EVP_MD_CTX *c;
	EVP_PKEY_CTX *pctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED448,NULL);
	EVP_PKEY_CTX *pctxx=pctx;

	if(U(!pctx))goto err1;
	if(U(!(c=EVP_MD_CTX_create())))goto err2;
	if(U(EVP_DigestVerifyInit(c,&pctxx,NULL,NULL,key)!=1))goto err3;
	if(U(EVP_DigestVerify(c,sig,slen,data,dlen)!=1))goto err3;
	err=0;
err3:	EVP_MD_CTX_destroy(c);
err2:	EVP_PKEY_CTX_free(pctx);
err1:	return err;
#else
	return -1;
#endif
}

int USICRYPT(ed448_verify_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_ED448) && !defined(USICRYPT_NO_IOV) && \
	defined(XSSL_HAS_CURVE448)
	int err=-1;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(data=malloc(len))))goto err1;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	err=USICRYPT(ed448_verify)(ctx,key,data,len,sig,slen);
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
err1:	return err;
#else
	return -1;
#endif
}

void USICRYPT(ed448_free)(void *ctx,void *key)
{
#if !defined(USICRYPT_NO_ED448) && defined(XSSL_HAS_CURVE448)
	EVP_PKEY_free(key);
#endif
}

#endif

void *USICRYPT(x25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	struct xssl_x25519 *x;

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(x=malloc(sizeof(struct xssl_x25519)))))goto err1;
	X25519_keypair(x->pub,x->key);
	return x;

err1:	return NULL;
#else
	return NULL;
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_PKEY_CTX *c;
	EVP_PKEY *key;

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(c=EVP_PKEY_CTX_new_id(NID_X25519,NULL))))goto err1;
	if(U(EVP_PKEY_keygen_init(c)!=1))goto err2;
	if(U(!(key=EVP_PKEY_new())))goto err2;
	if(U(EVP_PKEY_keygen(c,&key)!=1))goto err3;
	EVP_PKEY_CTX_free(c);
	return key;

err3:	EVP_PKEY_free(key);
err2:	EVP_PKEY_CTX_free(c);
err1:	return NULL;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	unsigned char *data;

	*klen=X25519_KEY_LENGTH;
	if(U(!(data=malloc(*klen))))goto err1;
	if(U(X25519(data,((struct xssl_x25519 *)key)->key,
		((struct xssl_x25519 *)pub)->pub)!=1))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*klen);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	size_t len;
	EVP_PKEY_CTX *c;
	unsigned char *data;

	if(U(!(c=EVP_PKEY_CTX_new(key,NULL))))goto err1;
	if(U(EVP_PKEY_derive_init(c)!=1))goto err2;
	if(U(EVP_PKEY_derive_set_peer(c,pub)!=1))goto err2;
	if(U(EVP_PKEY_derive(c,NULL,&len)!=1))goto err2;
	if(U(!(data=malloc(len))))goto err2;
	if(U(EVP_PKEY_derive(c,data,&len)!=1))goto err3;
	EVP_PKEY_CTX_free(c);
	*klen=len;
	return data;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
err2:	EVP_PKEY_CTX_free(c);
err1:	return NULL;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	unsigned char *data;

	*len=sizeof(xssl_x25519_asn1_pub)+X25519_KEY_LENGTH;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,xssl_x25519_asn1_pub,sizeof(xssl_x25519_asn1_pub));
	memcpy(data+sizeof(xssl_x25519_asn1_pub),
		((struct xssl_x25519 *)key)->pub,X25519_KEY_LENGTH);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	unsigned char *data;
	unsigned char *p;

	*len=sizeof(xssl_x25519_asn1_pub)+32;
	if(U(!(p=data=malloc(*len))))goto err1;
	if(U(i2d_PUBKEY(key,&p)!=*len))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	struct xssl_x25519 *x;

	if(U(len<sizeof(xssl_x25519_asn1_pub)+X25519_KEY_LENGTH)||
	    U(memcmp(key,xssl_x25519_asn1_pub,sizeof(xssl_x25519_asn1_pub))))
		goto err1;
	if(U(!(x=malloc(sizeof(struct xssl_x25519)))))goto err1;
	memcpy(x->pub,((unsigned char *)key)+sizeof(xssl_x25519_asn1_pub),
		X25519_KEY_LENGTH);
	return x;

err1:	return NULL;
#else
	return NULL;
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	if(U(len<sizeof(xssl_x25519_asn1_pub)+32)||
	    U(memcmp(key,xssl_x25519_asn1_pub,sizeof(xssl_x25519_asn1_pub))))
		return NULL;
	return d2i_PUBKEY(NULL,(const unsigned char **)&key,len);
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	unsigned char *data;

	*len=sizeof(xssl_x25519_asn1_key)+X25519_KEY_LENGTH;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,xssl_x25519_asn1_key,sizeof(xssl_x25519_asn1_key));
	memcpy(data+sizeof(xssl_x25519_asn1_key),
		((struct xssl_x25519 *)key)->key,X25519_KEY_LENGTH);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PrivateKey(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PrivateKey(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	struct xssl_x25519 *x;
	unsigned char bfr[X25519_KEY_LENGTH];

	if(U(len<sizeof(xssl_x25519_asn1_key)+X25519_KEY_LENGTH)||
	    U(memcmp(key,xssl_x25519_asn1_key,sizeof(xssl_x25519_asn1_key))))
		goto err1;
	if(U(!(x=malloc(sizeof(struct xssl_x25519)))))goto err1;
	memcpy(x->key,((unsigned char *)key)+sizeof(xssl_x25519_asn1_key),
		X25519_KEY_LENGTH);
	x->pub[0]=0x09;
	memset(x->pub+1,0,X25519_KEY_LENGTH-1);
	/* need to ignore errors, replaces x25519_public_from_private(), doh! */
	X25519(bfr,x->key,x->pub);
	memcpy(x->pub,bfr,X25519_KEY_LENGTH);
	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return x;

err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
#endif
	return NULL;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	void *mem=key;
	void *r=NULL;

	if(U(len<sizeof(xssl_x25519_asn1_key)+32)||
	    U(memcmp(key,xssl_x25519_asn1_key,sizeof(xssl_x25519_asn1_key))))
		goto err1;
	r=d2i_PrivateKey(NID_X25519,NULL,(const unsigned char **)&key,len);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(mem,len);
	return r;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void USICRYPT(x25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_X25519
#if defined(LIBRESSL_VERSION_NUMBER)
#if LIBRESSL_VERSION_NUMBER >= 0x20500000L
	((struct usicrypt_thread *)ctx)->global->
		memclear(key,sizeof(struct xssl_x25519));
	free(key);
#endif
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	EVP_PKEY_free((EVP_PKEY *)key);
#endif
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)

void *USICRYPT(x448_generate)(void *ctx)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	EVP_PKEY_CTX *c;
	EVP_PKEY *key;

	if(U(xssl_reseed(ctx)))goto err1;
	if(U(!(c=EVP_PKEY_CTX_new_id(NID_X448,NULL))))goto err1;
	if(U(EVP_PKEY_keygen_init(c)!=1))goto err2;
	if(U(!(key=EVP_PKEY_new())))goto err2;
	if(U(EVP_PKEY_keygen(c,&key)!=1))goto err3;
	EVP_PKEY_CTX_free(c);
	return key;

err3:	EVP_PKEY_free(key);
err2:	EVP_PKEY_CTX_free(c);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_derive)(void *ctx,void *key,void *pub,int *klen)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	size_t len;
	EVP_PKEY_CTX *c;
	unsigned char *data;

	if(U(!(c=EVP_PKEY_CTX_new(key,NULL))))goto err1;
	if(U(EVP_PKEY_derive_init(c)!=1))goto err2;
	if(U(EVP_PKEY_derive_set_peer(c,pub)!=1))goto err2;
	if(U(EVP_PKEY_derive(c,NULL,&len)!=1))goto err2;
	if(U(!(data=malloc(len))))goto err2;
	if(U(EVP_PKEY_derive(c,data,&len)!=1))goto err3;
	EVP_PKEY_CTX_free(c);
	*klen=len;
	return data;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
err2:	EVP_PKEY_CTX_free(c);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_get_pub)(void *ctx,void *key,int *len)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	unsigned char *data;
	unsigned char *p;

	*len=sizeof(xssl_x448_asn1_pub)+56;
	if(U(!(p=data=malloc(*len))))goto err1;
	if(U(i2d_PUBKEY(key,&p)!=*len))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*len);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_set_pub)(void *ctx,void *key,int len)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	if(U(len<sizeof(xssl_x448_asn1_pub)+56)||
	    U(memcmp(key,xssl_x448_asn1_pub,sizeof(xssl_x448_asn1_pub))))
		return NULL;
	return d2i_PUBKEY(NULL,(const unsigned char **)&key,len);
#else
	return NULL;
#endif
}

void *USICRYPT(x448_get_key)(void *ctx,void *key,int *len)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	int l;
	unsigned char *p=NULL;
	unsigned char *m;

	if(U((l=i2d_PrivateKey(key,NULL))<=0))goto err1;
	if(U(!(m=p=malloc(l))))goto err1;
	if(U((*len=i2d_PrivateKey(key,&m))<=0))goto err2;
	if(L(*len==l))goto err1;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(p,l);
	free(p);
	p=NULL;
err1:	return p;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_set_key)(void *ctx,void *key,int len)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	void *mem=key;
	void *r=NULL;

	if(U(len<sizeof(xssl_x448_asn1_key)+56)||
	    U(memcmp(key,xssl_x448_asn1_key,sizeof(xssl_x448_asn1_key))))
		goto err1;
	r=d2i_PrivateKey(NID_X448,NULL,(const unsigned char **)&key,len);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(mem,len);
	return r;
#else
	return NULL;
#endif
}

void USICRYPT(x448_free)(void *ctx,void *key)
{
#if !defined(USICRYPT_NO_X448) && defined(XSSL_HAS_CURVE448)
	EVP_PKEY_free((EVP_PKEY *)key);
#endif
}

#endif

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
		if(U(!(c=xssl_aes_ecb_init(ctx,key,klen))))break;
		c->encrypt=xssl_aes_ecb_encrypt;
		c->decrypt=xssl_aes_ecb_decrypt;
		c->reset=NULL;
		c->exit=xssl_aes_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		if(U(!(c=xssl_aes_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_cbc_encrypt;
		c->decrypt=xssl_aes_cbc_decrypt;
		c->reset=xssl_aes_cbc_reset;
		c->exit=xssl_aes_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_AES|USICRYPT_CTS:
		if(U(!(c=xssl_aes_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_cts_encrypt;
		c->decrypt=xssl_aes_cts_decrypt;
		c->reset=xssl_aes_cts_reset;
		c->exit=xssl_aes_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		if(U(!(c=xssl_aes_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_cfb_encrypt;
		c->decrypt=xssl_aes_cfb_decrypt;
		c->reset=xssl_aes_cfb_reset;
		c->exit=xssl_aes_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_AES|USICRYPT_CFB8:
		if(U(!(c=xssl_aes_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_cfb8_encrypt;
		c->decrypt=xssl_aes_cfb8_decrypt;
		c->reset=xssl_aes_cfb8_reset;
		c->exit=xssl_aes_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		if(U(!(c=xssl_aes_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_ofb_crypt;
		c->decrypt=xssl_aes_ofb_crypt;
		c->reset=xssl_aes_ofb_reset;
		c->exit=xssl_aes_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_AES|USICRYPT_CTR:
		if(U(!(c=xssl_aes_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_aes_ctr_crypt;
		c->decrypt=xssl_aes_ctr_crypt;
		c->reset=xssl_aes_ctr_reset;
		c->exit=xssl_aes_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		if(U(!(c=xssl_camellia_ecb_init(ctx,key,klen))))break;
		c->encrypt=xssl_camellia_ecb_encrypt;
		c->decrypt=xssl_camellia_ecb_decrypt;
		c->reset=NULL;
		c->exit=xssl_camellia_ecb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		if(U(!(c=xssl_camellia_cbc_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_cbc_encrypt;
		c->decrypt=xssl_camellia_cbc_decrypt;
		c->reset=xssl_camellia_cbc_reset;
		c->exit=xssl_camellia_cbc_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTS
	case USICRYPT_CAMELLIA|USICRYPT_CTS:
		if(U(!(c=xssl_camellia_cts_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_cts_encrypt;
		c->decrypt=xssl_camellia_cts_decrypt;
		c->reset=xssl_camellia_cts_reset;
		c->exit=xssl_camellia_cts_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		if(U(!(c=xssl_camellia_cfb_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_cfb_encrypt;
		c->decrypt=xssl_camellia_cfb_decrypt;
		c->reset=xssl_camellia_cfb_reset;
		c->exit=xssl_camellia_cfb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CFB8
	case USICRYPT_CAMELLIA|USICRYPT_CFB8:
		if(U(!(c=xssl_camellia_cfb8_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_cfb8_encrypt;
		c->decrypt=xssl_camellia_cfb8_decrypt;
		c->reset=xssl_camellia_cfb8_reset;
		c->exit=xssl_camellia_cfb8_exit;
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		if(U(!(c=xssl_camellia_ofb_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_ofb_crypt;
		c->decrypt=xssl_camellia_ofb_crypt;
		c->reset=xssl_camellia_ofb_reset;
		c->exit=xssl_camellia_ofb_exit;
		break;
#endif
#ifndef USICRYPT_NO_CTR
	case USICRYPT_CAMELLIA|USICRYPT_CTR:
		if(U(!(c=xssl_camellia_ctr_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_camellia_ctr_crypt;
		c->decrypt=xssl_camellia_ctr_crypt;
		c->reset=xssl_camellia_ctr_reset;
		c->exit=xssl_camellia_ctr_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_STREAM
	case USICRYPT_CHACHA20|USICRYPT_STREAM:
		if(U(!(c=xssl_chacha_init(ctx,key,klen,iv))))break;
		c->encrypt=xssl_chacha_crypt;
		c->decrypt=xssl_chacha_crypt;
		c->reset=xssl_chacha_reset;
		c->exit=xssl_chacha_exit;
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
		if(U(!(c=xssl_aes_xts_init(ctx,key,klen))))break;
		c->encrypt=xssl_aes_xts_encrypt;
		c->decrypt=xssl_aes_xts_decrypt;
		c->exit=xssl_aes_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_AES|USICRYPT_ESSIV:
		if(U(!(c=xssl_aes_essiv_init(ctx,key,klen))))break;
		c->encrypt=xssl_aes_essiv_encrypt;
		c->decrypt=xssl_aes_essiv_decrypt;
		c->exit=xssl_aes_essiv_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_XTS
	case USICRYPT_CAMELLIA|USICRYPT_XTS:
		if(U(!(c=xssl_camellia_xts_init(ctx,key,klen))))break;
		c->encrypt=xssl_camellia_xts_encrypt;
		c->decrypt=xssl_camellia_xts_decrypt;
		c->exit=xssl_camellia_xts_exit;
		break;
#endif
#ifndef USICRYPT_NO_ESSIV
	case USICRYPT_CAMELLIA|USICRYPT_ESSIV:
		if(U(!(c=xssl_camellia_essiv_init(ctx,key,klen))))break;
		c->encrypt=xssl_camellia_essiv_encrypt;
		c->decrypt=xssl_camellia_essiv_decrypt;
		c->exit=xssl_camellia_essiv_exit;
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
		if(U(!(c=xssl_aes_gcm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=xssl_aes_gcm_encrypt;
		c->decrypt=xssl_aes_gcm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=xssl_aes_gcm_encrypt_iov;
		c->decrypt_iov=xssl_aes_gcm_decrypt_iov;
#endif
		c->exit=xssl_aes_gcm_exit;
		break;
#endif
#ifndef USICRYPT_NO_CCM
	case USICRYPT_AES_CCM:
		if(U(!(c=xssl_aes_ccm_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=xssl_aes_ccm_encrypt;
		c->decrypt=xssl_aes_ccm_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=xssl_aes_ccm_encrypt_iov;
		c->decrypt_iov=xssl_aes_ccm_decrypt_iov;
#endif
		c->exit=xssl_aes_ccm_exit;
		break;
#endif
#endif
#ifndef USICRYPT_NO_CHACHA
#ifndef USICRYPT_NO_POLY
	case USICRYPT_CHACHA20_POLY1305:
		if(U(!(c=xssl_chacha_poly_init(ctx,key,klen,ilen,tlen))))break;
		c->encrypt=xssl_chacha_poly_encrypt;
		c->decrypt=xssl_chacha_poly_decrypt;
#ifndef USICRYPT_NO_IOV
		c->encrypt_iov=xssl_chacha_poly_encrypt_iov;
		c->decrypt_iov=xssl_chacha_poly_decrypt_iov;
#endif
		c->exit=xssl_chacha_poly_exit;
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
		return xssl_aes_cmac(ctx,key,klen,src,slen,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return xssl_camellia_cmac(ctx,key,klen,src,slen,dst);
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
		return xssl_aes_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#ifndef USICRYPT_NO_CAMELLIA
	case USICRYPT_CAMELLIA:
		return xssl_camellia_cmac_iov(ctx,key,klen,iov,niov,dst);
#endif
#endif
	default:return -1;
	}
}

void *USICRYPT(encrypt_p8)(void *ctx,void *key,int klen,void *data,int dlen,
	int cipher,int mode,int bits,int digest,int iter,int *rlen)
{
#ifndef USICRYPT_NO_PBKDF2
/* LibreSSL doesn't support prf setting, doh! */
#ifdef LIBRESSL_VERSION_NUMBER
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

	if(U(dlen>0x3fff)||U(iter<=0)||
		U(digest==USICRYPT_SHA1&&bits!=128))goto err1;

	if(U(xssl_asn_next(data,dlen,0x30,&cidx,&didx)))goto err1;
	if(U(cidx+didx!=dlen))goto err1;

	for(didx=0;didx<4;didx++)if(xssl_digest_asn[didx].oidlen&&
		xssl_digest_asn[didx].digest==digest)break;
	if(U(didx==4))goto err1;

	for(cidx=0;cidx<24;cidx++)if(xssl_cipher_asn[cidx].oidlen&&
		xssl_cipher_asn[cidx].cipher==cipher&&
		xssl_cipher_asn[cidx].mode==mode&&
		xssl_cipher_asn[cidx].bits==bits)break;
	if(U(cidx==24))goto err1;

	if(U(USICRYPT(random)(ctx,salt,8)))goto err1;
	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,8,iter,bfr)))goto err2;

	if(xssl_cipher_asn[cidx].ivlen)
		if(U(USICRYPT(random)(ctx,iv,xssl_cipher_asn[cidx].ivlen)))
			goto err3;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,cipher,mode,bfr,bits,iv))))
		goto err4;

	if(iter>=0x800000)ilen=4;
	else if(iter>=0x8000)ilen=3;
	else if(iter>=0x80)ilen=2;
	else ilen=1;

	if(xssl_cipher_asn[cidx].pad)
		plen=usicrypt_cipher_padding_add(ctx,NULL,dlen);
	else plen=0;
	len1=xssl_asn_length(NULL,dlen+plen)+1;
	len2=xssl_cipher_asn[cidx].oidlen+xssl_cipher_asn[cidx].ivlen+6;
	len3=ilen+sizeof(xssl_pbes2_oid)+sizeof(xssl_pbkdf2_oid)+24;
	if(digest!=USICRYPT_SHA1)len3+=xssl_digest_asn[didx].oidlen+6;
	*rlen=xssl_asn_length(NULL,len1+len2+len3+dlen+plen)+
		len1+len2+len3+dlen+plen+1;

	if(U(!(ptr=out=malloc(*rlen))))goto err5;

	*ptr++=0x30;
	ptr+=xssl_asn_length(ptr,len1+len2+len3+dlen+plen);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(xssl_pbes2_oid);
	memcpy(ptr,xssl_pbes2_oid,sizeof(xssl_pbes2_oid));
	ptr+=sizeof(xssl_pbes2_oid);
	len3-=sizeof(xssl_pbes2_oid)+6;
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2+len3);
	*ptr++=0x30;
	*ptr++=(unsigned char)(len3-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)sizeof(xssl_pbkdf2_oid);
	memcpy(ptr,xssl_pbkdf2_oid,sizeof(xssl_pbkdf2_oid));
	ptr+=sizeof(xssl_pbkdf2_oid);
	*ptr++=0x30;
	*ptr++=(unsigned char)
	     (ilen+12+(digest!=USICRYPT_SHA1?xssl_digest_asn[didx].oidlen+6:0));
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
		*ptr++=(unsigned char)(xssl_digest_asn[didx].oidlen+4);
		*ptr++=0x06;
		*ptr++=(unsigned char)xssl_digest_asn[didx].oidlen;
		memcpy(ptr,xssl_digest_asn[didx].oid,
			xssl_digest_asn[didx].oidlen);
		ptr+=xssl_digest_asn[didx].oidlen;
		*ptr++=0x05;
		*ptr++=0x00;
	}
	*ptr++=0x30;
	*ptr++=(unsigned char)(len2-2);
	*ptr++=0x06;
	*ptr++=(unsigned char)xssl_cipher_asn[cidx].oidlen;
	memcpy(ptr,xssl_cipher_asn[cidx].oid,xssl_cipher_asn[cidx].oidlen);
	ptr+=xssl_cipher_asn[cidx].oidlen;
	*ptr++=0x04;
	*ptr++=(unsigned char)xssl_cipher_asn[cidx].ivlen;
	if(xssl_cipher_asn[cidx].ivlen)
	{
		memcpy(ptr,iv,xssl_cipher_asn[cidx].ivlen);
		ptr+=xssl_cipher_asn[cidx].ivlen;
	}
	*ptr++=0x04;
	ptr+=xssl_asn_length(ptr,dlen+plen);
	memcpy(ptr,data,dlen);
	if(xssl_cipher_asn[cidx].pad)usicrypt_cipher_padding_add(ctx,ptr,dlen);

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
	return NULL;
#else
	int md;
	BIO *in;
	BIO *out;
	X509_SIG *p8enc;
	PKCS8_PRIV_KEY_INFO *p8dec;
	const EVP_CIPHER *cm;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	X509_ALGOR *pbk=NULL;
#endif
	unsigned char *tmp;
	unsigned char *r=NULL;

	if(U(iter<=0)||U(bits!=128&&digest==USICRYPT_SHA1))goto err1;

	switch(cipher|mode)
	{
#ifndef USICRYPT_NO_AES
#ifndef USICRYPT_NO_ECB
	case USICRYPT_AES|USICRYPT_ECB:
		switch(bits)
		{
		case 128:
			cm=EVP_aes_128_ecb();
			break;
		case 192:
			cm=EVP_aes_192_ecb();
			break;
		case 256:
			cm=EVP_aes_256_ecb();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_AES|USICRYPT_CBC:
		switch(bits)
		{
		case 128:
			cm=EVP_aes_128_cbc();
			break;
		case 192:
			cm=EVP_aes_192_cbc();
			break;
		case 256:
			cm=EVP_aes_256_cbc();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_AES|USICRYPT_CFB:
		switch(bits)
		{
		case 128:
			cm=EVP_aes_128_cfb();
			break;
		case 192:
			cm=EVP_aes_192_cfb();
			break;
		case 256:
			cm=EVP_aes_256_cfb();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_AES|USICRYPT_OFB:
		switch(bits)
		{
		case 128:
			cm=EVP_aes_128_ofb();
			break;
		case 192:
			cm=EVP_aes_192_ofb();
			break;
		case 256:
			cm=EVP_aes_256_ofb();
			break;
		default:goto err1;
		}
		break;
#endif
#endif
#ifndef USICRYPT_NO_CAMELLIA
#ifndef USICRYPT_NO_ECB
	case USICRYPT_CAMELLIA|USICRYPT_ECB:
		switch(bits)
		{
		case 128:
			cm=EVP_camellia_128_ecb();
			break;
		case 192:
			cm=EVP_camellia_192_ecb();
			break;
		case 256:
			cm=EVP_camellia_256_ecb();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_CBC
	case USICRYPT_CAMELLIA|USICRYPT_CBC:
		switch(bits)
		{
		case 128:
			cm=EVP_camellia_128_cbc();
			break;
		case 192:
			cm=EVP_camellia_192_cbc();
			break;
		case 256:
			cm=EVP_camellia_256_cbc();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_CFB
	case USICRYPT_CAMELLIA|USICRYPT_CFB:
		switch(bits)
		{
		case 128:
			cm=EVP_camellia_128_cfb();
			break;
		case 192:
			cm=EVP_camellia_192_cfb();
			break;
		case 256:
			cm=EVP_camellia_256_cfb();
			break;
		default:goto err1;
		}
		break;
#endif
#ifndef USICRYPT_NO_OFB
	case USICRYPT_CAMELLIA|USICRYPT_OFB:
		switch(bits)
		{
		case 128:
			cm=EVP_camellia_128_ofb();
			break;
		case 192:
			cm=EVP_camellia_192_ofb();
			break;
		case 256:
			cm=EVP_camellia_256_ofb();
			break;
		default:goto err1;
		}
		break;
#endif
#endif
	default:goto err1;
	}

	switch(digest)
	{
#ifndef USICRYPT_NO_SHA1
	case USICRYPT_SHA1:
		md=NID_hmacWithSHA1;
		break;
#endif
#ifndef USICRYPT_NO_SHA256
	case USICRYPT_SHA256:
		md=NID_hmacWithSHA256;
		break;
#endif
#ifndef USICRYPT_NO_SHA384
	case USICRYPT_SHA384:
		md=NID_hmacWithSHA384;
		break;
#endif
#ifndef USICRYPT_NO_SHA512
	case USICRYPT_SHA512:
		md=NID_hmacWithSHA512;
		break;
#endif
	default:goto err1;
	}

	if(U(!(in=BIO_new_mem_buf(data,dlen))))goto err1;
	if(U(!(out=BIO_new(BIO_s_mem()))))goto err2;
	if(U(!(p8dec=d2i_PKCS8_PRIV_KEY_INFO_bio(in,NULL))))goto err3;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if(U(!(pbk=PKCS5_pbe2_set_iv(cm,iter,NULL,0,NULL,md))))goto err4;
	if(U(!(p8enc=PKCS8_set0_pbe(key,klen,p8dec,pbk))))goto err5;
	pbk=NULL;
#else 
	if(U(!(p8enc=PKCS8_encrypt(md,cm,key,klen,NULL,0,iter,p8dec))))
		goto err4;
#endif
	if(U(i2d_PKCS8_bio(out,p8enc)<=0))goto err6;
	*rlen=(int)BIO_get_mem_data(out,&tmp);
	if(U(!(r=malloc(*rlen))))goto err6;
	memcpy(r,tmp,*rlen);

err6:	X509_SIG_free(p8enc);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
err5:	if(pbk)X509_ALGOR_free(pbk);
#endif
err4:	PKCS8_PRIV_KEY_INFO_free(p8dec);
err3:	BIO_free(out);
err2:	BIO_free(in);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
	return r;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(decrypt_p8)(void *ctx,void *key,int klen,void *data,int dlen,
	int *rlen)
{
#ifndef USICRYPT_NO_PBKDF2
/* LibreSSL doesn't support prf setting, doh! */
#ifdef LIBRESSL_VERSION_NUMBER
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

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	eptr=data+h+l;
	elen=dlen-h-l;
	data+=h;
	dlen=l;

	if(U(xssl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(xssl_pbes2_oid))||
		U(memcmp(data+h,xssl_pbes2_oid,l)))goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(xssl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	if(U(l!=sizeof(xssl_pbkdf2_oid))||U(memcmp(data+h,xssl_pbkdf2_oid,l)))
		goto err1;
	data+=h+l;
	dlen-=h+l;

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;
	mlen=l;

	if(U(xssl_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	salt=data+h;
	slen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(xssl_asn_next(data,dlen,0x02,&h,&l)))goto err1;
	if(U(!l)||U(l>sizeof(int)))goto err1;
	iter=data+h;
	ilen=l;
	data+=h+l;
	dlen-=h+l;
	mlen-=h+l;

	if(U(mlen<0))goto err1;
	else if(mlen)
	{
		if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
		data+=h;
		dlen-=h;

		if(U(xssl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
		md=data+h;
		mlen=l;
		data+=h+l;
		dlen-=h+l;

		if(U(xssl_asn_next(data,dlen,0x05,&h,&l)))goto err1;
		if(U(l))goto err1;
		data+=h;
		dlen-=h;
	}

	if(U(xssl_asn_next(data,dlen,0x30,&h,&l)))goto err1;
	data+=h;
	dlen-=h;

	if(U(xssl_asn_next(data,dlen,0x06,&h,&l)))goto err1;
	cipher=data+h;
	clen=l;
	data+=h+l;
	dlen-=h+l;

	if(U(xssl_asn_next(data,dlen,0x04,&h,&l)))goto err1;
	iv=data+h;
	ivlen=l;
	data+=h+l;
	dlen-=h+l;
	if(U(data!=eptr))goto err1;

	if(U(xssl_asn_next(eptr,elen,0x04,&h,&l)))goto err1;
	eptr+=h;
	elen=l;

	for(l=0,h=0;h<ilen;h++)l=(l<<8)|iter[h];
	if(U(!l))goto err1;

	if(mlen)
	{
		for(h=0;h<4;h++)if(xssl_digest_asn[h].oidlen&&
			mlen==xssl_digest_asn[h].oidlen&&
			!memcmp(md,xssl_digest_asn[h].oid,mlen))break;
		if(U(h==4))goto err1;
		else digest=xssl_digest_asn[h].digest;
	}

	for(h=0;h<24;h++)if(xssl_cipher_asn[h].oidlen&&
		clen==xssl_cipher_asn[h].oidlen&&
		!memcmp(cipher,xssl_cipher_asn[h].oid,clen))break;
	if(U(h==24)||U(xssl_cipher_asn[h].ivlen!=ivlen)||
		U(xssl_cipher_asn[h].bits!=128&&digest==USICRYPT_SHA1))
		goto err1;

	if(xssl_cipher_asn[h].pad)if(U(elen&0x0f))goto err1;

	if(U(USICRYPT(pbkdf2)(ctx,digest,key,klen,salt,slen,l,bfr)))goto err1;

	if(U(!(out=malloc(elen))))goto err2;

	if(U(!(c=USICRYPT(blkcipher_init)(ctx,xssl_cipher_asn[h].cipher,
		xssl_cipher_asn[h].mode,bfr,xssl_cipher_asn[h].bits,iv))))
		goto err3;
	if(U(USICRYPT(blkcipher_decrypt)(c,eptr,elen,out)))goto err5;
	USICRYPT(blkcipher_exit)(c);

	if(xssl_cipher_asn[h].pad)
	{
		if(U((*rlen=usicrypt_cipher_padding_get(ctx,out,elen))==-1))
			goto err4;
		else *rlen=elen-*rlen;
	}
	else *rlen=elen;

	if(U(xssl_asn_next(out,*rlen,0x30,&h,&l)))goto err4;
	if(U(h+l!=*rlen))goto err4;

	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
	return USICRYPT(do_realloc)(ctx,out,elen,*rlen);

err5:	USICRYPT(blkcipher_exit)(c);
err4:	((struct usicrypt_thread *)ctx)->global->memclear(out,elen);
err3:	free(out);
err2:	((struct usicrypt_thread *)ctx)->global->memclear(bfr,sizeof(bfr));
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
	return NULL;
#else
	BIO *in;
	BIO *out;
	X509_SIG *p8enc;
	PKCS8_PRIV_KEY_INFO *p8dec;
	unsigned char *tmp;
	unsigned char *r=NULL;

	if(U(!(in=BIO_new_mem_buf(data,dlen))))goto err1;
	if(U(!(out=BIO_new(BIO_s_mem()))))goto err2;
	if(U(!(p8enc=d2i_PKCS8_bio(in,NULL))))goto err3;
	if(U(!(p8dec=PKCS8_decrypt(p8enc,key,klen))))goto err4;
	if(U(i2d_PKCS8_PRIV_KEY_INFO_bio(out,p8dec)<=0))goto err5;
	*rlen=(int)BIO_get_mem_data(out,&tmp);
	if(U(!(r=malloc(*rlen))))goto err5;
	memcpy(r,tmp,*rlen);

err5:	PKCS8_PRIV_KEY_INFO_free(p8dec);
err4:	X509_SIG_free(p8enc);
err3:	BIO_free(out);
err2:	BIO_free(in);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,klen);
	return r;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(thread_init)(void *global)
{
	struct usicrypt_thread *ctx;

	if(U(!(ctx=malloc(sizeof(struct usicrypt_thread)))))goto err1;
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
#if !defined(USICRYPT_NO_THREADS)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	int i;
	int n=CRYPTO_num_locks();
#endif
#endif
	struct usicrypt_global *ctx;
	unsigned char bfr[32];

	USICRYPT(do_realloc)(NULL,NULL,0,0);
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(USICRYPT_NO_THREADS)
	if(U(!(ctx=malloc(sizeof(struct usicrypt_global)))))goto err1;
#elif defined(_WIN64) || defined(_WIN32)
	if(U(!(ctx=malloc(sizeof(struct usicrypt_global)+n*sizeof(HANDLE)))))
		goto err1;
#else
	if(U(!(ctx=malloc(sizeof(struct usicrypt_global)+n*
		sizeof(pthread_mutex_t)))))goto err1;
#endif
#else
	if(U(!(ctx=malloc(sizeof(struct usicrypt_global)))))goto err1;
#endif
	ctx->rng_seed=(rng_seed?rng_seed:USICRYPT(get_random));
	ctx->memclear=(memclear?memclear:USICRYPT(do_memclear));
	if(U(ctx->rng_seed(bfr,sizeof(bfr))))goto err2;
	RAND_seed(bfr,sizeof(bfr));
	ctx->memclear(bfr,sizeof(bfr));
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#if !defined(USICRYPT_NO_THREADS)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(_WIN64) || defined(_WIN32)
	for(i=0;i<n;i++)ctx->lock[i]=CreateMutex(NULL,FALSE,NULL);
#else
	for(i=0;i<n;i++)pthread_mutex_init(&ctx->lock[i],NULL);
	CRYPTO_THREADID_set_callback(xssl_gettid);
#endif
	CRYPTO_set_locking_callback(xssl_locker);
	xssl_lock=ctx->lock;
#endif
#endif
	return ctx;

err2:	free(ctx);
err1:	return NULL;
}

void USICRYPT(global_exit)(void *ctx)
{
#if !defined(USICRYPT_NO_THREADS)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	int i;
	int n=CRYPTO_num_locks();
#endif
#endif

	RAND_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
#if !defined(USICRYPT_NO_THREADS)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	for(i=0;i<n;i++)
#if defined(_WIN64) || defined(_WIN32)
		CloseHandle(((struct usicrypt_global *)ctx)->lock[i]);
#else
		pthread_mutex_destroy(
			&((struct usicrypt_global *)ctx)->lock[i]);
#endif
#endif
#endif
	free(ctx);
}

#endif
