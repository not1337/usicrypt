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
/*                               Common Stuff                                 */
/******************************************************************************/

#include <string.h>
#include <stdlib.h>

#if defined(USICRYPT_MBED)
#include <mbedtls/hmac_drbg.h>
#endif
#if defined(USICRYPT_WOLF)
#include <wolfssl/wolfcrypt/random.h>
#endif
#if defined(USICRYPT_NTTL)
#include <nettle/yarrow.h>
#endif

#ifdef USICRYPT_TEST
#undef USICRYPT_NO_RSA
#undef USICRYPT_NO_DH
#undef USICRYPT_NO_EC
#undef USICRYPT_NO_X25519
#undef USICRYPT_NO_DIGEST
#undef USICRYPT_NO_HMAC
#undef USICRYPT_NO_PBKDF2
#undef USICRYPT_NO_HKDF
#undef USICRYPT_NO_BASE64
#undef USICRYPT_NO_IOV
#undef USICRYPT_NO_SHA1
#undef USICRYPT_NO_SHA256
#undef USICRYPT_NO_SHA384
#undef USICRYPT_NO_SHA512
#undef USICRYPT_NO_CMAC
#undef USICRYPT_NO_AES
#undef USICRYPT_NO_CAMELLIA
#undef USICRYPT_NO_CHACHA
#undef USICRYPT_NO_STREAM
#undef USICRYPT_NO_ECB
#undef USICRYPT_NO_CBC
#undef USICRYPT_NO_CTS
#undef USICRYPT_NO_CFB
#undef USICRYPT_NO_CFB8
#undef USICRYPT_NO_OFB
#undef USICRYPT_NO_CTR
#undef USICRYPT_NO_XTS
#undef USICRYPT_NO_ESSIV
#undef USICRYPT_NO_GCM
#undef USICRYPT_NO_CCM
#undef USICRYPT_NO_POLY
#elif !defined(USICRYPT_GCRY) && !defined(USICRYPT_MBED) && \
	!defined(USICRYPT_NTTL) && !defined(USICRYPT_WOLF) && \
	!defined(USICRYPT_XSSL) && !defined(USICRYPT_UTIL)
#error You need to select the target library in the Makefile
#endif

/* the maximum sizes can be increased though wolfSSL is limited to 4096 bits */

#define USICRYPT_RSA_BITS_MIN	1024
#define USICRYPT_RSA_BITS_MAX	4096
#define USICRYPT_RSA_BYTES_MIN	(USICRYPT_RSA_BITS_MIN>>3)
#define USICRYPT_RSA_BYTES_MAX	(USICRYPT_RSA_BITS_MAX>>3)
#define USICRYPT_RSA_EXPONENT	0x10001

#define USICRYPT_DH_BITS_MIN	1024
#define USICRYPT_DH_BITS_MAX	4096
#define USICRYPT_DH_BYTES_MIN	(USICRYPT_DH_BITS_MIN>>3)
#define USICRYPT_DH_BYTES_MAX	(USICRYPT_DH_BITS_MAX>>3)

#define USICRYPT_TOT_EC_CURVES	6

struct usicrypt_global
{
	int (*rng_seed)(void *data,int len);
	void (*memclear)(void *data,int len);
#if !defined(USICRYPT_NO_THREADS) && defined(USICRYPT_XSSL)
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
#if defined(_WIN64) || defined(_WIN32)
	HANDLE lock[0];
#else
	pthread_mutex_t lock[0];
#endif
#endif
#endif
};

struct usicrypt_thread
{
	struct usicrypt_global *global;
#if defined(USICRYPT_XSSL) || defined(USICRYPT_GCRY) || defined(USICRYPT_NTTL)
	int total;
#endif
#if defined(USICRYPT_MBED)
	mbedtls_hmac_drbg_context rng;
#endif
#if defined(USICRYPT_WOLF)
	RNG rng;
#endif
#if defined(USICRYPT_NTTL)
	struct yarrow_source src[2];
	struct yarrow256_ctx rng;
#endif
};

struct usicrypt_cipher
{
	int (*encrypt)(void *,void *,int,void *);
	int (*decrypt)(void *,void *,int,void *);
	void (*reset)(void *,void *);
	void (*exit)(void *);
};

struct usicrypt_dskcipher
{
	int (*encrypt)(void *,void *,void *,int,void *);
	int (*decrypt)(void *,void *,void *,int,void *);
	void (*exit)(void *);
};

struct usicrypt_iov;

struct usicrypt_aeadcipher
{
	int (*encrypt)(void *,void *,void *,int,void *,int,void *,void *);
	int (*decrypt)(void *,void *,void *,int,void *,int,void *,void *);
#ifndef USICRYPT_NO_IOV
	int (*encrypt_iov)(void *,void *,void *,int,struct usicrypt_iov *,
		int,void *,void *);
	int (*decrypt_iov)(void *,void *,void *,int,struct usicrypt_iov *,
		int,void *,void *);
#endif
	void *(*init)(void *,void *,int,int,int);
	void (*exit)(void *);
};
