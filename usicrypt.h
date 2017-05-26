/*
 * usicrypt, a unified simple interface crypto library wrapper
 *
 * (c) 2017 Andreas Steinmetz
 *
 * Any OSI approved license of your choice applies, see the file LICENSE
 * for details.
 *
 * ---------------------------------------------------------------------
 *
 * Don't be irritated by USICRYPT(blah), this is only required for
 * testing purposes.
 * USICRYPT(blah) actually means: usicrypt_blah
 *
 * And please use SHA1 only if required for backward compatability - it's
 * dead, Jim
 */

#ifndef _USICRYPT_INCLUDED
#ifndef USICRYPT_TEST
#define _USICRYPT_INCLUDED
#ifdef USICRYPT
#undef USICRYPT
#endif
#define USICRYPT(a) usicrypt_##a
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/* digest selection */

#define USICRYPT_SHA1			0x0000
#define USICRYPT_SHA256			0x0001
#define USICRYPT_SHA384			0x0002
#define USICRYPT_SHA512			0x0003

/* standard cipher selection */

#define USICRYPT_AES			0x0000
#define USICRYPT_CAMELLIA		0x0100

/* stream cipher selection */

#define USICRYPT_CHACHA20		0x1000

/* aead cipher selection */

#define USICRYPT_AES_GCM		0x2000
#define USICRYPT_AES_CCM		0x2100
#define USICRYPT_CHACHA20_POLY1305	0x2200

/* mode selection (standard block cipher modes) */

#define USICRYPT_STREAM			0x0000
#define USICRYPT_ECB			0x0001
#define USICRYPT_CBC			0x0002
#define USICRYPT_CTS			0x0003
#define USICRYPT_CFB			0x0004
#define USICRYPT_CFB8			0x0005
#define USICRYPT_OFB			0x0006
#define USICRYPT_CTR			0x0007

/* mode selection (block cipher disk storage modes) */

#define USICRYPT_XTS			0x0010
#define USICRYPT_ESSIV			0x0020

/* predefined dh parameters */

#define USICRYPT_RFC5114_1024_160	0x0000
#define USICRYPT_RFC5114_2048_224	0x0001
#define USICRYPT_RFC5114_2048_256	0x0002

/* elliptic curve identifiers */

#define USICRYPT_BRAINPOOLP512R1	0x0000
#define USICRYPT_BRAINPOOLP384R1	0x0001
#define USICRYPT_BRAINPOOLP256R1	0x0002
#define USICRYPT_SECP521R1		0x0003
#define USICRYPT_SECP384R1		0x0004
#define USICRYPT_SECP256R1		0x0005

/* other identifiers */

#define USICRYPT_RSA			0x0100
#define USICRYPT_DH			0x0101
#define USICRYPT_X25519			0x0200
#define USICRYPT_PBES2			0x0fff

/* io vector array */

#ifndef USICRYPT_IOV_DEFINED
#define USICRYPT_IOV_DEFINED

struct usicrypt_iov
{
	void *data;
	int length;
};

#endif
 
/*
 * clear memory
 *
 * ctx		a thread context
 * data		the data to be cleared
 * len		the length of the data on bytes
 *
 * Note: this function is guaranteed not to be optimized away by the
 * compiler.
 */

extern void usicrypt_memclear(void *ctx,void *data,int len);

/*
 * base64 encode binary data as a zero terminated string
 *
 * ctx		a thread context
 * in		the data to be encoded
 * ilen		the data length in bytes
 * olen		the base64 encoded string length excluding the terminator
 *
 * returns a pointer to allocated memory of NULL in case of an error
 */

extern void *USICRYPT(base64_encode)(void *ctx,void *in,int ilen,int *olen);

/*
 * base64 decode a string to binary data
 *
 * ctx		a thread context
 * in		the base64 string to be decoded
 * ilen		the string length in bytes
 * olen		the base64 decoded data length
 *
 * returns a pointer to allocated memory of NULL in case of an error
 *
 * Note: only a pure base64 string is allowed, i.e. no padding or
 * line wraps/newlines.
 */

extern void *USICRYPT(base64_decode)(void *ctx,void *in,int ilen,int *olen);

/*
 * get random data
 *
 * ctx		a thread context
 * data		the random data storage location
 * len		the amount of random data in bytes
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(random)(void *ctx,void *data,int len);

/*
 * get the next linear feedback shift register value
 *
 * ctx		an allocated LFSR context
 * out		storage area for LFSR value (length specified during init)
 */

extern void usicrypt_lfsr_next(void *ctx,void *out);

/*
 * initialize a linear feedback shift register
 *
 * ctx		a thread context
 * bits		LFSR length in bits, 8 to 128 in multiples of 8
 * preset	initial value, must not be all zeroes, can be NULL for random
 *
 * returns an allocated LFSR context or NULL in case of an error
 *
 * Note: the primitive polynomials used guarantee a deterministic sequence
 * of (2^n)-1 different values for a LFSR length of n bits.
 */

extern void *usicrypt_lfsr_init(void *ctx,int bits,void *preset);

/*
 * release a linear feedback shift register
 *
 * ctx		an allocated LFSR context
 */

extern void usicrypt_lfsr_exit(void *ctx);

/*
 * digest size in bytes
 *
 * ctx		a thread context
 * md		the selected digest
 *
 * returns the storage space in bytes required for the selected digest
 * or -1 in case of an error
 */

extern int USICRYPT(digest_size)(void *ctx,int md);

/*
 * execute digest
 *
 * ctx		a thread context
 * md		the selected digest
 * data		the data to be processed
 * dlen		the lengh of the data in bytes
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(digest)(void *ctx,int md,void *in,int len,void *out);

/*
 * execute digest
 *
 * ctx		a thread context
 * md		the selected digest
 * iov		pointer to an iov array defining the data to be processed
 * niov		total elements of the iov array
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(digest_iov)(void *ctx,int md,struct usicrypt_iov *iov,
	int niov,void *out);

/*
 * execute HMAC
 *
 * ctx		a thread context
 * md		the selected digest
 * data		the data to be processed
 * dlen		the lengh of the data in bytes
 * key		the key data
 * klen		the key data length in bytes
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(hmac)(void *ctx,int md,void *data,int dlen,void *key,
	int klen,void *out);

/*
 * execute HMAC
 *
 * ctx		a thread context
 * md		the selected digest
 * iov		pointer to an iov array defining the data to be processed
 * niov		total elements of the iov array
 * key		the key data
 * klen		the key data length in bytes
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(hmac_iov)(void *ctx,int md,struct usicrypt_iov *iov,
	int niov,void *key,int klen,void *out);

/*
 * execute CMAC
 *
 * ctx		a thread context
 * cipher	the selected cipher, either AES or Camellia
 * key		the key data
 * klen		the key data length in bits (128/192/256)
 * src		the data to be authenticated
 * slen		the data length in bytes
 * dst		the resulting message authentication code, cipher block size
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(cmac)(void *ctx,int cipher,void *key,int klen,void *src,
	int slen,void *dst);

/*
 * execute CMAC
 *
 * ctx		a thread context
 * cipher	the selected cipher, either AES or Camellia
 * key		the key data
 * klen		the key data length in bits (128/192/256)
 * iov		pointer to an iov array defining the data to be authenticated
 * niov		total elements of the iov array
 * dst		the resulting message authentication code, cipher block size
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(cmac_iov)(void *ctx,int cipher,void *key,int klen,
	struct usicrypt_iov *iov,int niov,void *dst);

/*
 * execute PBKDF2
 *
 * ctx		a thread context
 * md		the selected digest
 * key		the key data
 * klen		the key data length in bytes
 * salt		the salt data
 * slen		the salt data length in bytes
 * iter		the amount of iterations
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 *
 * Note: the key data will always be cleared.
 */

extern int USICRYPT(pbkdf2)(void *ctx,int md,void *key,int klen,void *salt,
	int slen,int iter,void *out);

/*
 * execute HKDF
 *
 * ctx		a thread context
 * md		the selected digest
 * key		the key data
 * klen		the key data length in bytes
 * salt		the salt data, can be NULL
 * slen		the salt data length in bytes
 * info		the info data, can be NULL
 * ilen		the info data length in bytes
 * out		pointer to result storage location, size of selected digest
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(hkdf)(void *ctx,int md,void *key,int klen,void *salt,
	int slen,void *info,int ilen,void *out);

/*
 * generate a RSA public private keypair
 *
 * ctx		a thread context
 * bits		the key size in bits (>=1024 and a multiple of 8)
 *
 * returns an allocated key or NULL in case of an error
 */

extern void *USICRYPT(rsa_generate)(void *ctx,int bits);

/*
 * size of the public key
 *
 * ctx		a thread context
 * key		an allocated key
 *
 * returns the public key size in bits
 */

extern int USICRYPT(rsa_size)(void *ctx,void *key);

/*
 * export a RSA public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * k		an allocated key
 * len		the exported data length in bytes
 *
 * returns the allocated exported data or NULL in case of an error
 */

extern void *USICRYPT(rsa_get_pub)(void *ctx,void *k,int *len);

/*
 * import a RSA public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * key		the key data
 * len		the key data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 */

extern void *USICRYPT(rsa_set_pub)(void *ctx,void *key,int len);

/*
 * export a RSA public/private keypair in PKCS#1 DER format
 *
 * ctx		a thread context
 * k		an allocated key
 * len		the exported data length in bytes
 *
 * returns the allocated exported data or NULL in case of an error
 */

extern void *USICRYPT(rsa_get_key)(void *ctx,void *k,int *len);

/*
 * import a RSA public/private keypair in PKCS#1 DER format
 *
 * ctx		a thread context
 * key		the key data
 * len		the key data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(rsa_set_key)(void *ctx,void *key,int len);

/*
 * sign data with a private RSA key using RSA PKCS#1 v1.5
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be signed
 * dlen		the data length in bytes
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(rsa_sign_v15)(void *ctx,int md,void *key,void *data,
	int dlen,int *slen);

/*
 * sign data with a private RSA key using RSA PKCS#1 v1.5
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be signed
 * niov		total elements of the iov array
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(rsa_sign_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen);

/*
 * verify signature with a public RSA key using RSA PKCS#1 v1.5
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be verified
 * dlen		the data length in bytes
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of succes and -1 in case of an error
 */

extern int USICRYPT(rsa_verify_v15)(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen);

/*
 * verify signature with a public RSA key using RSA PKCS#1 v1.5
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be verified
 * niov		total elements of the iov array
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of succes and -1 in case of an error
 */

extern int USICRYPT(rsa_verify_v15_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen);

/*
 * sign data with a private RSA key using RSASSA-PSS
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be signed
 * dlen		the data length in bytes
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(rsa_sign_pss)(void *ctx,int md,void *key,void *data,
	int dlen,int *slen);

/*
 * sign data with a private RSA key using RSASSA-PSS
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be signed
 * niov		total elements of the iov array
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(rsa_sign_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen);

/*
 * verify signature with a public RSA key using RSASSA-PSS
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be verified
 * dlen		the data length in bytes
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of succes and -1 in case of an error
 */

extern int USICRYPT(rsa_verify_pss)(void *ctx,int md,void *key,void *data,
	int dlen,void *sig,int slen);

/*
 * verify signature with a public RSA key using RSASSA-PSS
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be verified
 * niov		total elements of the iov array
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of succes and -1 in case of an error
 */

extern int USICRYPT(rsa_verify_pss_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen);

/*
 * encrypt with a public RSA key using PKCS#1 v1.5 padding
 *
 * ctx		a thread context
 * key		an allocated key
 * data		the data to be encrypted
 * dlen		the data length in bytes
 * olen		the encrypted data length in bytes
 *
 * returns the allocated encrypted data or NULL in case of an error
 */

extern void *USICRYPT(rsa_encrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen);

/*
 * decrypt with a private RSA key using PKCS#1 v1.5 padding
 *
 * ctx		a thread context
 * key		an allocated key
 * data		the data to be decrypted
 * dlen		the data length in bytes
 * olen		the decrypted data length in bytes
 *
 * returns the allocated decrypted data or NULL in case of an error
 */

extern void *USICRYPT(rsa_decrypt_v15)(void *ctx,void *key,void *data,int dlen,
	int *olen);

/*
 * encrypt with a public RSA key using RSAES-OAEP
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be encrypted
 * dlen		the data length in bytes
 * olen		the encrypted data length in bytes
 *
 * returns the allocated encrypted data or NULL in case of an error
 */

extern void *USICRYPT(rsa_encrypt_oaep)(void *ctx,int md,void *key,void *data,
	int dlen,int *olen);

/*
 * decrypt with a private RSA key using RSAES-OAEP
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be decrypted
 * dlen		the data length in bytes
 * olen		the decrypted data length in bytes
 *
 * returns the allocated decrypted data or NULL in case of an error
 */

extern void *USICRYPT(rsa_decrypt_oaep)(void *ctx,int md,void *key,void *data,
	int dlen,int *olen);

/*
 * release an allocated RSA key
 *
 * ctx		a thread context
 * key		an allocated key
 */

extern void USICRYPT(rsa_free)(void *ctx,void *key);

/*
 * get predefined DH parameters in PKCS#3 DER format
 *
 * ctx		a thread context
 * which	a predefined parameter identifier
 * len		the length of the returned data in bytes
 *
 * returns the statically allocated DH data or NULL in case of an error
 *
 * Note: the following predefined parameters are available:
 *
 * rfc5114-1024-160
 * rfc5114-2048-224
 * rfc5114-2048-256
 */

extern void *usicrypt_dh_params(void *ctx,int which,int *len);

/*
 * generate DH parameters in PKCS#3 DER format
 *
 * ctx		a thread context
 * bits		the prime length in bits (>=1024 and a multiple of 8)
 * generator	the generator value, must be 2 or 5
 * len		the length of the returned data in bytes
 *
 * returns the allocated DH data or NULL in case of an error
 */

extern void *USICRYPT(dh_generate)(void *ctx,int bits,int generator,int *len);

/*
 * initialize a DH context from PKCS#3 DER formatted DH parameters
 *
 * ctx		a thread context
 * params	the DH parameters
 * len		the DH parameters length in bytes
 *
 * returns an allocated DH context or NULL in case of an error
 */

extern void *USICRYPT(dh_init)(void *ctx,void *params,int len);

/*
 * generate a DH keypair and export the public value
 *
 * ctx		a thread context
 * dh		an allocated DH context
 * len		the length of the public value in bytes
 *
 * returns the allocated public value or NULL in case of an error
 */

extern void *USICRYPT(dh_genex)(void *ctx,void *dh,int *len);

/*
 * export a DH public value and DH parameters in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * pub		a public value
 * publen	the length of the public value in bytes
 * params	the DH parameters in PKCS#3 DER format
 * plen		the DH parameters length in bytes
 * len		receives the exported data length in bytes
 *
 * returns the allocated exported data or NULL in case of an error
 */

extern void *usicrypt_dh_get_pub(void *ctx,void *pub,int publen,void *params,
	int plen,int *len);

/*
 * import a DH public value and DH parameters in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * data		the SubjectPublicKeyInfo formatted public value and parameters
 * dlen		the length of the SubjectPublicKeyInfo formatted data in bytes
 * params	receives the allocated DH parameters in PKCS#3 DER format
 * plen		receives the length of the DH parameters in bytes
 * len		receives the length of the public value in bytes
 *
 * returns the allocated public value or NULL in case of an error
 */

extern void *usicrypt_dh_set_pub(void *ctx,void *data,int dlen,void **params,
	int *plen,int *len);

/*
 * compare two DH parameters in PKCS#3 DER format
 *
 * ctx		a thread context
 * p1		the first set of DH parameters
 * p1len	the length of the first set of DH parameters in bytes
 * p2		the second set of DH parameters
 * p2len	the length of the second set of DH parameters in bytes
 *
 * returns 0 if the parameters are equal and -1 if not or an error occured
 */

extern int usicrypt_dh_cmp_params(void *ctx,void *p1,int p1len,void *p2,
	int p2len);

/*
 * convert DH parameters from PKCS#3 DER format to PKCS#3 PEM format
 *
 * ctx		a thread context
 * data		the PKCS#3 DER encoded DH parameters
 * dlen		the length of the PKCS#3 DER encoded DH parameters in bytes
 * rlen		the length of the PKCS#3 PEM encoded DH parameters in bytes
 *		excluding the terminating zero byte
 *
 * returns the allocated and zero terminated PKCS#3 PEM encoded DH parameters
 * or NULL in case of an error
 */

extern void *USICRYPT(dh_to_pem)(void *ctx,void *data,int dlen,int *rlen);

/*
 * convert DH parameters from PKCS#3 PEM format to PKCS#3 DER format
 *
 * ctx		a thread context
 * data		the PKCS#3 PEM encoded DH parameters
 * dlen		the length of the PKCS#3 PEM encoded DH parameters in bytes
 * rlen		the length of the PKCS#3 DER encoded DH parameters in bytes
 *
 * returns the allocated PKCS#3 DER encoded DH parameters or NULL in case of
 * an error
 */

extern void *USICRYPT(pem_to_dh)(void *ctx,void *data,int dlen,int *rlen);

/*
 * derives a DH shared secret
 *
 * ctx		a thread context
 * dh		an allocated DH context
 * pub		the peer's public value
 * plen		the peer's public value length in bytes
 * slen		the shared secret length in bytes
 *
 * returns the allocated shared secret or NULL in case of an error
 */

extern void *USICRYPT(dh_derive)(void *ctx,void *dh,void *pub,int plen,
	int *slen);

/*
 * release an allocated DH context
 *
 * ctx		a thread context
 * dh		an allocated dh context
 */

extern void USICRYPT(dh_free)(void *ctx,void *dh);

/*
 * generate an EC keypair
 *
 * ctx		a thread context
 * curve	a curve identifier
 *
 * returns the allocated key or NULL in case of an error
 *
 * Note: the following curves are supported:
 *
 * brainpoolP512r1
 * brainpoolP384r1
 * brainpoolP256r1
 * secp521r1
 * secp384r1
 * secp256r1
 *
 * Note: the curves starting with "secp" contain NSA defined parameters
 * of undisclosed origin and should thus be considered weak. If in doubt
 * and when possible these curves should not be used.
 */

extern void *USICRYPT(ec_generate)(void *ctx,int curve);

/*
 * get the curve identifier
 *
 * ctx		a thread context
 * key		an allocated key
 *
 * returns the curve identifier or -1 in case of an error
 */

extern int USICRYPT(ec_identifier)(void *ctx,void *key);

/*
 * derive an EC shared secret
 *
 * ctx		a thread context
 * key		the allocated local key pair
 * pub		the allocated public key of the peer
 * klen		the length of the shared secret in bytes
 *
 * returns the allocated shared secret or NULL in case of an error
 */

extern void *USICRYPT(ec_derive)(void *ctx,void *key,void *pub,int *klen);

/*
 * export an EC public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * k		an allocated key
 * len		the exported data length in bytes
 *
 * returns the allocated exported data or NULL in case of an error
 */

extern void *USICRYPT(ec_get_pub)(void *ctx,void *k,int *len);

/*
 * import an EC public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * key		the key data
 * len		the key data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 */

extern void *USICRYPT(ec_set_pub)(void *ctx,void *key,int len);

/*
 * export an EC key pair in PKCS#1 DER format
 *
 * ctx		a thread context
 * k		an allocated key pair
 * len		the exported data length in bytes
 *
 * returns the allocated exported data or NULL in case of an error
 */

extern void *USICRYPT(ec_get_key)(void *ctx,void *k,int *len);

/*
 * import an EC key pair in PKCS#1 DER format
 *
 * ctx		a thread context
 * key		the key pair data
 * len		the key pair data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(ec_set_key)(void *ctx,void *key,int len);

/*
 * sign data with a private EC key using ECDSA
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be signed
 * dlen		the data length in bytes
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(ec_sign)(void *ctx,int md,void *key,void *data,int dlen,
	int *slen);

/*
 * sign data with a private EC key using ECDSA
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be signed
 * niov		total elements of the iov array
 * slen		the signature length in bytes
 *
 * returns the allocated signature or NULL in case of an error
 */

extern void *USICRYPT(ec_sign_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,int *slen);

/*
 * verify signature with a public EC key using ECDSA
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * data		the data to be verified
 * dlen		the data length in bytes
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(ec_verify)(void *ctx,int md,void *key,void *data,int dlen,
	void *sig,int slen);

/*
 * verify signature with a public EC key using ECDSA
 *
 * ctx		a thread context
 * md		the selected digest
 * key		an allocated key
 * iov		pointer to an iov array defining the data to be verified
 * niov		total elements of the iov array
 * sig		the signature
 * slen		the signature length in bytes
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(ec_verify_iov)(void *ctx,int md,void *key,
	struct usicrypt_iov *iov,int niov,void *sig,int slen);

/*
 * release an allocated EC key
 *
 * ctx		a thread context
 * key		an allocated key
 */

extern void USICRYPT(ec_free)(void *ctx,void *key);

/*
 * generate an X25519 keypair
 *
 * ctx		a thread context
 *
 * returns the allocated key or NULL in case of an error
 */

extern void *USICRYPT(x25519_generate)(void *ctx);

/*
 * derive an X25519 shared secret
 *
 * ctx		a thread context
 * key		the allocated local key pair
 * pub		the allocated public key of the peer
 * klen		the length of the shared secret in bytes
 *
 * returns the allocated shared secret or NULL in case of an error
 */

extern void *USICRYPT(x25519_derive)(void *ctx,void *key,void *pub,int *klen);

/*
 * export an X25519 public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * key		an allocated key
 * len		the exported data length in bytes
 *
 * returns the allocated data or NULL in case of an error
 */

extern void *USICRYPT(x25519_get_pub)(void *ctx,void *key,int *len);

/*
 * import an X25519 public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * key		the key data
 * len		the key data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 */

extern void *USICRYPT(x25519_set_pub)(void *ctx,void *key,int len);

/*
 * export an X25519 private key in PKCS#8 DER format
 *
 * ctx		a thread context
 * key		an allocated key
 * len		the exported data length in bytes
 *
 * returns the allocated data or NULL in case of an error
 */

extern void *USICRYPT(x25519_get_key)(void *ctx,void *key,int *len);

/*
 * import an X25519 private key in PKCS#8 DER format
 *
 * ctx		a thread context
 * key		the key data
 * len		the key data length in bytes
 *
 * returns an allocated key or NULL in case of an error
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(x25519_set_key)(void *ctx,void *key,int len);

/*
 * release an allocated X25519 key
 *
 * ctx		a thread context
 * key		an allocated key
 */

extern void USICRYPT(x25519_free)(void *ctx,void *key);

/*
 * determine the type of a public key in SubjectPublicKeyInfo DER format
 *
 * ctx		a thread context
 * data		the public key data to be processed
 * dlen		the length of the public key data in bytes
 *
 * returns the public key identifier or -1 in case of an error
 */

extern int usicrypt_pub_type_from_p8(void *ctx,void *data,int dlen);

/*
 * determine the type of a private key in PKCS#8 DER format
 *
 * ctx		a thread context
 * data		the private key data to be processed
 * dlen		the length of the private key data in bytes
 *
 * returns the private key identifier or -1 in case of an error
 */

extern int usicrypt_key_type_from_p8(void *ctx,void *data,int dlen);

/*
 * convert a PKCS#1 encoded RSA key to PKCS#8
 *
 * ctx		a thread context
 * data		the PKCS#1 encoded RSA key
 * dlen		the length of the PKCS#1 encoded RSA key in bytes
 * p8len	the length of the PKCS#8 encoded RSA key in bytes
 *
 * returns the allocated PKCS#8 encoded RSA key or NULL in case of an error
 */

extern void *usicrypt_rsa_key_to_p8(void *ctx,void *data,int dlen,int *p8len);

/*
 * convert a PKCS#8 encoded RSA key to PKCS#1
 *
 * ctx		a thread context
 * data		the PKCS#8 encoded RSA key
 * dlen		the length of the PKCS#8 encoded RSA key in bytes
 * klen		the length of the PKCS#1 encoded RSA key in bytes
 *
 * returns the allocated PKCS#1 encoded RSA key or NULL in case of an error
 */

extern void *usicrypt_p8_to_rsa_key(void *ctx,void *data,int dlen,int *klen);

/*
 * convert a PKCS#1 encoded EC key to PKCS#8
 *
 * ctx		a thread context
 * data		the PKCS#1 encoded EC key
 * dlen		the length of the PKCS#1 encoded EC key in bytes
 * p8len	the length of the PKCS#8 encoded EC key in bytes
 *
 * returns the allocated PKCS#8 encoded EC key or NULL in case of an error
 */

extern void *usicrypt_ec_key_to_p8(void *ctx,void *data,int dlen,int *p8len);

/*
 * convert a PKCS#8 encoded EC key to PKCS#1
 *
 * ctx		a thread context
 * data		the PKCS#8 encoded EC key
 * dlen		the length of the PKCS#8 encoded EC key in bytes
 * klen		the length of the PKCS#1 encoded EC key in bytes
 *
 * returns the allocated PKCS#1 encoded EC key or NULL in case of an error
 */

extern void *usicrypt_p8_to_ec_key(void *ctx,void *data,int dlen,int *klen);

/*
 * encrypt a PKCS#8 encoded key using PBES2 and PBKDF2
 *
 * ctx		a thread context
 * key		the encryption key
 * klen		the encryption key length in bytes
 * data		the data to be encrypted
 * dlen		the length of the data to be encrypted in bytes
 * cipher	the cipher to be used, AES or Camellia
 * mode		the cipher mode, ECB, CBC ,CFB or OFB
 * bits		the cipher bits, 128, 192 or 256
 * digest	the PBKDF2 digest, SHA1, SHA256, SHA384 or SHA512
 * iter		the amount of PBKDF2 iterations (>=1, >=10000 recommended)
 * rlen		the length of the returned encrypted key in bytes
 *
 * returns the allocated encrypted key or NULL in case of an error
 *
 * Note: key encryption is only available using PBES2 encoding and PBKDF2
 * with SHA1/SHA256/SHA384/SHA512 and using AES or Camellia with 128/192/256
 * bits key and ECB/CBC/CFB/OFB mode and for PKCS#8 encoded keys.
 * 
 * Note: SHA1 is only available for 128 bit cipher keys.
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(encrypt_p8)(void *ctx,void *key,int klen,void *data,
	int dlen,int cipher,int mode,int bits,int digest,int iter,int *rlen);

/*
 * decrypt a PKCS#8 encoded key using PBES2 and PBKDF2
 *
 * ctx		a thread context
 * key		the decryption key
 * klen		the decryption key length in bytes
 * data		the encrypted data
 * dlen		the length of the encrypted data in bytes
 * rlen		the length of the returned decrypted key in bytes
 *
 * returns the allocated decrypted key or NULL in case of an error
 *
 * Note: only a PBES2 encoded encrypted key using PBKDF2 with
 * SHA1/SHA256/SHA384/SHA512 and using AES or Camellia with 128/192/256
 * bits key and ECB/CBC/CFB/OFB mode can be decrypted.
 *
 * Note: SHA1 is only available for 128 bit cipher keys.
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(decrypt_p8)(void *ctx,void *key,int klen,void *data,
	int dlen,int *rlen);

/*
 * convert PKCS#8 DER encoded data to PEM format
 *
 * ctx		a thread context
 * data		the PKCS#8 DER encoded data
 * dlen		the length of the PKCS#8 DER encoded data in bytes
 * rlen		the length of the PKCS#8 PEM encoded data in bytes excluding
 *		the terminating zero byte
 *
 * returns the allocated and zero terminated PKCS#8 PEM encoded data or NULL
 * in case of an error
 */

extern void *USICRYPT(p8_to_pem)(void *ctx,void *data,int dlen,int *rlen);

/*
 * convert PKCS#8 PEM encoded data to DER format
 *
 * ctx		a thread context
 * data		the PKCS#8 PEM encoded data
 * dlen		the length of the PKCS#8 PEM encoded data in bytes
 * rlen		the length of the PKCS#8 DER encoded data in bytes
 *
 * returns the allocated PKCS#8 DER encoded data or NULL in case of an error
 */

extern void *USICRYPT(pem_to_p8)(void *ctx,void *data,int dlen,int *rlen);

/*
 * get block size of cipher
 *
 * ctx		a thread context
 * cipher	a cipher identifier
 *
 * returns the cipher block size in bytes or -1 in case of an error
 */

extern int USICRYPT(cipher_block_size)(void *ctx,int cipher);

/*
 * perform PKCS#7 padding
 *
 * ctx		a thread context
 * data		the data to be padded or NULL
 * len		the length of the data to be padded in bytes
 *
 * returns the amount of padding bytes or -1 in case of an error
 *
 * Note: the specified data must have sufficient room for the
 * padding to be added.
 *
 * Note: the amount of bytes required for padding can be retrieved
 * by calling this function with NULL for data.
 *
 * Note: this routine supports 128 bit ciphers only.
 */

extern int usicrypt_cipher_padding_add(void *ctx,void *data,int len);

/*
 * check the PKCS#7 padding and return the padding length
 *
 * ctx		a thread context
 * data		the padded data
 * len		the length of the padded data in bytes
 *
 * returns the amount of padding in bytes or -1 in case of an error
 *
 * Note: this routine supports 128 bit ciphers only.
 */

extern int usicrypt_cipher_padding_get(void *ctx,void *data,int len);

/*
 * encrypt data using a standard block cipher mode
 *
 * ctx		an allocated standard block cipher context
 * src		the data to be encrypted
 * slen		the data length in bytes
 * dst		storage area for the encrypted data
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(blkcipher_encrypt)(void *ctx,void *src,int slen,void *dst);

/*
 * decrypt data using a standard block cipher mode
 *
 * ctx		an allocated standard block cipher context
 * src		the data to be decrypted
 * slen		the data length in bytes
 * dst		storage area for the decrypted data
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(blkcipher_decrypt)(void *ctx,void *src,int slen,void *dst);

/*
 * allocate a standard block cipher context
 *
 * ctx		a thread context
 * cipher	the selected cipher, either AES, Camellia or ChaCha20
 * mode		the cipher mode, Stream, ECB, CBC, CTS, CFB, CFB8, OFB or CTR
 * key		the key data
 * klen		the key data length in bits (128/192/256)
 * iv		the initial IV (ignored for ECB mode)
 *
 * returns the allocated standard block cipher context or NULL in case of an
 * error
 *
 * Note: the key data will always be cleared.
 *
 * AES/Camellia Notes:
 *
 * The IV length is 16 bytes. The Stream cipher mode is invalid.
 *
 * ChaCha20 Notes:
 *
 * The key length must be 256 bits and the IV length is 8 bytes. The cipher
 * mode must be Stream.
 *
 * Due to the vastly varying library implementations of ChaCha20 the following
 * limitations are necessary for proper interworking:
 *
 * The nonce when setting the IV will always be:
 * CCCCZZZZIIIIIIII
 * C=counter bytes, initialized to zero
 * Z=all zero bytes
 * I=IV bytes
 * Always assume that the counter is 32 bits only
 */

extern void *USICRYPT(blkcipher_init)(void *ctx,int cipher,int mode,void *key,
	int klen,void *iv);

/*
 * reset cipher state and set a new initial IV
 *
 * ctx		an allocated standard block cipher context
 * iv		the new initial IV
 *
 * Note: this is a NoOp for ECB mode.
 */

extern void USICRYPT(blkcipher_reset)(void *ctx,void *iv);

/*
 * release a standard block cipher context
 *
 * ctx		an allocated standard block cipher context
 */

extern void USICRYPT(blkcipher_exit)(void *ctx);

/*
 * encrypt data using a disk storage block cipher mode
 *
 * ctx		an allocated disk storage block cipher context
 * iv		the iv/sector number
 * src		the data to be encrypted
 * slen		the data length in bytes
 * dst		storage area for the encrypted data
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(dskcipher_encrypt)(void *ctx,void *iv,void *src,int slen,
	void *dst);

/*
 * decrypt data using a disk storage block cipher mode
 *
 * ctx		an allocated disk storage block cipher context
 * iv		the iv/sector number
 * src		the data to be decrypted
 * slen		the data length in bytes
 * dst		storage area for the decrypted data
 *
 * returns 0 in case of success and -1 in case of an error
 */

extern int USICRYPT(dskcipher_decrypt)(void *ctx,void *iv,void *src,int slen,
	void *dst);

/*
 * allocate a disk storage block cipher context
 *
 * ctx		a thread context
 * cipher	the selected cipher, either AES or Camellia
 * mode		the cipher mode, XTS or ESSIV
 * key		the key data
 * klen		the key data length in bits (XTS: 256/512, ESSIV: 128/192/256)
 *
 * returns the allocated disk storage block cipher context or NULL in case of an
 * error
 *
 * Note: the key data will always be cleared.
 */

extern void *USICRYPT(dskcipher_init)(void *ctx,int cipher,int mode,void *key,
	int klen);

/*
 * release a disk storage block cipher context
 *
 * ctx		an allocated disk storage block cipher context
 */

extern void USICRYPT(dskcipher_exit)(void *ctx);

/*
 * encrypt data using a block cipher in AEAD mode
 *
 * ctx		an allocated AEAD block cipher context
 * iv		the nonce/iv (length specified at init time)
 * src		the data to be encrypted
 * slen		the data length in bytes
 * aad		the additional authenticated data, can be NULL
 * alen		the length of the additional authenticated data in bytes
 * dst		storage area for the encrypted data
 * tag		storage area for the tag (length specified at init time)
 *
 * returns 0 in case of success and -1 in case of an error
 *
 * Note: the nonce/iv must not repeat for any given key.
 */

extern int USICRYPT(aeadcipher_encrypt)(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag);

/*
 * encrypt data using a block cipher in AEAD mode
 *
 * ctx		an allocated AEAD block cipher context
 * iv		the nonce/iv (length specified at init time)
 * src		the data to be encrypted
 * slen		the data length in bytes
 * iov		pointer to an aad iov array defining the data to be processed
 * niov		total elements of the additional authenticated data iov array
 * dst		storage area for the encrypted data
 * tag		storage area for the tag (length specified at init time)
 *
 * returns 0 in case of success and -1 in case of an error
 *
 * Note: the nonce/iv must not repeat for any given key.
 */

extern int USICRYPT(aeadcipher_encrypt_iov)(void *ctx,void *iv,void *src,
	int slen,struct usicrypt_iov *,int niov,void *dst,void *tag);

/*
 * decrypt data using a block cipher in AEAD mode
 *
 * ctx		an allocated AEAD block cipher context context
 * iv		the nonce/iv (length specified at init time)
 * src		the data to be decrypted
 * slen		the data length in bytes
 * aad		the additional authenticated data, can be NULL
 * alen		the length of the additional authenticated data in bytes
 * dst		storage area for the decrypted data
 * tag		the authentication tag (length specified at init time)
 *
 * returns 0 in case of success and -1 in case of an error
 *
 * Note: the nonce/iv must not repeat for any given key.
 */

extern int USICRYPT(aeadcipher_decrypt)(void *ctx,void *iv,void *src,int slen,
	void *aad,int alen,void *dst,void *tag);

/*
 * decrypt data using a block cipher in AEAD mode
 *
 * ctx		an allocated AEAD block cipher context context
 * iv		the nonce/iv (length specified at init time)
 * src		the data to be decrypted
 * slen		the data length in bytes
 * iov		pointer to an aad iov array defining the data to be processed
 * niov		total elements of the additional authenticated data iov array
 * dst		storage area for the decrypted data
 * tag		the authentication tag (length specified at init time)
 *
 * returns 0 in case of success and -1 in case of an error
 *
 * Note: the nonce/iv must not repeat for any given key.
 */

extern int USICRYPT(aeadcipher_decrypt_iov)(void *ctx,void *iv,void *src,
	int slen,struct usicrypt_iov *,int niov,void *dst,void *tag);

/*
 * allocate an AEAD block cipher context
 *
 * ctx		a thread context
 * cipher	the AEAD block cipher (AES/GCM, AES/CCM, ChaCha20/Poly1305)
 * key		the key data
 * klen		the key data length in bits (128/192/256, see notes)
 * ilen		the nonce/iv length in bytes (see notes)
 * tlen		the authentication tag length in bytes (see notes)
 *
 * returns the allocated AEAD block cipher context or NULL in case of an error
 *
 * Note: the key data will always be cleared.
 *
 * Note: the theoretical strength of the used block cipher with
 * regard to precomputation attacks is 2^(n/2) where n is the
 * key length in bits. Thus a minimum key length of 256 bits is
 * recommended.
 *
 * Notes for AES/GCM:
 *
 * Valid nonce/iv lengths in bytes are 1-16.
 * Valid authentication tag lengths in bytes are 4-16.
 * Portable authentication tag lengths in bytes are 4,8,12,13,14,15,16.
 *
 * The nonce/iv length should be set to 12, otherwise no more than 2^32
 * messages may be used with any given key. If the nonce/iv length is 12 and
 * the nonce/iv contains a deterministic part the maximum amount of messages
 * that may be used with any given key is specified by the maximum cycle of
 * the deterministic part.
 *
 * Notes for AES/CCM:
 *
 * Valid nonce/iv lengths in bytes are 7-13 => slen<2^((15-IV)*8)
 * Valid authentication tag lengths in bytes are 4-16 (only even values)
 *
 * Note: due to operational restrictions one should not encrypt and
 * authenticate more than 2^63 bytes with any given key (actually the
 * real value is close to 2^64 but then 2^63 is an easy limit to test for).
 *
 * Notes for ChaCha20/Poly1305:
 *
 * Valid key data length in bits is 256.
 * Valid nonce/iv length in bytes is 12.
 * Valid authentication tag length in bytes is 16.
 */

extern void *USICRYPT(aeadcipher_init)(void *ctx,int cipher,void *key,int klen,
	int ilen,int tlen);

/*
 * release an AEAD block cipher context
 *
 * ctx		an allocated AEAD block cipher context
 */

extern void USICRYPT(aeadcipher_exit)(void *ctx);

/*
 * allocate a thread context
 *
 * global	an allocated global context
 *
 * returns the allocated thread context or NULL in case of an error
 *
 * Note: thread contexts can be used in parallel but they are restricted
 * to the thread they are created in.
 *
 * Note: at least one thread context is required, even if no threads
 * are used.
 */

extern void *USICRYPT(thread_init)(void *global);

/*
 * release a thread context
 *
 * ctx		an allocated thread context
 */

extern void USICRYPT(thread_exit)(void *ctx);

/*
 * allocate a global context
 *
 * rng_seed	a reentrant function that provides the requested
 *		amount of random data from a system random data
 *		source, the function must return 0 in case of success
 *		or -1 in case of error - can be NULL if the internal
 *		implementation shall be used
 * memclear	a reentrant function that clears the specified amount
 *		of memory to a zero value - can be NULL if the
 *		internal implementation shall be used
 *
 * returns the allocated global context or NULL in case of an error
 *
 * Note: a global context must be allocated once in any application.
 */

extern void *USICRYPT(global_init)(int (*rng_seed)(void *data,int len),
	void (*memclear)(void *data,int len));

/*
 * release a global context
 *
 * ctx		an allocated global context
 *
 * Note: all allocated thread contexts must be released before
 * global context release.
 */

extern void USICRYPT(global_exit)(void *ctx);

#ifdef  __cplusplus
}
#endif

#endif
