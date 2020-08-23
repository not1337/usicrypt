/*
 * usicrypt, a unified simple interface crypto library wrapper
 *
 * (c) 2019 Andreas Steinmetz
 *
 * Any OSI approved license of your choice applies, see the file LICENSE
 * for details. For the required code in goldilocks-1.0 see
 * goldilocks-1.0/LICENSE.txt for license information.
 *
 */

/******************************************************************************/
/*                                 Testing                                    */
/******************************************************************************/

#ifndef USICRYPT_TEST

#ifdef USICRYPT_XSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
#define USICRYPT_DCAF_X448
#define USICRYPT_DCAF_ED448
#endif
#endif

#ifdef USICRYPT_MBED
#define USICRYPT_DCAF_X448
#endif

#ifdef USICRYPT_WOLF
#include <wolfssl/version.h>
#if LIBWOLFSSL_VERSION_HEX >= 0x04004000
#define USICRYPT_DCAF_X448
#define USICRYPT_DCAF_ED448
#endif
#endif

#ifdef USICRYPT_NTTL
#include <nettle/version.h>
#if NETTLE_VERSION_MAJOR > 3
#define USICRYPT_DCAF_X448
#elif NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 6
#define USICRYPT_DCAF_X448
#define USICRYPT_DCAF_ED448
#endif
#endif

#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#if !defined(USICRYPT_DCAF_X448) || !defined(USICRYPT_DCAF_ED448)

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) dcaf_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#define USICRYPT_DCAF_SOURCE

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

#endif

#ifndef USICRYPT_DCAF_X448
#define USICRYPT_DCAF_X448

#include "decaf/point_448.h"

#ifndef USICRYPT_NO_X448

struct dcaf_x448
{
	unsigned char pub[56];
	unsigned char key[56];
};

static const unsigned char dcaf_x448_asn1_pub[12]=
{
	0x30,0x42,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x6f,0x03,0x39,0x00
};

static const unsigned char dcaf_x448_asn1_key[16]=
{
	0x30,0x46,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x6f,0x04,0x3a,0x04,0x38
};

#endif

void *USICRYPT(x448_generate)(void *ctx)
{
#ifndef USICRYPT_NO_X448
	struct dcaf_x448 *x;

	if(U(!(x=malloc(sizeof(struct dcaf_x448)))))goto err1;
	if(U(USICRYPT(get_random)(x->key,sizeof(x->key))))goto err2;
	x->key[0]&=0xfc;
	x->key[55]|=0x80;
	decaf_x448_derive_public_key(x->pub,x->key);
	return x;

err2:	free(x);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_derive)(void *ctx,void *key,void *pub,int *klen)
{
#ifndef USICRYPT_NO_X448
	unsigned char *data;

	*klen=56;
	if(U(!(data=malloc(*klen))))goto err1;
	if(U(decaf_x448(data,((struct dcaf_x448 *)pub)->pub,
		((struct dcaf_x448 *)key)->key)!=DECAF_SUCCESS))goto err2;
	return data;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(data,*klen);
	free(data);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X448
	unsigned char *data;

	*len=sizeof(dcaf_x448_asn1_pub)+56;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,dcaf_x448_asn1_pub,sizeof(dcaf_x448_asn1_pub));
	memcpy(data+sizeof(dcaf_x448_asn1_pub),((struct dcaf_x448 *)key)->pub,
		56);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X448
	struct dcaf_x448 *x;

	if(U(len<sizeof(dcaf_x448_asn1_pub)+56)||
		U(memcmp(key,dcaf_x448_asn1_pub,sizeof(dcaf_x448_asn1_pub))))
			return NULL;
	if(U(!(x=malloc(sizeof(struct dcaf_x448)))))return NULL;
	memcpy(x->pub,((unsigned char *)key)+sizeof(dcaf_x448_asn1_pub),56);
	USICRYPT(do_memclear)(x->key,sizeof(x->key));
	return x;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_X448
	unsigned char *data;

	*len=sizeof(dcaf_x448_asn1_key)+56;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,dcaf_x448_asn1_key,sizeof(dcaf_x448_asn1_key));
	memcpy(data+sizeof(dcaf_x448_asn1_key),((struct dcaf_x448 *)key)->key,
		56);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(x448_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_X448
	struct dcaf_x448 *x=NULL;

	if(U(len<sizeof(dcaf_x448_asn1_key)+56)||
		U(memcmp(key,dcaf_x448_asn1_key,sizeof(dcaf_x448_asn1_key))))
			goto err1;
	if(U(!(x=malloc(sizeof(struct dcaf_x448)))))goto err1;
	memcpy(x->key,((unsigned char *)key)+sizeof(dcaf_x448_asn1_key),56);
	x->key[0]&=0xfc;
	x->key[55]|=0x80;
	decaf_x448_derive_public_key(x->pub,x->key);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return x;
#else
	return NULL;
#endif
}

void USICRYPT(x448_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_X448
	((struct usicrypt_thread *)ctx)->global->memclear(key,
		sizeof(struct dcaf_x448));
	free(key);
#endif
}

#endif

#ifndef USICRYPT_DCAF_ED448
#define USICRYPT_DCAF_ED448

#include "decaf/ed448.h"

#ifndef USICRYPT_NO_ED448

struct dcaf_ed448
{
	unsigned char pub[57];
	unsigned char key[57];
};

static const unsigned char dcaf_ed448_asn1_pub[12]=
{
	0x30,0x43,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x71,0x03,0x3a,0x00
};

static const unsigned char dcaf_ed448_asn1_key[16]=
{
	0x30,0x47,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x71,0x04,0x3b,0x04,0x39
};

#endif

void *USICRYPT(ed448_generate)(void *ctx)
{
#ifndef USICRYPT_NO_ED448
	struct dcaf_ed448 *x;

	if(U(!(x=malloc(sizeof(struct dcaf_ed448)))))goto err1;
	if(U(USICRYPT(get_random)(x->key,sizeof(x->key))))goto err2;
	decaf_ed448_derive_public_key(x->pub,x->key);
	return x;

err2:	free(x);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED448
	unsigned char *data;

	*len=sizeof(dcaf_ed448_asn1_pub)+57;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,dcaf_ed448_asn1_pub,sizeof(dcaf_ed448_asn1_pub));
	memcpy(data+sizeof(dcaf_ed448_asn1_pub),((struct dcaf_ed448 *)key)->pub,
		57);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED448
	struct dcaf_ed448 *x;

	if(U(len<sizeof(dcaf_ed448_asn1_pub)+57)||
		U(memcmp(key,dcaf_ed448_asn1_pub,sizeof(dcaf_ed448_asn1_pub))))
			return NULL;
	if(U(!(x=malloc(sizeof(struct dcaf_ed448)))))return NULL;
	memcpy(x->pub,((unsigned char *)key)+sizeof(dcaf_ed448_asn1_pub),57);
	USICRYPT(do_memclear)(x->key,sizeof(x->key));
	return x;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED448
	unsigned char *data;

	*len=sizeof(dcaf_ed448_asn1_key)+57;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,dcaf_ed448_asn1_key,sizeof(dcaf_ed448_asn1_key));
	memcpy(data+sizeof(dcaf_ed448_asn1_key),((struct dcaf_ed448 *)key)->key,
		57);
	return data;

err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED448
	struct dcaf_ed448 *x=NULL;

	if(U(len<sizeof(dcaf_ed448_asn1_key)+57)||
		U(memcmp(key,dcaf_ed448_asn1_key,sizeof(dcaf_ed448_asn1_key))))
			goto err1;
	if(U(!(x=malloc(sizeof(struct dcaf_ed448)))))goto err1;
	memcpy(x->key,((unsigned char *)key)+sizeof(dcaf_ed448_asn1_key),57);
	decaf_ed448_derive_public_key(x->pub,x->key);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(key,len);
	return x;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_sign)(void *ctx,void *key,void *data,int dlen,int *slen)
{
#ifndef USICRYPT_NO_ED448
	unsigned char *sig;

	*slen=114;
	if(U(!(sig=malloc(*slen))))return NULL;
	decaf_ed448_sign(sig,((struct dcaf_ed448 *)key)->key,
		((struct dcaf_ed448 *)key)->pub,data,dlen,0,NULL,0);
	return sig;
#else
	return NULL;
#endif
}

void *USICRYPT(ed448_sign_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,int *slen)
{
#if !defined(USICRYPT_NO_ED448) && !defined(USICRYPT_NO_IOV)
	unsigned char *sig;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	*slen=114;
	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(sig=malloc(*slen))))goto err1;
	if(U(!(data=malloc(len))))goto err2;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	decaf_ed448_sign(sig,((struct dcaf_ed448 *)key)->key,
		((struct dcaf_ed448 *)key)->pub,data,len,0,NULL,0);
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
#ifndef USICRYPT_NO_ED448
	if(slen!=114)return -1;
	if(decaf_ed448_verify(sig,((struct dcaf_ed448 *)key)->pub,data,dlen,0,
		NULL,0)!=DECAF_SUCCESS)return -1;
	return 0;
#else
	return -1;
#endif
}

int USICRYPT(ed448_verify_iov)(void *ctx,void *key,struct usicrypt_iov *iov,
	int niov,void *sig,int slen)
{
#if !defined(USICRYPT_NO_ED448) && !defined(USICRYPT_NO_IOV)
	int err=-1;
	int i;
	int len;
	unsigned char *data;
	unsigned char *p;

	if(slen!=114)return -1;
	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(data=malloc(len))))goto err1;
	for(p=data,i=0;i<niov;p+=iov[i++].length)
		memcpy(p,iov[i].data,iov[i].length);
	if(decaf_ed448_verify(sig,((struct dcaf_ed448 *)key)->pub,data,len,0,
		NULL,0)==DECAF_SUCCESS)err=0;
	((struct usicrypt_thread *)ctx)->global->memclear(data,len);
	free(data);
err1:	return err;
#else
	return -1;
#endif
}

void USICRYPT(ed448_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_ED448
	((struct usicrypt_thread *)ctx)->global->memclear(key,
		sizeof(struct dcaf_ed448));
	free(key);
#endif
}

#endif
