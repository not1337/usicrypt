/*
 * usicrypt, a unified simple interface crypto library wrapper
 *
 * (c) 2019 Andreas Steinmetz
 *
 * Any OSI approved license of your choice applies, see the file LICENSE
 * for details. For the code in github-orlp-ed25519 see
 * github-orlp-ed25519/license.txt for license information.
 *
 */

/******************************************************************************/
/*                                 Testing                                    */
/******************************************************************************/

#ifndef USICRYPT_ORLP25519
#define USICRYPT_ORLP25519
#endif

/******************************************************************************/
/*                                 Headers                                    */
/******************************************************************************/

#include "github-orlp-ed25519/src/ed25519.h"

#ifdef USICRYPT
#undef USICRYPT
#endif
#ifdef USICRYPT_TEST
#define USICRYPT(a) orlp_##a
#else
#define USICRYPT(a) usicrypt_##a
#endif

#include "usicrypt_internal.h"
#include "usicrypt.h"
#include "usicrypt_common.c"

#if defined(USICRYPT_ORLP25519)

struct orlp_ed25519
{
	unsigned char raw[32];
	unsigned char pub[32];
	unsigned char key[32];
};

static const unsigned char orlp_ed25519_asn1_pub[12]=
{
	0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,
	0x70,0x03,0x21,0x00
};

static const unsigned char orlp_ed25519_asn1_key[16]=
{
	0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,
	0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20
};

void *USICRYPT(ed25519_generate)(void *ctx)
{
#ifndef USICRYPT_NO_ED25519
	struct orlp_ed25519 *key;

	if(U(!(key=malloc(sizeof(struct orlp_ed25519)))))goto err1;
	if(U(USICRYPT(get_random)(key->raw,sizeof(key->raw))))goto err2;
	ed25519_create_keypair(key->pub,key->key,key->raw);
	return key;

err2:	free(key);
err1:	return NULL;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_get_pub)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED25519
	unsigned char *data=NULL;
	struct orlp_ed25519 *k=key;

	*len=sizeof(orlp_ed25519_asn1_pub)+32;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,orlp_ed25519_asn1_pub,sizeof(orlp_ed25519_asn1_pub));
	memcpy(data+sizeof(orlp_ed25519_asn1_pub),k->pub,32);
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_set_pub)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED25519
	struct orlp_ed25519 *k=NULL;

	if(U(len<sizeof(orlp_ed25519_asn1_pub)+32)||
	    U(memcmp(key,orlp_ed25519_asn1_pub,sizeof(orlp_ed25519_asn1_pub))))
		 goto err1;
	if(U(!(k=malloc(sizeof(struct orlp_ed25519)))))goto err1;
	USICRYPT(do_memclear)(k->raw,sizeof(k->raw));
	USICRYPT(do_memclear)(k->key,sizeof(k->key));
	memcpy(k->pub,key+sizeof(orlp_ed25519_asn1_pub),sizeof(k->pub));
err1:	return k;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_get_key)(void *ctx,void *key,int *len)
{
#ifndef USICRYPT_NO_ED25519
	unsigned char *data=NULL;
	struct orlp_ed25519 *k=key;

	*len=sizeof(orlp_ed25519_asn1_key)+32;
	if(U(!(data=malloc(*len))))goto err1;
	memcpy(data,orlp_ed25519_asn1_key,sizeof(orlp_ed25519_asn1_key));
	memcpy(data+sizeof(orlp_ed25519_asn1_key),k->raw,32);
err1:	return data;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_set_key)(void *ctx,void *key,int len)
{
#ifndef USICRYPT_NO_ED25519
	struct orlp_ed25519 *k=NULL;

	if(U(len<sizeof(orlp_ed25519_asn1_key)+32)||
	    U(memcmp(key,orlp_ed25519_asn1_key,sizeof(orlp_ed25519_asn1_key))))
		 goto err1;
	if(U(!(k=malloc(sizeof(struct orlp_ed25519)))))goto err1;
	memcpy(k->raw,key+sizeof(orlp_ed25519_asn1_key),sizeof(k->raw));
	ed25519_create_keypair(k->pub,k->key,k->raw);
err1:	return k;
#else
	return NULL;
#endif
}

void *USICRYPT(ed25519_sign)(void *ctx,void *key,void *data,int dlen,int *slen)
{
#ifndef USICRYPT_NO_ED25519
	unsigned char *sig=NULL;

	*slen=64;
	if(U(!(sig=malloc(*slen))))goto err1;
	ed25519_sign(sig,data,dlen,((struct orlp_ed25519 *)key)->pub,
		((struct orlp_ed25519 *)key)->key);
err1:	return sig;
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

	*slen=64;
	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(sig=malloc(*slen))))goto err1;
	if(U(!(data=malloc(len))))goto err2;
	for(p=data,i=0;i<niov;i++,p+=iov[i].length)
		memcpy(p,iov[i].data,iov[i].length);
	ed25519_sign(sig,data,len,((struct orlp_ed25519 *)key)->pub,
		((struct orlp_ed25519 *)key)->key);
	((struct usicrypt_thread *)ctx)->global->memclear(data,sizeof(len));
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
	if(slen!=64)return -1;
	if(!ed25519_verify(sig,data,dlen,((struct orlp_ed25519 *)key)->pub))
		return -1;
	return 0;
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

	if(slen!=64)return -1;
	for(len=0,i=0;i<niov;i++)len+=iov[i].length;
	if(U(!(data=malloc(len))))goto err1;
	for(p=data,i=0;i<niov;i++,p+=iov[i].length)
		memcpy(p,iov[i].data,iov[i].length);
	if(ed25519_verify(sig,data,len,((struct orlp_ed25519 *)key)->pub))err=0;
	((struct usicrypt_thread *)ctx)->global->memclear(data,sizeof(len));
	free(data);
err1:	return err;
#else
	return -1;
#endif
}

void USICRYPT(ed25519_free)(void *ctx,void *key)
{
#ifndef USICRYPT_NO_ED25519
	((struct usicrypt_thread *)ctx)->global->memclear(key,
		sizeof(struct orlp_ed25519));
	free(key);
#endif
}

#endif
