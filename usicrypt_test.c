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

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#ifdef USICRYPT
#undef USICRYPT
#endif
#define USICRYPT(a) xssl_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) mbed_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) wolf_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) gcry_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) nttl_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) orlp_##a
#include "usicrypt.h"
#undef USICRYPT
#define USICRYPT(a) dcaf_##a
#include "usicrypt.h"
#undef USICRYPT

#include <openssl/opensslv.h>
#include <mbedtls/version.h>
#include <wolfssl/version.h>
#include <nettle/version.h>

static int expensive=0;

int usicrypt_random(void *ctx,void *data,int len)
{
	int fd;
	int r=0;
	
	if((fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1)return -1;
	if(read(fd,data,len)!=len)r=-1;
	close(fd);
	return r;
}

static int printres(char *msg,int errc,int *errx)
{
	int i;

	printf("%s:",msg);
	if(errx[0])printf(" xssl failed");
	if(errx[1])printf(" mbed failed");
	if(errx[2])printf(" wolf failed");
	if(errx[3])printf(" gcry failed");
	if(errx[4])printf(" nttl failed");
	if(errc)printf(" compare failed");
	for(i=0;i<5;i++)errc+=errx[i];
	if(!errc)printf(" OK");
	printf("\n");
	return errc;
}

static struct rngops
{
	int (*random)(void *,void *,int);
	int iter;
} rngops[5]=
{
	{
		xssl_random,10000000,
	},
	{
		mbed_random,10000000,
	},
	{
		wolf_random,10000000,
	},
	{
		gcry_random,1000000,
	},
	{
		nttl_random,10000000,
	},
};

static void test_random_single(void *ctx,int *err,int iter,
	int (*random)(void *,void *,int))
{
	int i;
	unsigned long long val[2];

	if(random(ctx,&val[1],sizeof(val[0])))(*err)++;
	for(i=0;i<iter;i++)
	{
		if(random(ctx,&val[i&1],sizeof(val[0])))(*err)++;
		if(val[0]==val[1])(*err)++;
	}
}

static int test_random(void **ctx)
{
	int i;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)test_random_single(ctx[i],&err[i],rngops[i].iter,
		rngops[i].random);
	return printres("usicrypt_random()",0,err);
}

static struct dgszops
{
	int (*digest_size)(void *,int);
} dgszops[5]=
{
	{
		xssl_digest_size,
	},
	{
		mbed_digest_size,
	},
	{
		wolf_digest_size,
	},
	{
		gcry_digest_size,
	},
	{
		nttl_digest_size,
	},
};

static void test_digest_size_single(void *ctx,int *err,
	int (*digest_size)(void *,int))
{
	int i;
	int dgst;
	int cmp;

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	dgst=USICRYPT_SHA1;
			cmp=20;
			break;
		case 1:	dgst=USICRYPT_SHA256;
			cmp=32;
			break;
		case 2:	dgst=USICRYPT_SHA384;
			cmp=48;
			break;
		case 3:	dgst=USICRYPT_SHA512;
			cmp=64;
			break;
		}

		if(digest_size(ctx,dgst)!=cmp)(*err)++;
	}
}

static int test_digest_size(void **ctx)
{
	int i;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)
		test_digest_size_single(ctx[i],&err[i],dgszops[i].digest_size);
	return printres("usicrypt_digest_size()",0,err);
}

static struct dgstops
{
	int (*digest)(void *,int,void *,int,void *);
	int (*digest_iov)(void *,int,struct usicrypt_iov *,int,void *);
} dgstops[5]=
{
	{
		xssl_digest,xssl_digest_iov,
	},
	{
		mbed_digest,mbed_digest_iov,
	},
	{
		wolf_digest,wolf_digest_iov,
	},
	{
		gcry_digest,gcry_digest_iov,
	},
	{
		nttl_digest,nttl_digest_iov,
	},
};

static void test_digest_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct dgstops *a,struct dgstops *b)
{
	int i;
	int dgst;
	int size;
	struct usicrypt_iov iov[3];
	unsigned char data[256];
	unsigned char r1[64];
	unsigned char r2[64];

	iov[0].data=data;
	iov[0].length=40;
	iov[1].data=data+40;
	iov[1].length=24;
	iov[2].data=data+64;
	iov[2].length=sizeof(data)-64;

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	dgst=USICRYPT_SHA1;
			size=20;
			break;
		case 1:	dgst=USICRYPT_SHA256;
			size=32;
			break;
		case 2:	dgst=USICRYPT_SHA384;
			size=48;
			break;
		case 3:	dgst=USICRYPT_SHA512;
			size=64;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		if(a->digest(ctx1,dgst,data,sizeof(data),r1))(*err1)++;
		if(b->digest(ctx2,dgst,data,sizeof(data),r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;

		usicrypt_random(NULL,data,sizeof(data));
		if(a->digest_iov(ctx1,dgst,iov,3,r1))(*err1)++;
		if(b->digest_iov(ctx2,dgst,iov,3,r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;
	}
}

static int test_digest(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_digest_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&dgstops[i],&dgstops[j]);
	return printres("usicrypt_digest()",cerr,err);
}

static struct hmacops
{
	int (*hmac)(void *,int,void *,int,void *,int,void *);
	int (*hmac_iov)(void *,int,struct usicrypt_iov *,int,void *,int,void *);
} hmacops[5]=
{
	{
		xssl_hmac,xssl_hmac_iov,
	},
	{
		mbed_hmac,mbed_hmac_iov,
	},
	{
		wolf_hmac,wolf_hmac_iov,
	},
	{
		gcry_hmac,gcry_hmac_iov,
	},
	{
		nttl_hmac,nttl_hmac_iov,
	},
};

static void test_hmac_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct hmacops *a,struct hmacops *b)
{
	int i;
	int dgst;
	int size;
	struct usicrypt_iov iov[3];
	unsigned char data[256];
	unsigned char key[16];
	unsigned char r1[64];
	unsigned char r2[64];

	iov[0].data=data;
	iov[0].length=40;
	iov[1].data=data+40;
	iov[1].length=24;
	iov[2].data=data+64;
	iov[2].length=sizeof(data)-64;

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	dgst=USICRYPT_SHA1;
			size=20;
			break;
		case 1:	dgst=USICRYPT_SHA256;
			size=32;
			break;
		case 2:	dgst=USICRYPT_SHA384;
			size=48;
			break;
		case 3:	dgst=USICRYPT_SHA512;
			size=64;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		usicrypt_random(NULL,key,sizeof(key));
		if(a->hmac(ctx1,dgst,data,sizeof(data),key,sizeof(key),r1))
			(*err1)++;
		if(b->hmac(ctx2,dgst,data,sizeof(data),key,sizeof(key),r2))
			(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;

		usicrypt_random(NULL,data,sizeof(data));
		usicrypt_random(NULL,key,sizeof(key));
		if(a->hmac_iov(ctx1,dgst,iov,3,key,sizeof(key),r1))(*err1)++;
		if(b->hmac_iov(ctx2,dgst,iov,3,key,sizeof(key),r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;
	}
}

static int test_hmac(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_hmac_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&hmacops[i],&hmacops[j]);
	return printres("usicrypt_hmac()",cerr,err);
}

static struct pbkdfops
{
	int (*pbkdf2)(void *,int,void *,int,void *,int,int,void *);
} pbkdfops[5]=
{
	{
		xssl_pbkdf2,
	},
	{
		mbed_pbkdf2,
	},
	{
		wolf_pbkdf2,
	},
	{
		gcry_pbkdf2,
	},
	{
		nttl_pbkdf2,
	},
};

static void test_pbkdf2_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct pbkdfops *a,struct pbkdfops *b)
{
	int i;
	int dgst;
	int size;
	unsigned char key1[16];
	unsigned char key2[16];
	unsigned char salt[16];
	unsigned char r1[64];
	unsigned char r2[64];

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	dgst=USICRYPT_SHA1;
			size=20;
			break;
		case 1:	dgst=USICRYPT_SHA256;
			size=32;
			break;
		case 2:	dgst=USICRYPT_SHA384;
			size=48;
			break;
		case 3:	dgst=USICRYPT_SHA512;
			size=64;
			break;
		}

		usicrypt_random(NULL,salt,sizeof(salt));
		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key1));

		if(a->pbkdf2(ctx1,dgst,key1,sizeof(key1),salt,sizeof(salt),
			1000,r1))(*err1)++;
		if(b->pbkdf2(ctx2,dgst,key2,sizeof(key2),salt,sizeof(salt),
			1000,r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;
	}
}

static int test_pbkdf2(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_pbkdf2_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&pbkdfops[i],&pbkdfops[j]);
	return printres("usicrypt_pbkdf2()",cerr,err);
}

static struct hkdfops
{
	int (*hkdf)(void *,int,void *,int,void *,int,void *,int,void *);
} hkdfops[5]=
{
	{
		xssl_hkdf,
	},
	{
		mbed_hkdf,
	},
	{
		wolf_hkdf,
	},
	{
		gcry_hkdf,
	},
	{
		nttl_hkdf,
	},
};

static void test_hkdf_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct hkdfops *a,struct hkdfops *b)
{
	int i;
	int dgst;
	int size;
	unsigned char key1[16];
	unsigned char key2[16];
	unsigned char salt[16];
	unsigned char r1[64];
	unsigned char r2[64];

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	dgst=USICRYPT_SHA1;
			size=20;
			break;
		case 1:	dgst=USICRYPT_SHA256;
			size=32;
			break;
		case 2:	dgst=USICRYPT_SHA384;
			size=48;
			break;
		case 3:	dgst=USICRYPT_SHA512;
			size=64;
			break;
		}

		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key1));

		if(a->hkdf(ctx1,dgst,key1,sizeof(key1),NULL,0,NULL,0,r1))
			(*err1)++;
		if(b->hkdf(ctx2,dgst,key2,sizeof(key2),NULL,0,NULL,0,r2))
			(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;

		usicrypt_random(NULL,salt,sizeof(salt));
		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key1));

		if(a->hkdf(ctx1,dgst,key1,sizeof(key1),salt,sizeof(salt),
			NULL,0,r1))(*err1)++;
		if(b->hkdf(ctx2,dgst,key2,sizeof(key2),salt,sizeof(salt),
			NULL,0,r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;

		usicrypt_random(NULL,salt,sizeof(salt));
		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key1));

		if(a->hkdf(ctx1,dgst,key1,sizeof(key1),salt,sizeof(salt),
			"test",4,r1))(*err1)++;
		if(b->hkdf(ctx2,dgst,key2,sizeof(key2),salt,sizeof(salt),
			"test",4,r2))(*err2)++;
		if(memcmp(r1,r2,size))(*err)++;
	}
}

static int test_hkdf(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_hkdf_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&hkdfops[i],&hkdfops[j]);
	return printres("usicrypt_hkdf()",cerr,err);
}

static struct b64ops
{
	void *(*base64_encode)(void *,void *,int,int *);
	void *(*base64_decode)(void *,void *,int,int *);
} b64ops[5]=
{
	{
		xssl_base64_encode,xssl_base64_decode,
	},
	{
		mbed_base64_encode,mbed_base64_decode,
	},
	{
		wolf_base64_encode,wolf_base64_decode,
	},
	{
		gcry_base64_encode,gcry_base64_decode,
	},
	{
		nttl_base64_encode,nttl_base64_decode,
	},
};

static void test_base64_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct b64ops *a,struct b64ops *b)
{
	int i;
	int l;
	int len1;
	int len2;
	void *k1;
	void *k2;
	unsigned char data[256];

	for(i=0;i<4;i++)
	{
		l=sizeof(data)-i;

		k1=NULL;
		k2=NULL;
		usicrypt_random(NULL,data,l);
		if(!(k1=a->base64_encode(ctx1,data,l,&len1)))(*err1)++;
		else if(strlen(k1)!=len1)(*err1)++;
		else if(!(k2=a->base64_decode(ctx1,k1,len1,&len2)))(*err1)++;
		else if(len2!=l||memcmp(k2,data,len2))(*err1)++;
		if(k1)free(k1);
		if(k2)free(k2);

		k1=NULL;
		k2=NULL;
		usicrypt_random(NULL,data,l);
		if(!(k1=b->base64_encode(ctx2,data,l,&len1)))(*err2)++;
		else if(strlen(k1)!=len1)(*err2)++;
		else if(!(k2=b->base64_decode(ctx2,k1,len1,&len2)))(*err2)++;
		else if(len2!=l||memcmp(k2,data,len2))(*err2)++;
		if(k1)free(k1);
		if(k2)free(k2);

		k1=NULL;
		k2=NULL;
		usicrypt_random(NULL,data,l);
		if(!(k1=a->base64_encode(ctx1,data,l,&len1)))(*err1)++;
		else if(strlen(k1)!=len1)(*err1)++;
		else if(!(k2=b->base64_decode(ctx2,k1,len1,&len2)))(*err2)++;
		else if(len2!=l||memcmp(k2,data,len2))(*err)++;
		if(k1)free(k1);
		if(k2)free(k2);

		k1=NULL;
		k2=NULL;
		usicrypt_random(NULL,data,l);
		if(!(k1=b->base64_encode(ctx2,data,l,&len1)))(*err2)++;
		else if(strlen(k1)!=len1)(*err2)++;
		else if(!(k2=a->base64_decode(ctx1,k1,len1,&len2)))(*err1)++;
		else if(len2!=l||memcmp(k2,data,len2))(*err)++;
		if(k1)free(k1);
		if(k2)free(k2);
	}
}

static int test_base64(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_base64_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&b64ops[i],&b64ops[j]);
	return printres("usicrypt_base64_...()",cerr,err);
}

static struct rsaops
{
	void *(*rsa_generate)(void *,int);
	int (*rsa_size)(void *,void *);
	void *(*rsa_get_pub)(void *,void *,int *);
	void *(*rsa_set_pub)(void *,void *,int);
	void *(*rsa_get_key)(void *,void *,int *);
	void *(*rsa_set_key)(void *,void *,int);
	void *(*rsa_sign_v15)(void *,int,void *,void *,int,int *);
	int (*rsa_verify_v15)(void *,int,void *,void *,int,void *,int);
	void *(*rsa_sign_v15_iov)(void *,int,void *,struct usicrypt_iov *,
		int,int *);
	int (*rsa_verify_v15_iov)(void *,int,void *,struct usicrypt_iov *,
		int,void *,int);
	void *(*rsa_sign_pss)(void *,int,void *,void *,int,int *);
	int (*rsa_verify_pss)(void *,int,void *,void *,int,void *,int);
	void *(*rsa_sign_pss_iov)(void *,int,void *,struct usicrypt_iov *,
		int,int *);
	int (*rsa_verify_pss_iov)(void *,int,void *,struct usicrypt_iov *,
		int,void *,int);
	void *(*rsa_encrypt_v15)(void *,void *,void *,int,int *);
	void *(*rsa_decrypt_v15)(void *,void *,void *,int,int *);
	void *(*rsa_encrypt_oaep)(void *,int,void *,void *,int,int *);
	void *(*rsa_decrypt_oaep)(void *,int,void *,void *,int,int *);
	void (*rsa_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} rsaops[5]=
{
	{
		xssl_rsa_generate,xssl_rsa_size,xssl_rsa_get_pub,
		xssl_rsa_set_pub,xssl_rsa_get_key,xssl_rsa_set_key,
		xssl_rsa_sign_v15,xssl_rsa_verify_v15,xssl_rsa_sign_v15_iov,
		xssl_rsa_verify_v15_iov,xssl_rsa_sign_pss,xssl_rsa_verify_pss,
		xssl_rsa_sign_pss_iov,xssl_rsa_verify_pss_iov,
		xssl_rsa_encrypt_v15,xssl_rsa_decrypt_v15,
		xssl_rsa_encrypt_oaep,xssl_rsa_decrypt_oaep,xssl_rsa_free,
		xssl_encrypt_p8,xssl_decrypt_p8,xssl_p8_to_pem,xssl_pem_to_p8,
	},
	{
		mbed_rsa_generate,mbed_rsa_size,mbed_rsa_get_pub,
		mbed_rsa_set_pub,mbed_rsa_get_key,mbed_rsa_set_key,
		mbed_rsa_sign_v15,mbed_rsa_verify_v15,mbed_rsa_sign_v15_iov,
		mbed_rsa_verify_v15_iov,mbed_rsa_sign_pss,mbed_rsa_verify_pss,
		mbed_rsa_sign_pss_iov,mbed_rsa_verify_pss_iov,
		mbed_rsa_encrypt_v15,mbed_rsa_decrypt_v15,
		mbed_rsa_encrypt_oaep,mbed_rsa_decrypt_oaep,mbed_rsa_free,
		mbed_encrypt_p8,mbed_decrypt_p8,mbed_p8_to_pem,mbed_pem_to_p8,
	},
	{
		wolf_rsa_generate,wolf_rsa_size,wolf_rsa_get_pub,
		wolf_rsa_set_pub,wolf_rsa_get_key,wolf_rsa_set_key,
		wolf_rsa_sign_v15,wolf_rsa_verify_v15,wolf_rsa_sign_v15_iov,
		wolf_rsa_verify_v15_iov,wolf_rsa_sign_pss,wolf_rsa_verify_pss,
		wolf_rsa_sign_pss_iov,wolf_rsa_verify_pss_iov,
		wolf_rsa_encrypt_v15,wolf_rsa_decrypt_v15,
		wolf_rsa_encrypt_oaep,wolf_rsa_decrypt_oaep,wolf_rsa_free,
		wolf_encrypt_p8,wolf_decrypt_p8,wolf_p8_to_pem,wolf_pem_to_p8,
	},
	{
		gcry_rsa_generate,gcry_rsa_size,gcry_rsa_get_pub,
		gcry_rsa_set_pub,gcry_rsa_get_key,gcry_rsa_set_key,
		gcry_rsa_sign_v15,gcry_rsa_verify_v15,gcry_rsa_sign_v15_iov,
		gcry_rsa_verify_v15_iov,gcry_rsa_sign_pss,gcry_rsa_verify_pss,
		gcry_rsa_sign_pss_iov,gcry_rsa_verify_pss_iov,
		gcry_rsa_encrypt_v15,gcry_rsa_decrypt_v15,
		gcry_rsa_encrypt_oaep,gcry_rsa_decrypt_oaep,gcry_rsa_free,
		gcry_encrypt_p8,gcry_decrypt_p8,gcry_p8_to_pem,gcry_pem_to_p8,
	},
	{
		nttl_rsa_generate,nttl_rsa_size,nttl_rsa_get_pub,
		nttl_rsa_set_pub,nttl_rsa_get_key,nttl_rsa_set_key,
		nttl_rsa_sign_v15,nttl_rsa_verify_v15,nttl_rsa_sign_v15_iov,
		nttl_rsa_verify_v15_iov,nttl_rsa_sign_pss,nttl_rsa_verify_pss,
		nttl_rsa_sign_pss_iov,nttl_rsa_verify_pss_iov,
		nttl_rsa_encrypt_v15,nttl_rsa_decrypt_v15,
		nttl_rsa_encrypt_oaep,nttl_rsa_decrypt_oaep,nttl_rsa_free,
		nttl_encrypt_p8,nttl_decrypt_p8,nttl_p8_to_pem,nttl_pem_to_p8,
	},
};

static void test_rsa_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	int nopss,struct rsaops *a,struct rsaops *b)
{
	int i;
	int j;
	int k;
	int l;
	int m;
	int n;
	int p1;
	int p2;
	int p3;
	int p4;
	int len;
	int maxlen;
	int size;
	int bits=0;
	int md;
	int em1;
	int em2;
	int slen;
	int elen;
	int dlen;
	int pe1len;
	int pe2len;
	int de1len;
	int de2len;
	int plen1[4];
	int plen2[4];
	int klen1[4];
	int klen2[4];
	void *sig;
	void *enc;
	void *dec;
	void *pe1;
	void *pe2;
	void *de1;
	void *de2;
	void *rsa1[4];
	void *rsa2[4];
	void *rsa3[4];
	void *rsa4[4];
	void *rsa5[4];
	void *rsa6[4];
	void *pub1[4];
	void *pub2[4];
	void *key1[4];
	void *key2[4];
	struct usicrypt_iov iov[3];
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];
	unsigned char maxdata[2048];

	em1=*err1;
	em2=*err2;

	iov[0].data=data;
	iov[0].length=4;
	iov[1].data=data+4;
	iov[1].length=8;
	iov[2].data=data+12;
	iov[2].length=sizeof(data)-12;

	memset(rsa1,0,sizeof(rsa1));
	memset(rsa2,0,sizeof(rsa2));
	memset(rsa3,0,sizeof(rsa3));
	memset(rsa4,0,sizeof(rsa4));
	memset(rsa5,0,sizeof(rsa5));
	memset(rsa6,0,sizeof(rsa6));
	memset(pub1,0,sizeof(pub1));
	memset(pub2,0,sizeof(pub2));
	memset(key1,0,sizeof(key1));
	memset(key2,0,sizeof(key2));

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	bits=1024;
			break;
		case 1:	bits=2048;
			break;
		case 2:	bits=3072;
			break;
		case 3:	bits=4096;
			break;
		}

		if(!(rsa1[i]=a->rsa_generate(ctx1,bits)))(*err1)++;
		else if(a->rsa_size(ctx1,rsa1[i])!=bits)(*err1)++;
		else if(!(pub1[i]=a->rsa_get_pub(ctx1,rsa1[i],&plen1[i])))
			(*err1)++;
		else if(!(key1[i]=a->rsa_get_key(ctx1,rsa1[i],&klen1[i])))
			(*err1)++;

		if(!(rsa2[i]=b->rsa_generate(ctx2,bits)))(*err2)++;
		else if(b->rsa_size(ctx2,rsa2[i])!=bits)(*err2)++;
		else if(!(pub2[i]=b->rsa_get_pub(ctx2,rsa2[i],&plen2[i])))
			(*err2)++;
		else if(!(key2[i]=b->rsa_get_key(ctx2,rsa2[i],&klen2[i])))
			(*err2)++;

		if(usicrypt_pub_type_from_p8(ctx1,pub1[i],plen1[i])!=
			USICRYPT_RSA)(*err)++;
		if(usicrypt_pub_type_from_p8(ctx2,pub2[i],plen2[i])!=
			USICRYPT_RSA)(*err)++;

		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_rsa_key_to_p8(ctx1,key1[i],klen1[i],&elen)))
			(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=USICRYPT_RSA)
			(*err)++;
		else if(!(dec=usicrypt_p8_to_rsa_key(ctx1,enc,elen,&dlen)))
			(*err)++;
		else if(dlen!=klen1[i]||memcmp(key1[i],dec,dlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_rsa_key_to_p8(ctx2,key2[i],klen2[i],&elen)))
			(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=USICRYPT_RSA)
			(*err)++;
		else if(!(dec=usicrypt_p8_to_rsa_key(ctx2,enc,elen,&dlen)))
			(*err)++;
		else if(dlen!=klen2[i]||memcmp(key2[i],dec,dlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);
	}
	if(*err1!=em1||*err2!=em2)goto out;

	for(i=0;i<4;i++)for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;
		if(!expensive&&n)continue;

		switch(j)
		{
		case 0:	p1=USICRYPT_SHA1;
			break;
		case 1:	p1=USICRYPT_SHA256;
			break;
		case 2:	p1=USICRYPT_SHA384;
			break;
		case 3:	p1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	p2=USICRYPT_AES;
			break;
		case 1:	p2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	p3=USICRYPT_ECB;
			break;
		case 1:	p3=USICRYPT_CBC;
			break;
		case 2:	p3=USICRYPT_CFB;
			break;
		case 3:	p3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	p4=1;
			break;
		case 1:	p4=0x7f;
			break;
		case 2:	p4=0x80;
			break;
		case 3:	p4=0x7fff;
			break;
		case 4:	p4=0x8000;
			break;
		}

		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;
		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_rsa_key_to_p8(ctx1,key1[i],klen1[i],&elen)))
			(*err)++;
		else if(!(pe1=a->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		if(!(dec=usicrypt_rsa_key_to_p8(ctx2,key2[i],klen2[i],&dlen)))
			(*err)++;
		else if(!(pe2=b->p8_to_pem(ctx2,dec,dlen,&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=dlen||memcmp(de2,dec,de2len))(*err2)++;
		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);
		if(enc)free(enc);
		if(dec)free(dec);

		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;
		if(!(pe1=a->p8_to_pem(ctx1,pub1[i],plen1[i],&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=plen1[i]||memcmp(de1,pub1[i],de1len))(*err1)++;
		if(!(pe2=b->p8_to_pem(ctx2,pub2[i],plen2[i],&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=plen2[i]||memcmp(de2,pub2[i],de2len))(*err2)++;
		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe1=NULL;
		de1=NULL;
		if(!(sig=usicrypt_rsa_key_to_p8(ctx1,key1[i],klen1[i],&slen)))
			(*err)++;
		else if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err1)++;
		else if(!(pe1=a->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe1)free(pe1);
		if(de1)free(de1);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe2=NULL;
		de2=NULL;
		if(!(sig=usicrypt_rsa_key_to_p8(ctx2,key1[i],klen1[i],&slen)))
			(*err)++;
		else if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err2)++;
		else if(!(pe2=b->p8_to_pem(ctx2,enc,elen,&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=elen||memcmp(de2,enc,de2len))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe2)free(pe2);
		if(de2)free(de2);
	}

	for(i=0;i<4;i++)
	{
		if(!(rsa3[i]=a->rsa_set_pub(ctx1,pub2[i],plen2[i])))(*err1)++;
		if(!(rsa5[i]=a->rsa_set_key(ctx1,key2[i],klen2[i])))(*err1)++;

		if(!(rsa4[i]=b->rsa_set_pub(ctx2,pub1[i],plen1[i])))(*err2)++;
		if(!(rsa6[i]=b->rsa_set_key(ctx2,key1[i],klen1[i])))(*err2)++;
	}
	if(*err1!=em1||*err2!=em2)goto out;

	for(i=0;i<4;i++)
	{
		switch(i)
		{
		case 0:	bits=1024;
			break;
		case 1:	bits=2048;
			break;
		case 2:	bits=3072;
			break;
		case 3:	bits=4096;
			break;
		}

		for(j=0;j<4;j++)
		{
			switch(j)
			{
			case 0:	md=USICRYPT_SHA1;
				break;
			case 1:	md=USICRYPT_SHA256;
				break;
			case 2:	md=USICRYPT_SHA384;
				break;
			case 3:	md=USICRYPT_SHA512;
				break;
			}

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->rsa_sign_v15(ctx1,md,rsa1[i],data,
				sizeof(data),&size)))(*err1)++;
			else if(b->rsa_verify_v15(ctx2,md,rsa4[i],data,
				sizeof(data),sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_v15(ctx2,md,rsa2[i],data,
				sizeof(data),&size)))(*err2)++;
			else if(a->rsa_verify_v15(ctx1,md,rsa3[i],data,
				sizeof(data),sig,size))(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->rsa_sign_v15(ctx1,md,rsa5[i],data,
				sizeof(data),&size)))(*err1)++;
			else if(b->rsa_verify_v15(ctx2,md,rsa2[i],data,
				sizeof(data),sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_v15(ctx2,md,rsa6[i],data,
				sizeof(data),&size)))(*err2)++;
			else if(a->rsa_verify_v15(ctx1,md,rsa1[i],data,
				sizeof(data),sig,size))(*err1)++;
			if(sig)free(sig);

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->rsa_sign_v15_iov(ctx1,md,rsa1[i],iov,3,
				&size)))(*err1)++;
			else if(b->rsa_verify_v15_iov(ctx2,md,rsa4[i],iov,3,
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_v15_iov(ctx2,md,rsa2[i],iov,3,
				&size)))(*err2)++;
			else if(a->rsa_verify_v15_iov(ctx1,md,rsa3[i],iov,3,
				sig,size))(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->rsa_sign_v15_iov(ctx1,md,rsa5[i],iov,3,
				&size)))(*err1)++;
			else if(b->rsa_verify_v15_iov(ctx2,md,rsa2[i],iov,3,
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_v15_iov(ctx2,md,rsa6[i],iov,3,
				&size)))(*err2)++;
			else if(a->rsa_verify_v15_iov(ctx1,md,rsa1[i],iov,3,
				sig,size))(*err1)++;
			if(sig)free(sig);
		}

		if(!nopss)for(j=0;j<(i?4:3);j++)
		{
			switch(j)
			{
			case 0:	md=USICRYPT_SHA1;
				break;
			case 1:	md=USICRYPT_SHA256;
				break;
			case 2:	md=USICRYPT_SHA384;
				break;
			case 3:	md=USICRYPT_SHA512;
				break;
			}

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->rsa_sign_pss(ctx1,md,rsa1[i],data,
				sizeof(data),&size)))(*err1)++;
			else if(b->rsa_verify_pss(ctx2,md,rsa4[i],data,
				sizeof(data),sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_pss(ctx2,md,rsa2[i],data,
				sizeof(data),&size)))(*err2)++;
			else if(a->rsa_verify_pss(ctx1,md,rsa3[i],data,
				sizeof(data),sig,size))(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->rsa_sign_pss(ctx1,md,rsa5[i],data,
				sizeof(data),&size)))(*err1)++;
			else if(b->rsa_verify_pss(ctx2,md,rsa2[i],data,
				sizeof(data),sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_pss(ctx2,md,rsa6[i],data,
				sizeof(data),&size)))(*err2)++;
			else if(a->rsa_verify_pss(ctx1,md,rsa1[i],data,
				sizeof(data),sig,size))(*err1)++;
			if(sig)free(sig);

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->rsa_sign_pss_iov(ctx1,md,rsa1[i],iov,3,
				&size)))(*err1)++;
			else if(b->rsa_verify_pss_iov(ctx2,md,rsa4[i],iov,3,
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_pss_iov(ctx2,md,rsa2[i],iov,3,
				&size)))(*err2)++;
			else if(a->rsa_verify_pss_iov(ctx1,md,rsa3[i],iov,3,
				sig,size))(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->rsa_sign_pss_iov(ctx1,md,rsa5[i],iov,3,
				&size)))(*err1)++;
			else if(b->rsa_verify_pss_iov(ctx2,md,rsa2[i],iov,3,
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->rsa_sign_pss_iov(ctx2,md,rsa6[i],iov,3,
				&size)))(*err2)++;
			else if(a->rsa_verify_pss_iov(ctx1,md,rsa1[i],iov,3,
				sig,size))(*err1)++;
			if(sig)free(sig);
		}

		usicrypt_random(NULL,data,sizeof(data));

		enc=NULL;
		dec=NULL;
		if(!(enc=a->rsa_encrypt_v15(ctx1,rsa3[i],data,sizeof(data),
			&size)))(*err1)++;
		else if(!(dec=b->rsa_decrypt_v15(ctx2,rsa2[i],enc,size,
			&len)))(*err2)++;
		else if(len!=sizeof(data)||memcmp(dec,data,len))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		enc=NULL;
		dec=NULL;
		if(!(enc=b->rsa_encrypt_v15(ctx2,rsa4[i],data,sizeof(data),
			&size)))(*err2)++;
		else if(!(dec=a->rsa_decrypt_v15(ctx1,rsa1[i],enc,size,
			&len)))(*err1)++;
		else if(len!=sizeof(data)||memcmp(dec,data,len))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		maxlen=(bits>>3)-11;
		usicrypt_random(NULL,maxdata,sizeof(maxdata));

		enc=NULL;
		dec=NULL;
		if(!(enc=a->rsa_encrypt_v15(ctx1,rsa3[i],maxdata,maxlen,
			&size)))(*err1)++;
		else if(!(dec=b->rsa_decrypt_v15(ctx2,rsa2[i],enc,size,
			&len)))(*err2)++;
		else if(len!=maxlen||memcmp(dec,maxdata,maxlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		enc=NULL;
		dec=NULL;
		if(!(enc=b->rsa_encrypt_v15(ctx2,rsa4[i],maxdata,maxlen,
			&size)))(*err2)++;
		else if(!(dec=a->rsa_decrypt_v15(ctx1,rsa1[i],enc,size,
			&len)))(*err1)++;
		else if(len!=maxlen||memcmp(dec,maxdata,maxlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		for(j=0;j<(i?4:2);j++)
		{
			switch(j)
			{
			case 0:	md=USICRYPT_SHA1;
				break;
			case 1:	md=USICRYPT_SHA256;
				break;
			case 2:	md=USICRYPT_SHA384;
				break;
			case 3:	md=USICRYPT_SHA512;
				break;
			}

			usicrypt_random(NULL,data,sizeof(data));

			enc=NULL;
			dec=NULL;
			if(!(enc=a->rsa_encrypt_oaep(ctx1,md,rsa3[i],data,
				sizeof(data),&size)))(*err1)++;
			else if(!(dec=b->rsa_decrypt_oaep(ctx2,md,rsa2[i],
				enc,size,&len)))(*err2)++;
			else if(len!=sizeof(data)||memcmp(dec,data,len))
				(*err)++;
			if(enc)free(enc);
			if(dec)free(dec);

			enc=NULL;
			dec=NULL;
			if(!(enc=b->rsa_encrypt_oaep(ctx2,md,rsa4[i],data,
				sizeof(data),&size)))(*err2)++;
			else if(!(dec=a->rsa_decrypt_oaep(ctx1,md,rsa1[i],
				enc,size,&len)))(*err1)++;
			else if(len!=sizeof(data)||memcmp(dec,data,len))
				(*err)++;
			if(enc)free(enc);
			if(dec)free(dec);
		}
	}

out:	for(i=0;i<4;i++)
	{
		if(rsa1[i])a->rsa_free(ctx1,rsa1[i]);
		if(rsa2[i])b->rsa_free(ctx2,rsa2[i]);
		if(rsa3[i])a->rsa_free(ctx1,rsa3[i]);
		if(rsa4[i])b->rsa_free(ctx2,rsa4[i]);
		if(rsa5[i])a->rsa_free(ctx1,rsa5[i]);
		if(rsa6[i])b->rsa_free(ctx2,rsa6[i]);
		if(pub1[i])free(pub1[i]);
		if(pub2[i])free(pub2[i]);
		if(key1[i])free(key1[i]);
		if(key2[i])free(key2[i]);
	}
}

static int test_rsa(void **ctx)
{
	int i;
	int j;
	int x;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
#if LIBWOLFSSL_VERSION_HEX < 0x04003000
		if(i==2||j==2)x=1;
		else x=0;
#else
		x=0;
#endif
		test_rsa_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],x,
			&rsaops[i],&rsaops[j]);
	}
	return printres("usicrypt_rsa_...()",cerr,err);
}

static struct dhops
{
	void *(*dh_generate)(void *,int,int,int *);
	void *(*dh_init)(void *,void *,int);
	void *(*dh_genex)(void *,void *,int *);
	void *(*dh_derive)(void *,void *,void *,int,int *);
	void (*dh_free)(void *,void *);
	void *(*dh_to_pem)(void *,void *,int,int *);
	void *(*pem_to_dh)(void *,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} dhops[5]=
{
	{
		xssl_dh_generate,xssl_dh_init,xssl_dh_genex,xssl_dh_derive,
		xssl_dh_free,xssl_dh_to_pem,xssl_pem_to_dh,xssl_p8_to_pem,
		xssl_pem_to_p8,
	},
	{
		mbed_dh_generate,mbed_dh_init,mbed_dh_genex,mbed_dh_derive,
		mbed_dh_free,mbed_dh_to_pem,mbed_pem_to_dh,mbed_p8_to_pem,
		mbed_pem_to_p8,
	},
	{
		wolf_dh_generate,wolf_dh_init,wolf_dh_genex,wolf_dh_derive,
		wolf_dh_free,wolf_dh_to_pem,wolf_pem_to_dh,wolf_p8_to_pem,
		wolf_pem_to_p8,
	},
	{
		gcry_dh_generate,gcry_dh_init,gcry_dh_genex,gcry_dh_derive,
		gcry_dh_free,gcry_dh_to_pem,gcry_pem_to_dh,gcry_p8_to_pem,
		gcry_pem_to_p8,
	},
	{
		nttl_dh_generate,nttl_dh_init,nttl_dh_genex,nttl_dh_derive,
		nttl_dh_free,nttl_dh_to_pem,nttl_pem_to_dh,nttl_p8_to_pem,
		nttl_pem_to_p8,
	},
};

static void test_dh_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct dhops *a,struct dhops *b,int nogen)
{
	int i;
	int dlen;
	int em;
	int em1;
	int em2;
	int plen1[3];
	int plen2[3];
	int slen1[3];
	int slen2[3];
	int p81len[3];
	int p82len[3];
	int v81len[3];
	int v82len[3];
	int c81len[3];
	int c82len[3];
	int gen1len;
	int gen2len;
	int dp1len;
	int dp2len;
	int dp3len;
	int dp4len;
	int ds1len;
	int ds2len;
	int ds3len;
	int ds4len;
	int pe1len;
	int pe2len;
	int de1len;
	int de2len;
	int p;
	unsigned char *data;
	void *dh1[3];
	void *dh2[3];
	void *pub1[3];
	void *pub2[3];
	void *sec1[3];
	void *sec2[3];
	void *p81[3];
	void *p82[3];
	void *v81[3];
	void *v82[3];
	void *c81[3];
	void *c82[3];
	void *gen1;
	void *gen2;
	void *dg1;
	void *dg2;
	void *dg3;
	void *dg4;
	void *dp1;
	void *dp2;
	void *dp3;
	void *dp4;
	void *ds1;
	void *ds2;
	void *ds3;
	void *ds4;
	void *pe1;
	void *pe2;
	void *de1;
	void *de2;

	em=*err;
	em1=*err1;
	em2=*err2;

	memset(dh1,0,sizeof(dh1));
	memset(dh2,0,sizeof(dh2));
	memset(pub1,0,sizeof(pub1));
	memset(pub2,0,sizeof(pub2));
	memset(sec1,0,sizeof(sec1));
	memset(sec2,0,sizeof(sec2));
	memset(p81,0,sizeof(p81));
	memset(p82,0,sizeof(p82));
	memset(v81,0,sizeof(v81));
	memset(v82,0,sizeof(v82));
	memset(c81,0,sizeof(c81));
	memset(c82,0,sizeof(c82));

	for(i=0;i<3;i++)
	{
		switch(i)
		{
		case 0:	p=USICRYPT_RFC5114_1024_160;
			break;
		case 1:	p=USICRYPT_RFC5114_2048_224;
			break;
		case 2:	p=USICRYPT_RFC5114_2048_256;
			break;
		}

		if(!(data=usicrypt_dh_params(ctx1,p,&dlen)))(*err)++;

		if(!(dh1[i]=a->dh_init(ctx1,data,dlen)))(*err1)++;
		else if(!(pub1[i]=a->dh_genex(ctx1,dh1[i],&plen1[i])))(*err1)++;

		if(!(dh2[i]=b->dh_init(ctx2,data,dlen)))(*err2)++;
		else if(!(pub2[i]=b->dh_genex(ctx2,dh2[i],&plen2[i])))(*err2)++;
	}
	if(*err!=em||*err1!=em1||*err2!=em2)goto out;

	for(i=0;i<3;i++)
	{
		switch(i)
		{
		case 0:	p=USICRYPT_RFC5114_1024_160;
			break;
		case 1:	p=USICRYPT_RFC5114_2048_224;
			break;
		case 2:	p=USICRYPT_RFC5114_2048_256;
			break;
		}

		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;

		if(!(data=usicrypt_dh_params(ctx1,p,&dlen)))(*err)++;

		if(!(p81[i]=usicrypt_dh_get_pub(ctx1,pub1[i],plen1[i],
			data,dlen,&p81len[i])))(*err1)++;
		else if(!(v81[i]=usicrypt_dh_set_pub(ctx1,p81[i],p81len[i],
			&c81[i],&c81len[i],&v81len[i])))(*err1)++;
		else if(v81len[i]!=plen1[i]||memcmp(v81[i],pub1[i],plen1[i]))
			(*err1)++;
		else if(usicrypt_dh_cmp_params(ctx1,c81[i],c81len[i],data,dlen))
			(*err1)++;

		if(!(p82[i]=usicrypt_dh_get_pub(ctx2,pub2[i],plen2[i],
			data,dlen,&p82len[i])))(*err2)++;
		else if(!(v82[i]=usicrypt_dh_set_pub(ctx2,p82[i],p82len[i],
			&c82[i],&c82len[i],&v82len[i])))(*err2)++;
		else if(v82len[i]!=plen2[i]||memcmp(v82[i],pub2[i],plen2[i]))
			(*err2)++;
		else if(usicrypt_dh_cmp_params(ctx2,c82[i],c82len[i],data,dlen))
			(*err2)++;

		if(usicrypt_pub_type_from_p8(ctx1,p81[i],p81len[i])!=
			USICRYPT_DH)(*err)++;
		if(usicrypt_pub_type_from_p8(ctx2,p82[i],p82len[i])!=
			USICRYPT_DH)(*err)++;

		if(!(pe1=a->p8_to_pem(ctx1,p81[i],p81len[i],&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=p81len[i]||memcmp(de1,p81[i],de1len))(*err1)++;

		if(!(pe2=b->p8_to_pem(ctx2,p82[i],p82len[i],&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=p82len[i]||memcmp(de2,p82[i],de2len))(*err2)++;

		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);
	}

	for(i=0;i<3;i++)
	{
		if(!(sec1[i]=a->dh_derive(ctx1,dh1[i],pub2[i],plen2[i],
			&slen1[i])))(*err1)++;
		else if(!(sec2[i]=b->dh_derive(ctx2,dh2[i],pub1[i],plen1[i],
			&slen2[i])))(*err2)++;
		else if(slen1[i]!=slen2[i]||memcmp(sec1[i],sec2[i],slen1[i]))
			(*err)++;
	}

	if(nogen)goto out;

	for(i=2;i<=5;i+=3)
	{
		gen1=NULL;
		gen2=NULL;
		dg1=NULL;
		dg2=NULL;
		dg3=NULL;
		dg4=NULL;
		dp1=NULL;
		dp2=NULL;
		dp3=NULL;
		dp4=NULL;
		ds1=NULL;
		ds2=NULL;
		ds3=NULL;
		ds4=NULL;
		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;

		if(!(gen1=a->dh_generate(ctx1,1024,i,&gen1len)))(*err1)++;
		if(!(gen2=b->dh_generate(ctx2,1024,i,&gen2len)))(*err2)++;
		if(!gen1||!gen2)goto cont;

		if(!(dg1=a->dh_init(ctx1,gen1,gen1len)))(*err1)++;
		if(!(dg2=b->dh_init(ctx2,gen2,gen2len)))(*err2)++;
		if(!(dg3=a->dh_init(ctx1,gen2,gen2len)))(*err1)++;
		if(!(dg4=b->dh_init(ctx2,gen1,gen1len)))(*err2)++;
		if(!dg1||!dg2||!dg3||!dg4)goto out;

		if(!(dp1=a->dh_genex(ctx1,dg1,&dp1len)))(*err1)++;
		if(!(dp2=b->dh_genex(ctx2,dg2,&dp2len)))(*err2)++;
		if(!(dp3=a->dh_genex(ctx1,dg3,&dp3len)))(*err1)++;
		if(!(dp4=b->dh_genex(ctx2,dg4,&dp4len)))(*err2)++;
		if(!dp1||!dp2||!dp3||!dp4)goto out;

		if(!(ds1=a->dh_derive(ctx1,dg1,dp4,dp4len,&ds1len)))(*err1)++;
		if(!(ds2=b->dh_derive(ctx2,dg2,dp3,dp3len,&ds2len)))(*err2)++;
		if(!(ds3=a->dh_derive(ctx1,dg3,dp2,dp2len,&ds3len)))(*err1)++;
		if(!(ds4=b->dh_derive(ctx2,dg4,dp1,dp1len,&ds4len)))(*err2)++;
		if(!ds1||!ds2||!ds3||!ds4)goto out;

		if(ds1len!=ds4len||memcmp(ds1,ds4,ds1len))(*err)++;
		if(ds2len!=ds3len||memcmp(ds2,ds3,ds2len))(*err)++;

		if(!(pe1=a->dh_to_pem(ctx1,gen1,gen1len,&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_dh(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=gen1len||memcmp(de1,gen1,de1len))(*err1)++;

		if(!(pe2=b->dh_to_pem(ctx2,gen2,gen2len,&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_dh(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=gen2len||memcmp(de2,gen2,de2len))(*err2)++;

cont:		if(gen1)free(gen1);
		if(gen2)free(gen2);
		if(dg1)a->dh_free(ctx1,dg1);
		if(dg2)b->dh_free(ctx2,dg2);
		if(dg3)a->dh_free(ctx1,dg3);
		if(dg4)b->dh_free(ctx2,dg4);
		if(dp1)free(dp1);
		if(dp2)free(dp2);
		if(dp3)free(dp3);
		if(dp4)free(dp4);
		if(ds1)free(ds1);
		if(ds2)free(ds2);
		if(ds3)free(ds3);
		if(ds4)free(ds4);
		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);
	}

out:	for(i=0;i<3;i++)
	{
		if(dh1[i])a->dh_free(ctx1,dh1[i]);
		if(dh2[i])b->dh_free(ctx2,dh2[i]);
		if(pub1[i])free(pub1[i]);
		if(pub2[i])free(pub2[i]);
		if(p81[i])free(p81[i]);
		if(p82[i])free(p82[i]);
		if(v81[i])free(v81[i]);
		if(v82[i])free(v82[i]);
		if(c81[i])free(c81[i]);
		if(c82[i])free(c82[i]);
	}
}

static int test_dh(void **ctx)
{
	int i;
	int j;
	int skip;
	int nogen;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0,skip=0;i<5;i++,skip=0)for(j=i+1;j<5;j++)
	{
#if LIBWOLFSSL_VERSION_HEX >= 0x03012002
		if(skip)nogen=1;
#else
		if(i==2||j==2||skip)nogen=1;
#endif
		else nogen=0;
		test_dh_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			&dhops[i],&dhops[j],nogen);
		if(!nogen&&!expensive)skip=1;
	}

	return printres("usicrypt_dh_...()",cerr,err);
}

static struct ecops
{
	void *(*ec_generate)(void *,int);
	int (*ec_identifier)(void *,void *);
	void *(*ec_derive)(void *,void *,void *,int *);
	void *(*ec_get_pub)(void *,void *,int *);
	void *(*ec_set_pub)(void *,void *,int);
	void *(*ec_get_key)(void *,void *,int *);
	void *(*ec_set_key)(void *,void *,int);
	void *(*ec_sign)(void *,int,void *,void *,int,int *);
	int (*ec_verify)(void *,int,void *,void *,int,void *,int);
	void *(*ec_sign_iov)(void *,int,void *,struct usicrypt_iov *,
		int,int *);
	int (*ec_verify_iov)(void *,int,void *,struct usicrypt_iov *,
		int,void *,int);
	void (*ec_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} ecops[5]=
{
	{
		xssl_ec_generate,xssl_ec_identifier,xssl_ec_derive,
		xssl_ec_get_pub,xssl_ec_set_pub,xssl_ec_get_key,xssl_ec_set_key,
		xssl_ec_sign,xssl_ec_verify,xssl_ec_sign_iov,xssl_ec_verify_iov,
		xssl_ec_free,xssl_encrypt_p8,xssl_decrypt_p8,xssl_p8_to_pem,
		xssl_pem_to_p8,
	},
	{
		mbed_ec_generate,mbed_ec_identifier,mbed_ec_derive,
		mbed_ec_get_pub,mbed_ec_set_pub,mbed_ec_get_key,mbed_ec_set_key,
		mbed_ec_sign,mbed_ec_verify,mbed_ec_sign_iov,mbed_ec_verify_iov,
		mbed_ec_free,mbed_encrypt_p8,mbed_decrypt_p8,mbed_p8_to_pem,
		mbed_pem_to_p8,
	},
	{
		wolf_ec_generate,wolf_ec_identifier,wolf_ec_derive,
		wolf_ec_get_pub,wolf_ec_set_pub,wolf_ec_get_key,wolf_ec_set_key,
		wolf_ec_sign,wolf_ec_verify,wolf_ec_sign_iov,wolf_ec_verify_iov,
		wolf_ec_free,wolf_encrypt_p8,wolf_decrypt_p8,wolf_p8_to_pem,
		wolf_pem_to_p8,
	},
	{
		gcry_ec_generate,gcry_ec_identifier,gcry_ec_derive,
		gcry_ec_get_pub,gcry_ec_set_pub,gcry_ec_get_key,gcry_ec_set_key,
		gcry_ec_sign,gcry_ec_verify,gcry_ec_sign_iov,gcry_ec_verify_iov,
		gcry_ec_free,gcry_encrypt_p8,gcry_decrypt_p8,gcry_p8_to_pem,
		gcry_pem_to_p8,
	},
	{
		nttl_ec_generate,nttl_ec_identifier,nttl_ec_derive,
		nttl_ec_get_pub,nttl_ec_set_pub,nttl_ec_get_key,nttl_ec_set_key,
		nttl_ec_sign,nttl_ec_verify,nttl_ec_sign_iov,nttl_ec_verify_iov,
		nttl_ec_free,nttl_encrypt_p8,nttl_decrypt_p8,nttl_p8_to_pem,
		nttl_pem_to_p8,
	},
};

static void test_ec_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	int imin,struct ecops *a,struct ecops *b)
{
	int i;
	int j;
	int k;
	int l;
	int m;
	int n;
	int p1;
	int p2;
	int p3;
	int p4;
	int bits;
	int id=-1;
	int md;
	int size;
	int em1;
	int em2;
	int dlen1;
	int dlen2;
	int slen;
	int elen;
	int dlen;
	int pe1len;
	int pe2len;
	int de1len;
	int de2len;
	int plen1[6];
	int plen2[6];
	int klen1[6];
	int klen2[6];
	void *sig;
	void *der1;
	void *der2;
	void *enc;
	void *dec;
	void *pe1;
	void *pe2;
	void *de1;
	void *de2;
	void *ec1[6];
	void *ec2[6];
	void *ec3[6];
	void *ec4[6];
	void *ec5[6];
	void *ec6[6];
	void *ec7[6];
	void *ec8[6];
	void *pub1[6];
	void *pub2[6];
	void *key1[6];
	void *key2[6];
	struct usicrypt_iov iov[3];
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];

	em1=*err1;
	em2=*err2;

	memset(ec1,0,sizeof(ec1));
	memset(ec2,0,sizeof(ec2));
	memset(ec3,0,sizeof(ec3));
	memset(ec4,0,sizeof(ec4));
	memset(ec5,0,sizeof(ec5));
	memset(ec6,0,sizeof(ec6));
	memset(ec7,0,sizeof(ec7));
	memset(ec8,0,sizeof(ec8));
	memset(pub1,0,sizeof(pub1));
	memset(pub2,0,sizeof(pub2));
	memset(key1,0,sizeof(key1));
	memset(key2,0,sizeof(key2));

	for(i=imin;i<6;i++)
	{
		switch(i)
		{
		case 0:	id=USICRYPT_BRAINPOOLP512R1;
			break;
		case 1:	id=USICRYPT_BRAINPOOLP384R1;
			break;
		case 2:	id=USICRYPT_BRAINPOOLP256R1;
			break;
		case 3:	id=USICRYPT_SECP521R1;
			break;
		case 4:	id=USICRYPT_SECP384R1;
			break;
		case 5:	id=USICRYPT_SECP256R1;
			break;
		}

		if(!(ec1[i]=a->ec_generate(ctx1,id)))(*err1)++;
		else if(id!=a->ec_identifier(ctx1,ec1[i]))(*err1)++;
		else if(!(pub1[i]=a->ec_get_pub(ctx1,ec1[i],&plen1[i])))
			(*err1)++;
		else if(!(key1[i]=a->ec_get_key(ctx1,ec1[i],&klen1[i])))
			(*err1)++;

		if(!(ec2[i]=b->ec_generate(ctx2,id)))(*err2)++;
		else if(id!=b->ec_identifier(ctx2,ec2[i]))(*err2)++;
		else if(!(pub2[i]=b->ec_get_pub(ctx2,ec2[i],&plen2[i])))
			(*err2)++;
		else if(!(key2[i]=b->ec_get_key(ctx2,ec2[i],&klen2[i])))
			(*err2)++;

		if(usicrypt_pub_type_from_p8(ctx1,pub1[i],plen1[i])!=id)
			(*err)++;
		if(usicrypt_pub_type_from_p8(ctx2,pub2[i],plen2[i])!=id)
			(*err)++;

		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_ec_key_to_p8(ctx1,key1[i],klen1[i],&elen)))
			(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=id)
			(*err)++;
		else if(!(dec=usicrypt_p8_to_ec_key(ctx1,enc,elen,&dlen)))
			(*err)++;
		else if(dlen!=klen1[i]||memcmp(key1[i],dec,dlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_ec_key_to_p8(ctx2,key2[i],klen2[i],&elen)))
			(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=id)
			(*err)++;
		else if(!(dec=usicrypt_p8_to_ec_key(ctx2,enc,elen,&dlen)))
			(*err)++;
		else if(dlen!=klen2[i]||memcmp(key2[i],dec,dlen))(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);
	}
	if(*err1!=em1||*err2!=em2)goto out;

	for(i=imin;i<6;i++)for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;
		if(!expensive&&n)continue;

		switch(j)
		{
		case 0:	p1=USICRYPT_SHA1;
			break;
		case 1:	p1=USICRYPT_SHA256;
			break;
		case 2:	p1=USICRYPT_SHA384;
			break;
		case 3:	p1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	p2=USICRYPT_AES;
			break;
		case 1:	p2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	p3=USICRYPT_ECB;
			break;
		case 1:	p3=USICRYPT_CBC;
			break;
		case 2:	p3=USICRYPT_CFB;
			break;
		case 3:	p3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	p4=1;
			break;
		case 1:	p4=0x7f;
			break;
		case 2:	p4=0x80;
			break;
		case 3:	p4=0x7fff;
			break;
		case 4:	p4=0x8000;
			break;
		}

		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;
		if(!(pe1=a->p8_to_pem(ctx1,pub1[i],plen1[i],&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=plen1[i]||memcmp(de1,pub1[i],de1len))(*err1)++;
		if(!(pe2=b->p8_to_pem(ctx2,pub2[i],plen2[i],&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=plen2[i]||memcmp(de2,pub2[i],de2len))(*err2)++;
		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);

		pe1=NULL;
		pe2=NULL;
		de1=NULL;
		de2=NULL;
		enc=NULL;
		dec=NULL;
		if(!(enc=usicrypt_ec_key_to_p8(ctx1,key1[i],klen1[i],&elen)))
			(*err)++;
		else if(!(pe1=a->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		if(!(dec=usicrypt_ec_key_to_p8(ctx2,key2[i],klen2[i],&dlen)))
			(*err)++;
		else if(!(pe2=b->p8_to_pem(ctx2,dec,dlen,&pe2len)))(*err2)++;
		else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=dlen||memcmp(de2,dec,de2len))(*err2)++;
		if(pe1)free(pe1);
		if(pe2)free(pe2);
		if(de1)free(de1);
		if(de2)free(de2);
		if(enc)free(enc);
		if(dec)free(dec);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe1=NULL;
		de1=NULL;
		if(!(sig=usicrypt_ec_key_to_p8(ctx1,key1[i],klen1[i],&slen)))
			(*err)++;
		else if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err1)++;
		else if(!(pe1=b->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=b->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe1)free(pe1);
		if(de1)free(de1);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe2=NULL;
		de2=NULL;
		if(!(sig=usicrypt_ec_key_to_p8(ctx2,key1[i],klen1[i],&slen)))
			(*err)++;
		else if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err2)++;
		else if(!(pe2=a->p8_to_pem(ctx2,enc,elen,&pe2len)))(*err2)++;
		else if(!(de2=a->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=elen||memcmp(de2,enc,de2len))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe2)free(pe2);
		if(de2)free(de2);
	}

	for(i=imin;i<6;i++)
	{
		if(!(ec3[i]=a->ec_set_pub(ctx1,pub2[i],plen2[i])))(*err1)++;
		if(!(ec7[i]=a->ec_set_pub(ctx1,pub1[i],plen1[i])))(*err1)++;
		if(!(ec5[i]=a->ec_set_key(ctx1,key2[i],klen2[i])))(*err1)++;

		if(!(ec4[i]=b->ec_set_pub(ctx2,pub1[i],plen1[i])))(*err2)++;
		if(!(ec8[i]=b->ec_set_pub(ctx2,pub2[i],plen2[i])))(*err2)++;
		if(!(ec6[i]=b->ec_set_key(ctx2,key1[i],klen1[i])))(*err2)++;
	}
	if(*err1!=em1||*err2!=em2)goto out;

	for(i=imin;i<6;i++)
	{
		for(j=0;j<4;j++)
		{
			switch(j)
			{
			case 0:	md=USICRYPT_SHA1;
				break;
			case 1:	md=USICRYPT_SHA256;
				break;
			case 2:	md=USICRYPT_SHA384;
				break;
			case 3:	md=USICRYPT_SHA512;
				break;
			}

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->ec_sign(ctx1,md,ec1[i],data,sizeof(data),
				&size)))(*err1)++;
			else if(b->ec_verify(ctx2,md,ec4[i],data,sizeof(data),
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->ec_sign(ctx2,md,ec2[i],data,sizeof(data),
				&size)))(*err2)++;
			else if(a->ec_verify(ctx1,md,ec3[i],data,sizeof(data),
				sig,size))(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->ec_sign(ctx1,md,ec5[i],data,sizeof(data),
				&size)))(*err1)++;
			else if(b->ec_verify(ctx2,md,ec2[i],data,sizeof(data),
				sig,size))(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->ec_sign(ctx2,md,ec6[i],data,sizeof(data),
				&size)))(*err2)++;
			else if(a->ec_verify(ctx1,md,ec1[i],data,sizeof(data),
				sig,size))(*err1)++;
			if(sig)free(sig);

			iov[0].data=data;
			iov[0].length=4;
			iov[1].data=data+4;
			iov[1].length=8;
			iov[2].data=data+12;
			iov[2].length=sizeof(data)-12;

			usicrypt_random(NULL,data,sizeof(data));

			sig=NULL;
			if(!(sig=a->ec_sign_iov(ctx1,md,ec1[i],iov,3,&size)))
				(*err1)++;
			else if(b->ec_verify_iov(ctx2,md,ec4[i],iov,3,sig,size))
				(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->ec_sign_iov(ctx2,md,ec2[i],iov,3,&size)))
				(*err2)++;
			else if(a->ec_verify_iov(ctx1,md,ec3[i],iov,3,sig,size))
				(*err1)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=a->ec_sign_iov(ctx1,md,ec5[i],iov,3,&size)))
				(*err1)++;
			else if(b->ec_verify_iov(ctx2,md,ec2[i],iov,3,sig,size))
				(*err2)++;
			if(sig)free(sig);

			sig=NULL;
			if(!(sig=b->ec_sign_iov(ctx2,md,ec6[i],iov,3,&size)))
				(*err2)++;
			else if(a->ec_verify_iov(ctx1,md,ec1[i],iov,3,sig,size))
				(*err1)++;
			if(sig)free(sig);
		}

		der1=NULL;
		der2=NULL;
		if(!(der1=a->ec_derive(ctx1,ec1[i],ec3[i],&dlen1)))(*err1)++;
		else if(!(der2=b->ec_derive(ctx2,ec2[i],ec4[i],&dlen2)))
			(*err2)++;
		else if(dlen1!=dlen2||memcmp(der1,der2,dlen1))(*err)++;
		if(der1)free(der1);
		if(der2)free(der2);
	}

out:	for(i=imin;i<6;i++)
	{
		if(ec1[i])a->ec_free(ctx1,ec1[i]);
		if(ec2[i])b->ec_free(ctx2,ec2[i]);
		if(ec3[i])a->ec_free(ctx1,ec3[i]);
		if(ec4[i])b->ec_free(ctx2,ec4[i]);
		if(ec5[i])a->ec_free(ctx1,ec5[i]);
		if(ec6[i])b->ec_free(ctx2,ec6[i]);
		if(ec7[i])a->ec_free(ctx1,ec7[i]);
		if(ec8[i])b->ec_free(ctx2,ec8[i]);
		if(pub1[i])free(pub1[i]);
		if(pub2[i])free(pub2[i]);
		if(key1[i])free(key1[i]);
		if(key2[i])free(key2[i]);
	}
}

static int test_ec(void **ctx)
{
	int i;
	int j;
	int x;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
		if(i==4||j==4)x=3;
		else x=0;
		test_ec_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],x,
			&ecops[i],&ecops[j]);
	}
	return printres("usicrypt_ec_...()",cerr,err);
}

static struct ed25519ops
{
	void *(*ed25519_generate)(void *);
	void *(*ed25519_get_pub)(void *,void *,int *);
	void *(*ed25519_set_pub)(void *,void *,int);
	void *(*ed25519_get_key)(void *,void *,int *);
	void *(*ed25519_set_key)(void *,void *,int);
	void *(*ed25519_sign)(void *,void *,void *,int,int *);
	int (*ed25519_verify)(void *,void *,void *,int,void *,int);
	void *(*ed25519_sign_iov)(void *,void *,struct usicrypt_iov *,
		int,int *);
	int (*ed25519_verify_iov)(void *,void *,struct usicrypt_iov *,
		int,void *,int);
	void (*ed25519_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} ed25519ops[5]=
{
#ifndef LIBRESSL_VERSION_NUMBER
	{
		xssl_ed25519_generate,xssl_ed25519_get_pub,xssl_ed25519_set_pub,
		xssl_ed25519_get_key,xssl_ed25519_set_key,xssl_ed25519_sign,
		xssl_ed25519_verify,xssl_ed25519_sign_iov,
		xssl_ed25519_verify_iov,xssl_ed25519_free,xssl_encrypt_p8,
		xssl_decrypt_p8,xssl_p8_to_pem,xssl_pem_to_p8,
	},
#else
	{
		orlp_ed25519_generate,orlp_ed25519_get_pub,orlp_ed25519_set_pub,
		orlp_ed25519_get_key,orlp_ed25519_set_key,orlp_ed25519_sign,
		orlp_ed25519_verify,orlp_ed25519_sign_iov,
		orlp_ed25519_verify_iov,orlp_ed25519_free,xssl_encrypt_p8,
		xssl_decrypt_p8,xssl_p8_to_pem,xssl_pem_to_p8,
	},
#endif
	{
		orlp_ed25519_generate,orlp_ed25519_get_pub,orlp_ed25519_set_pub,
		orlp_ed25519_get_key,orlp_ed25519_set_key,orlp_ed25519_sign,
		orlp_ed25519_verify,orlp_ed25519_sign_iov,
		orlp_ed25519_verify_iov,orlp_ed25519_free,mbed_encrypt_p8,
		mbed_decrypt_p8,mbed_p8_to_pem,mbed_pem_to_p8,
	},
	{
		wolf_ed25519_generate,wolf_ed25519_get_pub,wolf_ed25519_set_pub,
		wolf_ed25519_get_key,wolf_ed25519_set_key,wolf_ed25519_sign,
		wolf_ed25519_verify,wolf_ed25519_sign_iov,
		wolf_ed25519_verify_iov,wolf_ed25519_free,wolf_encrypt_p8,
		wolf_decrypt_p8,wolf_p8_to_pem,wolf_pem_to_p8,
	},
	{
		orlp_ed25519_generate,orlp_ed25519_get_pub,orlp_ed25519_set_pub,
		orlp_ed25519_get_key,orlp_ed25519_set_key,orlp_ed25519_sign,
		orlp_ed25519_verify,orlp_ed25519_sign_iov,
		orlp_ed25519_verify_iov,orlp_ed25519_free,gcry_encrypt_p8,
		gcry_decrypt_p8,gcry_p8_to_pem,gcry_pem_to_p8,
	},
	{
		nttl_ed25519_generate,nttl_ed25519_get_pub,nttl_ed25519_set_pub,
		nttl_ed25519_get_key,nttl_ed25519_set_key,nttl_ed25519_sign,
		nttl_ed25519_verify,nttl_ed25519_sign_iov,
		nttl_ed25519_verify_iov,nttl_ed25519_free,nttl_encrypt_p8,
		nttl_decrypt_p8,nttl_p8_to_pem,nttl_pem_to_p8,
	},
};

static void test_ed25519_pair(void *ctx1,void *ctx2,int *err,int *err1,
	int *err2,struct ed25519ops *a,struct ed25519ops *b)
{
	int j;
	int k;
	int l;
	int m;
	int n;
	int p1;
	int p2;
	int p3;
	int p4;
	int bits;
	int size;
	int em1;
	int em2;
	int slen;
	int elen;
	int dlen;
	int pe1len;
	int pe2len;
	int de1len;
	int de2len;
	int plen1;
	int plen2;
	int klen1;
	int klen2;
	void *sig;
	void *enc;
	void *dec;
	void *pe1;
	void *pe2;
	void *de1;
	void *de2;
	void *ed1=NULL;
	void *ed2=NULL;
	void *ed3=NULL;
	void *ed4=NULL;
	void *ed5=NULL;
	void *ed6=NULL;
	void *ed7=NULL;
	void *ed8=NULL;
	void *pub1=NULL;
	void *pub2=NULL;
	void *key1=NULL;
	void *key2=NULL;
	struct usicrypt_iov iov[3];
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];

	em1=*err1;
	em2=*err2;

	if(!(ed1=a->ed25519_generate(ctx1)))(*err1)++;
	else if(!(pub1=a->ed25519_get_pub(ctx1,ed1,&plen1)))(*err1)++;
	else if(!(key1=a->ed25519_get_key(ctx1,ed1,&klen1)))(*err1)++;

	if(!(ed2=b->ed25519_generate(ctx2)))(*err2)++;
	else if(!(pub2=b->ed25519_get_pub(ctx2,ed2,&plen2)))(*err2)++;
	else if(!(key2=b->ed25519_get_key(ctx2,ed2,&klen2)))(*err2)++;

	if(usicrypt_pub_type_from_p8(ctx1,pub1,plen1)!=USICRYPT_ED25519)
		(*err)++;
	if(usicrypt_pub_type_from_p8(ctx2,pub2,plen2)!=USICRYPT_ED25519)
		(*err)++;

	if(*err1!=em1||*err2!=em2)goto out;

	if(!(ed3=a->ed25519_set_pub(ctx1,pub2,plen2)))(*err1)++;
	if(!(ed7=a->ed25519_set_pub(ctx1,pub1,plen1)))(*err1)++;
	if(!(ed5=a->ed25519_set_key(ctx1,key2,klen2)))(*err1)++;

	if(!(ed4=b->ed25519_set_pub(ctx2,pub1,plen1)))(*err2)++;
	if(!(ed8=b->ed25519_set_pub(ctx2,pub2,plen2)))(*err2)++;
	if(!(ed6=b->ed25519_set_key(ctx2,key1,klen1)))(*err2)++;

	if(*err1!=em1||*err2!=em2)goto out;

	for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;

		switch(j)
		{
		case 0:	p1=USICRYPT_SHA1;
			break;
		case 1:	p1=USICRYPT_SHA256;
			break;
		case 2:	p1=USICRYPT_SHA384;
			break;
		case 3:	p1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	p2=USICRYPT_AES;
			break;
		case 1:	p2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	p3=USICRYPT_ECB;
			break;
		case 1:	p3=USICRYPT_CBC;
			break;
		case 2:	p3=USICRYPT_CFB;
			break;
		case 3:	p3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	p4=1;
			break;
		case 1:	p4=0x7f;
			break;
		case 2:	p4=0x80;
			break;
		case 3:	p4=0x7fff;
			break;
		case 4:	p4=0x8000;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe1=NULL;
		de1=NULL;
		if(!(sig=a->ed25519_get_key(ctx1,ed1,&slen)))(*err)++;
		else if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err1)++;
		else if(!(pe1=b->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=b->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe1)free(pe1);
		if(de1)free(de1);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe2=NULL;
		de2=NULL;
		if(!(sig=b->ed25519_get_key(ctx2,ed1,&slen)))(*err)++;
		else if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err2)++;
		else if(!(pe2=a->p8_to_pem(ctx2,enc,elen,&pe2len)))(*err2)++;
		else if(!(de2=a->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=elen||memcmp(de2,enc,de2len))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe2)free(pe2);
		if(de2)free(de2);
	}

	usicrypt_random(NULL,data,sizeof(data));

	sig=NULL;
	if(!(sig=a->ed25519_sign(ctx1,ed1,data,sizeof(data),&size)))(*err1)++;
	else if(b->ed25519_verify(ctx2,ed4,data,sizeof(data),sig,size))
		(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed25519_sign(ctx2,ed2,data,sizeof(data),&size)))(*err2)++;
	else if(a->ed25519_verify(ctx1,ed3,data,sizeof(data),sig,size))
		(*err1)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=a->ed25519_sign(ctx1,ed5,data,sizeof(data),&size)))(*err1)++;
	else if(b->ed25519_verify(ctx2,ed2,data,sizeof(data),sig,size))
		(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed25519_sign(ctx2,ed6,data,sizeof(data),&size)))(*err2)++;
	else if(a->ed25519_verify(ctx1,ed1,data,sizeof(data),sig,size))
		(*err1)++;
	if(sig)free(sig);

	iov[0].data=data;
	iov[0].length=4;
	iov[1].data=data+4;
	iov[1].length=8;
	iov[2].data=data+12;
	iov[2].length=sizeof(data)-12;

	usicrypt_random(NULL,data,sizeof(data));

	sig=NULL;
	if(!(sig=a->ed25519_sign_iov(ctx1,ed1,iov,3,&size)))(*err1)++;
	else if(b->ed25519_verify_iov(ctx2,ed4,iov,3,sig,size))(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed25519_sign_iov(ctx2,ed2,iov,3,&size)))(*err2)++;
	else if(a->ed25519_verify_iov(ctx1,ed3,iov,3,sig,size))(*err1)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=a->ed25519_sign_iov(ctx1,ed5,iov,3,&size)))(*err1)++;
	else if(b->ed25519_verify_iov(ctx2,ed2,iov,3,sig,size))(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed25519_sign_iov(ctx2,ed6,iov,3,&size)))(*err2)++;
	else if(a->ed25519_verify_iov(ctx1,ed1,iov,3,sig,size))(*err1)++;
	if(sig)free(sig);

out:	if(ed1)a->ed25519_free(ctx1,ed1);
	if(ed2)b->ed25519_free(ctx2,ed2);
	if(ed3)a->ed25519_free(ctx1,ed3);
	if(ed4)b->ed25519_free(ctx2,ed4);
	if(ed5)a->ed25519_free(ctx1,ed5);
	if(ed6)b->ed25519_free(ctx2,ed6);
	if(ed7)a->ed25519_free(ctx1,ed7);
	if(ed8)b->ed25519_free(ctx2,ed8);
	if(pub1)free(pub1);
	if(pub2)free(pub2);
	if(key1)free(key1);
	if(key2)free(key2);
}

static int test_ed25519(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
		test_ed25519_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			&ed25519ops[i],&ed25519ops[j]);
	}
	return printres("usicrypt_ed25519_...()",cerr,err);
}

static struct ed448ops
{
	void *(*ed448_generate)(void *);
	void *(*ed448_get_pub)(void *,void *,int *);
	void *(*ed448_set_pub)(void *,void *,int);
	void *(*ed448_get_key)(void *,void *,int *);
	void *(*ed448_set_key)(void *,void *,int);
	void *(*ed448_sign)(void *,void *,void *,int,int *);
	int (*ed448_verify)(void *,void *,void *,int,void *,int);
	void *(*ed448_sign_iov)(void *,void *,struct usicrypt_iov *,
		int,int *);
	int (*ed448_verify_iov)(void *,void *,struct usicrypt_iov *,
		int,void *,int);
	void (*ed448_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} ed448ops[5]=
{
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
	{
		xssl_ed448_generate,xssl_ed448_get_pub,xssl_ed448_set_pub,
		xssl_ed448_get_key,xssl_ed448_set_key,xssl_ed448_sign,
		xssl_ed448_verify,xssl_ed448_sign_iov,
		xssl_ed448_verify_iov,xssl_ed448_free,xssl_encrypt_p8,
		xssl_decrypt_p8,xssl_p8_to_pem,xssl_pem_to_p8,
	},
#else
	{
		dcaf_ed448_generate,dcaf_ed448_get_pub,dcaf_ed448_set_pub,
		dcaf_ed448_get_key,dcaf_ed448_set_key,dcaf_ed448_sign,
		dcaf_ed448_verify,dcaf_ed448_sign_iov,
		dcaf_ed448_verify_iov,dcaf_ed448_free,xssl_encrypt_p8,
		xssl_decrypt_p8,xssl_p8_to_pem,xssl_pem_to_p8,
	},
#endif
	{
		dcaf_ed448_generate,dcaf_ed448_get_pub,dcaf_ed448_set_pub,
		dcaf_ed448_get_key,dcaf_ed448_set_key,dcaf_ed448_sign,
		dcaf_ed448_verify,dcaf_ed448_sign_iov,
		dcaf_ed448_verify_iov,dcaf_ed448_free,mbed_encrypt_p8,
		mbed_decrypt_p8,mbed_p8_to_pem,mbed_pem_to_p8,
	},
#if LIBWOLFSSL_VERSION_HEX >= 0x04004000
	{
		wolf_ed448_generate,wolf_ed448_get_pub,wolf_ed448_set_pub,
		wolf_ed448_get_key,wolf_ed448_set_key,wolf_ed448_sign,
		wolf_ed448_verify,wolf_ed448_sign_iov,
		wolf_ed448_verify_iov,wolf_ed448_free,wolf_encrypt_p8,
		wolf_decrypt_p8,wolf_p8_to_pem,wolf_pem_to_p8,
	},
#else
	{
		dcaf_ed448_generate,dcaf_ed448_get_pub,dcaf_ed448_set_pub,
		dcaf_ed448_get_key,dcaf_ed448_set_key,dcaf_ed448_sign,
		dcaf_ed448_verify,dcaf_ed448_sign_iov,
		dcaf_ed448_verify_iov,dcaf_ed448_free,wolf_encrypt_p8,
		wolf_decrypt_p8,wolf_p8_to_pem,wolf_pem_to_p8,
	},
#endif
	{
		dcaf_ed448_generate,dcaf_ed448_get_pub,dcaf_ed448_set_pub,
		dcaf_ed448_get_key,dcaf_ed448_set_key,dcaf_ed448_sign,
		dcaf_ed448_verify,dcaf_ed448_sign_iov,
		dcaf_ed448_verify_iov,dcaf_ed448_free,gcry_encrypt_p8,
		gcry_decrypt_p8,gcry_p8_to_pem,gcry_pem_to_p8,
	},
#if NETTLE_VERSION_MAJOR > 3 || \
	( NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 6 )
	{
		nttl_ed448_generate,nttl_ed448_get_pub,nttl_ed448_set_pub,
		nttl_ed448_get_key,nttl_ed448_set_key,nttl_ed448_sign,
		nttl_ed448_verify,nttl_ed448_sign_iov,
		nttl_ed448_verify_iov,nttl_ed448_free,nttl_encrypt_p8,
		nttl_decrypt_p8,nttl_p8_to_pem,nttl_pem_to_p8,
	},
#else
	{
		dcaf_ed448_generate,dcaf_ed448_get_pub,dcaf_ed448_set_pub,
		dcaf_ed448_get_key,dcaf_ed448_set_key,dcaf_ed448_sign,
		dcaf_ed448_verify,dcaf_ed448_sign_iov,
		dcaf_ed448_verify_iov,dcaf_ed448_free,nttl_encrypt_p8,
		nttl_decrypt_p8,nttl_p8_to_pem,nttl_pem_to_p8,
	},
#endif
};

static void test_ed448_pair(void *ctx1,void *ctx2,int *err,int *err1,
	int *err2,struct ed448ops *a,struct ed448ops *b)
{
	int j;
	int k;
	int l;
	int m;
	int n;
	int p1;
	int p2;
	int p3;
	int p4;
	int bits;
	int size;
	int em1;
	int em2;
	int slen;
	int elen;
	int dlen;
	int pe1len;
	int pe2len;
	int de1len;
	int de2len;
	int plen1;
	int plen2;
	int klen1;
	int klen2;
	void *sig;
	void *enc;
	void *dec;
	void *pe1;
	void *pe2;
	void *de1;
	void *de2;
	void *ed1=NULL;
	void *ed2=NULL;
	void *ed3=NULL;
	void *ed4=NULL;
	void *ed5=NULL;
	void *ed6=NULL;
	void *ed7=NULL;
	void *ed8=NULL;
	void *pub1=NULL;
	void *pub2=NULL;
	void *key1=NULL;
	void *key2=NULL;
	struct usicrypt_iov iov[3];
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];

	em1=*err1;
	em2=*err2;

	if(!(ed1=a->ed448_generate(ctx1)))(*err1)++;
	else if(!(pub1=a->ed448_get_pub(ctx1,ed1,&plen1)))(*err1)++;
	else if(!(key1=a->ed448_get_key(ctx1,ed1,&klen1)))(*err1)++;

	if(!(ed2=b->ed448_generate(ctx2)))(*err2)++;
	else if(!(pub2=b->ed448_get_pub(ctx2,ed2,&plen2)))(*err2)++;
	else if(!(key2=b->ed448_get_key(ctx2,ed2,&klen2)))(*err2)++;

	if(usicrypt_pub_type_from_p8(ctx1,pub1,plen1)!=USICRYPT_ED448)
		(*err)++;
	if(usicrypt_pub_type_from_p8(ctx2,pub2,plen2)!=USICRYPT_ED448)
		(*err)++;

	if(*err1!=em1||*err2!=em2)goto out;

	if(!(ed3=a->ed448_set_pub(ctx1,pub2,plen2)))(*err1)++;
	if(!(ed7=a->ed448_set_pub(ctx1,pub1,plen1)))(*err1)++;
	if(!(ed5=a->ed448_set_key(ctx1,key2,klen2)))(*err1)++;

	if(!(ed4=b->ed448_set_pub(ctx2,pub1,plen1)))(*err2)++;
	if(!(ed8=b->ed448_set_pub(ctx2,pub2,plen2)))(*err2)++;
	if(!(ed6=b->ed448_set_key(ctx2,key1,klen1)))(*err2)++;

	if(*err1!=em1||*err2!=em2)goto out;

	for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;

		switch(j)
		{
		case 0:	p1=USICRYPT_SHA1;
			break;
		case 1:	p1=USICRYPT_SHA256;
			break;
		case 2:	p1=USICRYPT_SHA384;
			break;
		case 3:	p1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	p2=USICRYPT_AES;
			break;
		case 1:	p2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	p3=USICRYPT_ECB;
			break;
		case 1:	p3=USICRYPT_CBC;
			break;
		case 2:	p3=USICRYPT_CFB;
			break;
		case 3:	p3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	p4=1;
			break;
		case 1:	p4=0x7f;
			break;
		case 2:	p4=0x80;
			break;
		case 3:	p4=0x7fff;
			break;
		case 4:	p4=0x8000;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe1=NULL;
		de1=NULL;
		if(!(sig=a->ed448_get_key(ctx1,ed1,&slen)))(*err)++;
		else if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err1)++;
		else if(!(pe1=b->p8_to_pem(ctx1,enc,elen,&pe1len)))(*err1)++;
		else if(!(de1=b->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
		else if(de1len!=elen||memcmp(de1,enc,de1len))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe1)free(pe1);
		if(de1)free(de1);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		sig=NULL;
		enc=NULL;
		dec=NULL;
		pe2=NULL;
		de2=NULL;
		if(!(sig=b->ed448_get_key(ctx2,ed1,&slen)))(*err)++;
		else if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),sig,slen,
			p2,p3,bits,p1,p4,&elen)))(*err2)++;
		else if(!(pe2=a->p8_to_pem(ctx2,enc,elen,&pe2len)))(*err2)++;
		else if(!(de2=a->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
		else if(de2len!=elen||memcmp(de2,enc,de2len))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(slen!=dlen||memcmp(sig,dec,slen))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(sig)free(sig);
		if(enc)free(enc);
		if(dec)free(dec);
		if(pe2)free(pe2);
		if(de2)free(de2);
	}

	usicrypt_random(NULL,data,sizeof(data));

	sig=NULL;
	if(!(sig=a->ed448_sign(ctx1,ed1,data,sizeof(data),&size)))(*err1)++;
	else if(b->ed448_verify(ctx2,ed4,data,sizeof(data),sig,size))
		(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed448_sign(ctx2,ed2,data,sizeof(data),&size)))(*err2)++;
	else if(a->ed448_verify(ctx1,ed3,data,sizeof(data),sig,size))
		(*err1)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=a->ed448_sign(ctx1,ed5,data,sizeof(data),&size)))(*err1)++;
	else if(b->ed448_verify(ctx2,ed2,data,sizeof(data),sig,size))
		(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed448_sign(ctx2,ed6,data,sizeof(data),&size)))(*err2)++;
	else if(a->ed448_verify(ctx1,ed1,data,sizeof(data),sig,size))
		(*err1)++;
	if(sig)free(sig);

	iov[0].data=data;
	iov[0].length=4;
	iov[1].data=data+4;
	iov[1].length=8;
	iov[2].data=data+12;
	iov[2].length=sizeof(data)-12;

	usicrypt_random(NULL,data,sizeof(data));

	sig=NULL;
	if(!(sig=a->ed448_sign_iov(ctx1,ed1,iov,3,&size)))(*err1)++;
	else if(b->ed448_verify_iov(ctx2,ed4,iov,3,sig,size))(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed448_sign_iov(ctx2,ed2,iov,3,&size)))(*err2)++;
	else if(a->ed448_verify_iov(ctx1,ed3,iov,3,sig,size))(*err1)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=a->ed448_sign_iov(ctx1,ed5,iov,3,&size)))(*err1)++;
	else if(b->ed448_verify_iov(ctx2,ed2,iov,3,sig,size))(*err2)++;
	if(sig)free(sig);

	sig=NULL;
	if(!(sig=b->ed448_sign_iov(ctx2,ed6,iov,3,&size)))(*err2)++;
	else if(a->ed448_verify_iov(ctx1,ed1,iov,3,sig,size))(*err1)++;
	if(sig)free(sig);

out:	if(ed1)a->ed448_free(ctx1,ed1);
	if(ed2)b->ed448_free(ctx2,ed2);
	if(ed3)a->ed448_free(ctx1,ed3);
	if(ed4)b->ed448_free(ctx2,ed4);
	if(ed5)a->ed448_free(ctx1,ed5);
	if(ed6)b->ed448_free(ctx2,ed6);
	if(ed7)a->ed448_free(ctx1,ed7);
	if(ed8)b->ed448_free(ctx2,ed8);
	if(pub1)free(pub1);
	if(pub2)free(pub2);
	if(key1)free(key1);
	if(key2)free(key2);
}

static int test_ed448(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
		test_ed448_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			&ed448ops[i],&ed448ops[j]);
	}
	return printres("usicrypt_ed448_...()",cerr,err);
}

static struct x25519ops
{
	void *(*x25519_generate)(void *);
	void *(*x25519_derive)(void *,void *,void *,int *);
	void *(*x25519_get_pub)(void *,void *,int *);
	void *(*x25519_set_pub)(void *,void *,int);
	void *(*x25519_get_key)(void *,void *,int *);
	void *(*x25519_set_key)(void *,void *,int);
	void (*x25519_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} x25519ops[5]=
{
	{
		xssl_x25519_generate,xssl_x25519_derive,xssl_x25519_get_pub,
		xssl_x25519_set_pub,xssl_x25519_get_key,xssl_x25519_set_key,
		xssl_x25519_free,xssl_encrypt_p8,xssl_decrypt_p8,
		xssl_p8_to_pem,xssl_pem_to_p8,
	},
	{
		mbed_x25519_generate,mbed_x25519_derive,mbed_x25519_get_pub,
		mbed_x25519_set_pub,mbed_x25519_get_key,mbed_x25519_set_key,
		mbed_x25519_free,mbed_encrypt_p8,mbed_decrypt_p8,
		mbed_p8_to_pem,mbed_pem_to_p8,
	},
	{
		wolf_x25519_generate,wolf_x25519_derive,wolf_x25519_get_pub,
		wolf_x25519_set_pub,wolf_x25519_get_key,wolf_x25519_set_key,
		wolf_x25519_free,wolf_encrypt_p8,wolf_decrypt_p8,
		wolf_p8_to_pem,wolf_pem_to_p8,
	},
	{
		gcry_x25519_generate,gcry_x25519_derive,gcry_x25519_get_pub,
		gcry_x25519_set_pub,gcry_x25519_get_key,gcry_x25519_set_key,
		gcry_x25519_free,gcry_encrypt_p8,gcry_decrypt_p8,
		gcry_p8_to_pem,gcry_pem_to_p8,
	},
	{
		nttl_x25519_generate,nttl_x25519_derive,nttl_x25519_get_pub,
		nttl_x25519_set_pub,nttl_x25519_get_key,nttl_x25519_set_key,
		nttl_x25519_free,nttl_encrypt_p8,nttl_decrypt_p8,
		nttl_p8_to_pem,nttl_pem_to_p8,
	},
};

static void test_x25519_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct x25519ops *a,struct x25519ops *b)
{
	int j;
	int k;
	int l;
	int m;
	int n;
	int pr1;
	int pr2;
	int pr3;
	int pr4;
	int bits;
	int em1;
	int em2;
	int elen;
	int dlen;
	int plen1;
	int plen2;
	int plen3;
	int plen4;
	int klen1;
	int klen2;
	int rlen1;
	int rlen2;
	int rlen3;
	int rlen4;
	int pe1len;
	int pe2len;
	int pe3len;
	int pe4len;
	int de1len;
	int de2len;
	int de3len;
	int de4len;
	void *enc;
	void *dec;
	void *x1;
	void *x2;
	void *x3;
	void *x4;
	void *pub1;
	void *pub2;
	void *pub3;
	void *pub4;
	void *p1;
	void *p2;
	void *k1;
	void *k2;
	void *r1;
	void *r2;
	void *r3;
	void *r4;
	void *pe1;
	void *pe2;
	void *pe3;
	void *pe4;
	void *de1;
	void *de2;
	void *de3;
	void *de4;
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];

	em1=*err1;
	em2=*err2;

	k1=NULL;
	k2=NULL;
	x3=NULL;
	x4=NULL;
	pub1=NULL;
	pub2=NULL;
	pub3=NULL;
	pub4=NULL;
	p1=NULL;
	p2=NULL;
	r1=NULL;
	r2=NULL;
	r3=NULL;
	r4=NULL;
	pe1=NULL;
	pe2=NULL;
	pe3=NULL;
	pe4=NULL;
	de1=NULL;
	de2=NULL;
	de3=NULL;
	de4=NULL;

	if(!(x1=a->x25519_generate(ctx1)))(*err1)++;
	else if(!(pub1=a->x25519_get_pub(ctx1,x1,&plen1)))(*err1)++;
	else if(usicrypt_pub_type_from_p8(ctx1,pub1,plen1)!=USICRYPT_X25519)
		(*err)++;
	if(!(x2=b->x25519_generate(ctx2)))(*err2)++;
	else if(!(pub2=b->x25519_get_pub(ctx2,x2,&plen2)))(*err2)++;
	else if(usicrypt_pub_type_from_p8(ctx2,pub2,plen2)!=USICRYPT_X25519)
		(*err)++;
	if(*err1!=em1||*err2!=em2)goto out;

	if(!(k1=a->x25519_get_key(ctx1,x1,&klen1)))(*err1)++;
	else if(usicrypt_key_type_from_p8(ctx1,k1,klen1)!=USICRYPT_X25519)
		(*err)++;
	else if(!(x3=a->x25519_set_key(ctx1,k1,klen1)))(*err1)++;
	else if(!(pub3=a->x25519_get_pub(ctx1,x3,&plen3)))(*err1)++;
	else if(plen1!=plen3||memcmp(pub1,pub3,plen1))(*err1)++;
	if(!(k2=b->x25519_get_key(ctx2,x2,&klen2)))(*err2)++;
	else if(usicrypt_key_type_from_p8(ctx2,k2,klen2)!=USICRYPT_X25519)
		(*err)++;
	else if(!(x4=b->x25519_set_key(ctx2,k2,klen2)))(*err2)++;
	else if(!(pub4=b->x25519_get_pub(ctx2,x4,&plen4)))(*err2)++;
	else if(plen2!=plen4||memcmp(pub2,pub4,plen2))(*err2)++;

	if(k1)free(k1);
	if(k2)free(k2);
	if(!(k1=a->x25519_get_key(ctx1,x1,&klen1)))(*err1)++;
	if(!(k2=b->x25519_get_key(ctx2,x2,&klen2)))(*err2)++;

	if(!(pe1=a->p8_to_pem(ctx1,pub1,plen1,&pe1len)))(*err1)++;
	else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
	else if(de1len!=plen1||memcmp(de1,pub1,de1len))(*err1)++;
	if(!(pe2=b->p8_to_pem(ctx2,pub2,plen2,&pe2len)))(*err2)++;
	else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
	else if(de2len!=plen2||memcmp(de2,pub2,de2len))(*err2)++;

	if(!(pe3=a->p8_to_pem(ctx1,k1,klen1,&pe3len)))(*err1)++;
	else if(!(de3=a->pem_to_p8(ctx1,pe3,pe3len,&de3len)))(*err1)++;
	else if(de3len!=klen1||memcmp(de3,k1,de3len))(*err1)++;
	if(!(pe4=b->p8_to_pem(ctx2,k2,klen2,&pe4len)))(*err2)++;
	else if(!(de4=b->pem_to_p8(ctx2,pe4,pe4len,&de4len)))(*err2)++;
	else if(de4len!=klen2||memcmp(de4,k2,de4len))(*err2)++;

	if(!(p1=a->x25519_set_pub(ctx1,pub2,plen2)))(*err1)++;
	if(!(p2=b->x25519_set_pub(ctx2,pub1,plen1)))(*err2)++;
	if(*err1!=em1||*err2!=em2)goto out;

	if(!(r1=a->x25519_derive(ctx1,x1,p1,&rlen1)))(*err1)++;
	else if(!(r2=b->x25519_derive(ctx2,x2,p2,&rlen2)))(*err2)++;
	else if(!(r3=a->x25519_derive(ctx1,x3,p1,&rlen3)))(*err1)++;
	else if(!(r4=b->x25519_derive(ctx2,x4,p2,&rlen4)))(*err2)++;
	else if(rlen1!=rlen2||memcmp(r1,r2,rlen1))(*err)++;
	else if(rlen2!=rlen3||memcmp(r2,r3,rlen3))(*err)++;
	else if(rlen3!=rlen4||memcmp(r3,r4,rlen3))(*err)++;

	if(k1&&k2)for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;
		if(!expensive&&n)continue;

		switch(j)
		{
		case 0:	pr1=USICRYPT_SHA1;
			break;
		case 1:	pr1=USICRYPT_SHA256;
			break;
		case 2:	pr1=USICRYPT_SHA384;
			break;
		case 3:	pr1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	pr2=USICRYPT_AES;
			break;
		case 1:	pr2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	pr3=USICRYPT_ECB;
			break;
		case 1:	pr3=USICRYPT_CBC;
			break;
		case 2:	pr3=USICRYPT_CFB;
			break;
		case 3:	pr3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	pr4=1;
			break;
		case 1:	pr4=0x7f;
			break;
		case 2:	pr4=0x80;
			break;
		case 3:	pr4=0x7fff;
			break;
		case 4:	pr4=0x8000;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		enc=NULL;
		dec=NULL;
		if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),k1,klen1,
			pr2,pr3,bits,pr1,pr4,&elen)))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(klen1!=dlen||memcmp(k1,dec,klen1))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		enc=NULL;
		dec=NULL;
		if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),k2,klen2,
			pr2,pr3,bits,pr1,pr4,&elen)))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(klen2!=dlen||memcmp(k2,dec,klen2))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);
	}

out:	if(x1)a->x25519_free(ctx1,x1);
	if(x2)b->x25519_free(ctx2,x2);
	if(x3)a->x25519_free(ctx1,x3);
	if(x4)b->x25519_free(ctx2,x4);
	if(p1)a->x25519_free(ctx1,p1);
	if(p2)b->x25519_free(ctx2,p2);
	if(pub1)free(pub1);
	if(pub2)free(pub2);
	if(pub3)free(pub3);
	if(pub4)free(pub4);
	if(k1)free(k1);
	if(k2)free(k2);
	if(r1)free(r1);
	if(r2)free(r2);
	if(r3)free(r3);
	if(r4)free(r4);
	if(pe1)free(pe1);
	if(pe2)free(pe2);
	if(pe3)free(pe3);
	if(pe4)free(pe4);
	if(de1)free(de1);
	if(de2)free(de2);
	if(de3)free(de3);
	if(de4)free(de4);
}

static int test_x25519(void **ctx)
{
	int i;
	int j;
	int x;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
#if ( defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20500000L ) || ( !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L )
		x=1;
#else
		if(i==0||j==0)x=0;
		else x=1;
#endif
#if MBEDTLS_VERSION_NUMBER < 0x02050000
		if(i==1||j==1)x=0;
#endif
		if(x)test_x25519_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			&x25519ops[i],&x25519ops[j]);
	}
	return printres("usicrypt_x25519_...:()",cerr,err);
}

static struct x448ops
{
	void *(*x448_generate)(void *);
	void *(*x448_derive)(void *,void *,void *,int *);
	void *(*x448_get_pub)(void *,void *,int *);
	void *(*x448_set_pub)(void *,void *,int);
	void *(*x448_get_key)(void *,void *,int *);
	void *(*x448_set_key)(void *,void *,int);
	void (*x448_free)(void *,void *);
	void *(*encrypt_p8)(void *,void *,int,void *,int,int,int,int,int,int,
		int *);
	void *(*decrypt_p8)(void *,void *,int,void *,int,int *);
	void *(*p8_to_pem)(void *,void *,int,int *);
	void *(*pem_to_p8)(void *,void *,int,int *);
} x448ops[5]=
{
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L
	{
		xssl_x448_generate,xssl_x448_derive,xssl_x448_get_pub,
		xssl_x448_set_pub,xssl_x448_get_key,xssl_x448_set_key,
		xssl_x448_free,xssl_encrypt_p8,xssl_decrypt_p8,
		xssl_p8_to_pem,xssl_pem_to_p8,
	},
#else
	{
		dcaf_x448_generate,dcaf_x448_derive,dcaf_x448_get_pub,
		dcaf_x448_set_pub,dcaf_x448_get_key,dcaf_x448_set_key,
		dcaf_x448_free,xssl_encrypt_p8,xssl_decrypt_p8,
		xssl_p8_to_pem,xssl_pem_to_p8,
	},
#endif
#if MBEDTLS_VERSION_NUMBER >= 0x02090000
	{
		mbed_x448_generate,mbed_x448_derive,mbed_x448_get_pub,
		mbed_x448_set_pub,mbed_x448_get_key,mbed_x448_set_key,
		mbed_x448_free,mbed_encrypt_p8,mbed_decrypt_p8,
		mbed_p8_to_pem,mbed_pem_to_p8,
	},
#else
	{
		dcaf_x448_generate,dcaf_x448_derive,dcaf_x448_get_pub,
		dcaf_x448_set_pub,dcaf_x448_get_key,dcaf_x448_set_key,
		dcaf_x448_free,mbed_encrypt_p8,mbed_decrypt_p8,
		mbed_p8_to_pem,mbed_pem_to_p8,
	},
#endif
#if LIBWOLFSSL_VERSION_HEX >= 0x04004000
	{
		wolf_x448_generate,wolf_x448_derive,wolf_x448_get_pub,
		wolf_x448_set_pub,wolf_x448_get_key,wolf_x448_set_key,
		wolf_x448_free,wolf_encrypt_p8,wolf_decrypt_p8,
		wolf_p8_to_pem,wolf_pem_to_p8,
	},
#else
	{
		dcaf_x448_generate,dcaf_x448_derive,dcaf_x448_get_pub,
		dcaf_x448_set_pub,dcaf_x448_get_key,dcaf_x448_set_key,
		dcaf_x448_free,wolf_encrypt_p8,wolf_decrypt_p8,
		wolf_p8_to_pem,wolf_pem_to_p8,
	},
#endif
	{
		dcaf_x448_generate,dcaf_x448_derive,dcaf_x448_get_pub,
		dcaf_x448_set_pub,dcaf_x448_get_key,dcaf_x448_set_key,
		dcaf_x448_free,gcry_encrypt_p8,gcry_decrypt_p8,
		gcry_p8_to_pem,gcry_pem_to_p8,
	},
#if NETTLE_VERSION_MAJOR > 3 || \
	( NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR >= 6 )
	{
		nttl_x448_generate,nttl_x448_derive,nttl_x448_get_pub,
		nttl_x448_set_pub,nttl_x448_get_key,nttl_x448_set_key,
		nttl_x448_free,nttl_encrypt_p8,nttl_decrypt_p8,
		nttl_p8_to_pem,nttl_pem_to_p8,
	},
#else
	{
		dcaf_x448_generate,dcaf_x448_derive,dcaf_x448_get_pub,
		dcaf_x448_set_pub,dcaf_x448_get_key,dcaf_x448_set_key,
		dcaf_x448_free,nttl_encrypt_p8,nttl_decrypt_p8,
		nttl_p8_to_pem,nttl_pem_to_p8,
	},
#endif
};

static void test_x448_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct x448ops *a,struct x448ops *b)
{
	int j;
	int k;
	int l;
	int m;
	int n;
	int pr1;
	int pr2;
	int pr3;
	int pr4;
	int bits;
	int em1;
	int em2;
	int elen;
	int dlen;
	int plen1;
	int plen2;
	int plen3;
	int plen4;
	int klen1;
	int klen2;
	int rlen1;
	int rlen2;
	int rlen3;
	int rlen4;
	int pe1len;
	int pe2len;
	int pe3len;
	int pe4len;
	int de1len;
	int de2len;
	int de3len;
	int de4len;
	void *enc;
	void *dec;
	void *x1;
	void *x2;
	void *x3;
	void *x4;
	void *pub1;
	void *pub2;
	void *pub3;
	void *pub4;
	void *p1;
	void *p2;
	void *k1;
	void *k2;
	void *r1;
	void *r2;
	void *r3;
	void *r4;
	void *pe1;
	void *pe2;
	void *pe3;
	void *pe4;
	void *de1;
	void *de2;
	void *de3;
	void *de4;
	unsigned char data[32];
	unsigned char data1[32];
	unsigned char data2[32];

	em1=*err1;
	em2=*err2;

	k1=NULL;
	k2=NULL;
	x3=NULL;
	x4=NULL;
	pub1=NULL;
	pub2=NULL;
	pub3=NULL;
	pub4=NULL;
	p1=NULL;
	p2=NULL;
	r1=NULL;
	r2=NULL;
	r3=NULL;
	r4=NULL;
	pe1=NULL;
	pe2=NULL;
	pe3=NULL;
	pe4=NULL;
	de1=NULL;
	de2=NULL;
	de3=NULL;
	de4=NULL;

	if(!(x1=a->x448_generate(ctx1)))(*err1)++;
	else if(!(pub1=a->x448_get_pub(ctx1,x1,&plen1)))(*err1)++;
	else if(usicrypt_pub_type_from_p8(ctx1,pub1,plen1)!=USICRYPT_X448)
		(*err)++;
	if(!(x2=b->x448_generate(ctx2)))(*err2)++;
	else if(!(pub2=b->x448_get_pub(ctx2,x2,&plen2)))(*err2)++;
	else if(usicrypt_pub_type_from_p8(ctx2,pub2,plen2)!=USICRYPT_X448)
		(*err)++;
	if(*err1!=em1||*err2!=em2)goto out;

	if(!(k1=a->x448_get_key(ctx1,x1,&klen1)))(*err1)++;
	else if(usicrypt_key_type_from_p8(ctx1,k1,klen1)!=USICRYPT_X448)
		(*err)++;
	else if(!(x3=a->x448_set_key(ctx1,k1,klen1)))(*err1)++;
	else if(!(pub3=a->x448_get_pub(ctx1,x3,&plen3)))(*err1)++;
	else if(plen1!=plen3||memcmp(pub1,pub3,plen1))(*err1)++;
	if(!(k2=b->x448_get_key(ctx2,x2,&klen2)))(*err2)++;
	else if(usicrypt_key_type_from_p8(ctx2,k2,klen2)!=USICRYPT_X448)
		(*err)++;
	else if(!(x4=b->x448_set_key(ctx2,k2,klen2)))(*err2)++;
	else if(!(pub4=b->x448_get_pub(ctx2,x4,&plen4)))(*err2)++;
	else if(plen2!=plen4||memcmp(pub2,pub4,plen2))(*err2)++;

	if(k1)free(k1);
	if(k2)free(k2);
	if(!(k1=a->x448_get_key(ctx1,x1,&klen1)))(*err1)++;
	if(!(k2=b->x448_get_key(ctx2,x2,&klen2)))(*err2)++;

	if(!(pe1=a->p8_to_pem(ctx1,pub1,plen1,&pe1len)))(*err1)++;
	else if(!(de1=a->pem_to_p8(ctx1,pe1,pe1len,&de1len)))(*err1)++;
	else if(de1len!=plen1||memcmp(de1,pub1,de1len))(*err1)++;
	if(!(pe2=b->p8_to_pem(ctx2,pub2,plen2,&pe2len)))(*err2)++;
	else if(!(de2=b->pem_to_p8(ctx2,pe2,pe2len,&de2len)))(*err2)++;
	else if(de2len!=plen2||memcmp(de2,pub2,de2len))(*err2)++;

	if(!(pe3=a->p8_to_pem(ctx1,k1,klen1,&pe3len)))(*err1)++;
	else if(!(de3=a->pem_to_p8(ctx1,pe3,pe3len,&de3len)))(*err1)++;
	else if(de3len!=klen1||memcmp(de3,k1,de3len))(*err1)++;
	if(!(pe4=b->p8_to_pem(ctx2,k2,klen2,&pe4len)))(*err2)++;
	else if(!(de4=b->pem_to_p8(ctx2,pe4,pe4len,&de4len)))(*err2)++;
	else if(de4len!=klen2||memcmp(de4,k2,de4len))(*err2)++;

	if(!(p1=a->x448_set_pub(ctx1,pub2,plen2)))(*err1)++;
	if(!(p2=b->x448_set_pub(ctx2,pub1,plen1)))(*err2)++;
	if(*err1!=em1||*err2!=em2)goto out;

	if(!(r1=a->x448_derive(ctx1,x1,p1,&rlen1)))(*err1)++;
	else if(!(r2=b->x448_derive(ctx2,x2,p2,&rlen2)))(*err2)++;
	else if(!(r3=a->x448_derive(ctx1,x3,p1,&rlen3)))(*err1)++;
	else if(!(r4=b->x448_derive(ctx2,x4,p2,&rlen4)))(*err2)++;
	else if(rlen1!=rlen2||memcmp(r1,r2,rlen1))(*err)++;
	else if(rlen2!=rlen3||memcmp(r2,r3,rlen3))(*err)++;
	else if(rlen3!=rlen4||memcmp(r3,r4,rlen3))(*err)++;

	if(k1&&k2)for(j=0;j<4;j++)for(k=0;k<2;k++)for(l=0;l<3;l++)
		for(m=0;m<4;m++)for(n=0;n<5;n++)
	{
		if(!j&&l)continue;
		if(!expensive&&n)continue;

		switch(j)
		{
		case 0:	pr1=USICRYPT_SHA1;
			break;
		case 1:	pr1=USICRYPT_SHA256;
			break;
		case 2:	pr1=USICRYPT_SHA384;
			break;
		case 3:	pr1=USICRYPT_SHA512;
			break;
		}

		switch(k)
		{
		case 0:	pr2=USICRYPT_AES;
			break;
		case 1:	pr2=USICRYPT_CAMELLIA;
			break;
		}

		switch(l)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(m)
		{
		case 0:	pr3=USICRYPT_ECB;
			break;
		case 1:	pr3=USICRYPT_CBC;
			break;
		case 2:	pr3=USICRYPT_CFB;
			break;
		case 3:	pr3=USICRYPT_OFB;
			break;
		}

		switch(n)
		{
		case 0:	pr4=1;
			break;
		case 1:	pr4=0x7f;
			break;
		case 2:	pr4=0x80;
			break;
		case 3:	pr4=0x7fff;
			break;
		case 4:	pr4=0x8000;
			break;
		}

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		enc=NULL;
		dec=NULL;
		if(!(enc=a->encrypt_p8(ctx1,data1,sizeof(data1),k1,klen1,
			pr2,pr3,bits,pr1,pr4,&elen)))(*err1)++;
		else if(!(dec=b->decrypt_p8(ctx2,data2,sizeof(data2),enc,elen,
			&dlen)))(*err2)++;
		else if(klen1!=dlen||memcmp(k1,dec,klen1))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx1,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);

		usicrypt_random(NULL,data,sizeof(data));
		memcpy(data1,data,sizeof(data));
		memcpy(data2,data,sizeof(data));

		enc=NULL;
		dec=NULL;
		if(!(enc=b->encrypt_p8(ctx2,data1,sizeof(data1),k2,klen2,
			pr2,pr3,bits,pr1,pr4,&elen)))(*err2)++;
		else if(!(dec=a->decrypt_p8(ctx1,data2,sizeof(data2),enc,elen,
			&dlen)))(*err1)++;
		else if(klen2!=dlen||memcmp(k2,dec,klen2))(*err)++;
		else if(usicrypt_key_type_from_p8(ctx2,enc,elen)!=
			USICRYPT_PBES2)(*err)++;
		if(enc)free(enc);
		if(dec)free(dec);
	}

out:	if(x1)a->x448_free(ctx1,x1);
	if(x2)b->x448_free(ctx2,x2);
	if(x3)a->x448_free(ctx1,x3);
	if(x4)b->x448_free(ctx2,x4);
	if(p1)a->x448_free(ctx1,p1);
	if(p2)b->x448_free(ctx2,p2);
	if(pub1)free(pub1);
	if(pub2)free(pub2);
	if(pub3)free(pub3);
	if(pub4)free(pub4);
	if(k1)free(k1);
	if(k2)free(k2);
	if(r1)free(r1);
	if(r2)free(r2);
	if(r3)free(r3);
	if(r4)free(r4);
	if(pe1)free(pe1);
	if(pe2)free(pe2);
	if(pe3)free(pe3);
	if(pe4)free(pe4);
	if(de1)free(de1);
	if(de2)free(de2);
	if(de3)free(de3);
	if(de4)free(de4);
}

static int test_x448(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
		test_x448_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			&x448ops[i],&x448ops[j]);
	}
	return printres("usicrypt_x448_...:()",cerr,err);
}

static struct cmacops
{
	int (*cmac)(void *,int,void *,int,void *,int,void *);
	int (*cmac_iov)(void *,int,void *,int,struct usicrypt_iov *,int,void *);
} cmacops[5]=
{
	{
		xssl_cmac,xssl_cmac_iov,
	},
	{
		mbed_cmac,mbed_cmac_iov,
	},
	{
		wolf_cmac,wolf_cmac_iov,
	},
	{
		gcry_cmac,gcry_cmac_iov,
	},
	{
		nttl_cmac,nttl_cmac_iov,
	},
};

static void test_cmac_pair(void *ctx1,void *ctx2,int *err,int *err1,int *err2,
	struct cmacops *a,struct cmacops *b)
{
	int i;
	int bits;
	int cipher;
	struct usicrypt_iov iov[6];
	unsigned char key[32];
	unsigned char data[256];
	unsigned char cmac1[16];
	unsigned char cmac2[16];

	for(i=0;i<6;i++)
	{
		switch(i%3)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		switch(i/3)
		{
		case 0:	cipher=USICRYPT_AES;
			break;
		case 1:	cipher=USICRYPT_CAMELLIA;
			break;
		}

		usicrypt_random(NULL,key,sizeof(key));
		usicrypt_random(NULL,data,sizeof(data));

		if(a->cmac(ctx1,cipher,key,bits,data,sizeof(data),cmac1))
			(*err1)++;
		else if(b->cmac(ctx2,cipher,key,bits,data,sizeof(data),cmac2))
			(*err2)++;
		else if(memcmp(cmac1,cmac2,16))(*err)++;

		usicrypt_random(NULL,key,sizeof(key));
		usicrypt_random(NULL,data,sizeof(data));

		if(a->cmac(ctx1,cipher,key,bits,data,sizeof(data)-5,cmac1))
			(*err1)++;
		else if(b->cmac(ctx2,cipher,key,bits,data,sizeof(data)-5,
			cmac2))(*err2)++;
		else if(memcmp(cmac1,cmac2,16))(*err)++;

		iov[0].data=data;
		iov[0].length=40;
		iov[1].data=data+40;
		iov[1].length=24;
		iov[2].data=data+64;
		iov[2].length=sizeof(data)-64;

		if(a->cmac_iov(ctx1,cipher,key,bits,iov,3,cmac1))(*err1)++;
		else if(b->cmac_iov(ctx2,cipher,key,bits,iov,3,cmac2))(*err2)++;
		else if(memcmp(cmac1,cmac2,16))(*err)++;

		iov[0].data=data;
		iov[0].length=8;
		iov[1].data=data+8;
		iov[1].length=4;
		iov[2].data=data+12;
		iov[2].length=16;
		iov[3].data=data+28;
		iov[3].length=20;
		iov[4].data=data+48;
		iov[4].length=16;
		iov[5].data=data+64;
		iov[5].length=sizeof(data)-64;

		if(a->cmac_iov(ctx1,cipher,key,bits,iov,6,cmac1))(*err1)++;
		else if(b->cmac_iov(ctx2,cipher,key,bits,iov,6,cmac2))(*err2)++;
		else if(memcmp(cmac1,cmac2,16))(*err)++;

		iov[0].data=data;
		iov[0].length=8;
		iov[1].data=data+8;
		iov[1].length=4;
		iov[2].data=data+12;
		iov[2].length=16;
		iov[3].data=data+28;
		iov[3].length=20;
		iov[4].data=data+48;
		iov[4].length=16;
		iov[5].data=data+64;
		iov[5].length=sizeof(data)-65;

		if(a->cmac_iov(ctx1,cipher,key,bits,iov,6,cmac1))(*err1)++;
		else if(b->cmac_iov(ctx2,cipher,key,bits,iov,6,cmac2))(*err2)++;
		else if(memcmp(cmac1,cmac2,16))(*err)++;
	}
}

static int test_cmac(void **ctx)
{
	int i;
	int j;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_cmac_pair(ctx[i],ctx[j],&cerr,
		&err[i],&err[j],&cmacops[i],&cmacops[j]);
	return printres("usicrypt_cmac()",cerr,err);
}

static struct cbsops
{
	int (*cipher_block_size)(void *,int);
} cbsops[5]=
{
	{
		xssl_cipher_block_size,
	},
	{
		mbed_cipher_block_size,
	},
	{
		wolf_cipher_block_size,
	},
	{
		gcry_cipher_block_size,
	},
	{
		nttl_cipher_block_size,
	},
};

static void test_cipher_block_size_single(void *ctx,int *err,
	int (*cipher_block_size)(void *,int))
{
	int i;
	int cipher;
	int size;

	for(i=0;i<6;i++)
	{
		switch(i)
		{
		case 0:	cipher=USICRYPT_AES;
			size=16;
			break;
		case 1:	cipher=USICRYPT_CAMELLIA;
			size=16;
			break;
		case 2:	cipher=USICRYPT_CHACHA20;
			size=1;
			break;
		case 3:	cipher=USICRYPT_AES_GCM;
			size=1;
			break;
		case 4:	cipher=USICRYPT_AES_CCM;
			size=1;
			break;
		case 5:	cipher=USICRYPT_CHACHA20_POLY1305;
			size=1;
			break;
		}

		if(cipher_block_size(ctx,cipher)!=size)(*err)++;
	}
}

static int test_cipher_block_size(void **ctx)
{
	int i;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)test_cipher_block_size_single(ctx[i],&err[i],
		cbsops[i].cipher_block_size);
	return printres("usicrypt_cipher_block_size()",0,err);
}

static struct blkops
{
	void *(*blkcipher_init)(void *,int,int,void *,int,void *);
	int (*blkcipher_encrypt)(void *,void *,int,void *);
	int (*blkcipher_decrypt)(void *,void *,int,void *);
	void (*blkcipher_reset)(void *,void *);
	void (*blkcipher_exit)(void *);
} blkops[5]=
{
	{
		xssl_blkcipher_init,xssl_blkcipher_encrypt,
		xssl_blkcipher_decrypt,xssl_blkcipher_reset,
		xssl_blkcipher_exit,
	},
	{
		mbed_blkcipher_init,mbed_blkcipher_encrypt,
		mbed_blkcipher_decrypt,mbed_blkcipher_reset,
		mbed_blkcipher_exit,
	},
	{
		wolf_blkcipher_init,wolf_blkcipher_encrypt,
		wolf_blkcipher_decrypt,wolf_blkcipher_reset,
		wolf_blkcipher_exit,
	},
	{
		gcry_blkcipher_init,gcry_blkcipher_encrypt,
		gcry_blkcipher_decrypt,gcry_blkcipher_reset,
		gcry_blkcipher_exit,
	},
	{
		nttl_blkcipher_init,nttl_blkcipher_encrypt,
		nttl_blkcipher_decrypt,nttl_blkcipher_reset,
		nttl_blkcipher_exit,
	},
};

static void test_blkcipher_pair(void *ctx1,void *ctx2,int *err,int *err1,
	int *err2,int cipher,int mode,int zero,int stream,int imin,int imax,
	struct blkops *a,struct blkops *b)
{
	int i;
	int bits=0;
	int em1;
	int em2;
	void *blk1[3];
	void *blk2[3];
	unsigned char iv[16];
	unsigned char key1[32];
	unsigned char key2[32];
	unsigned char data[256];
	unsigned char enc[256];
	unsigned char dec[256];

	em1=*err1;
	em2=*err2;

	memset(blk1,0,sizeof(blk1));
	memset(blk2,0,sizeof(blk2));

	for(i=imin;i<imax;i++)
	{
		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key2));

		switch(i)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		}

		if(!(blk1[i]=a->blkcipher_init(ctx1,cipher,mode,key1,bits,iv)))
			(*err1)++;
		if(!(blk2[i]=b->blkcipher_init(ctx2,cipher,mode,key2,bits,iv)))
			(*err2)++;
	}
	if(*err1!=em1||*err2!=em2)goto out;

	for(i=imin;i<imax;i++)
	{
		usicrypt_random(NULL,data,sizeof(data));

		if(a->blkcipher_encrypt(blk1[i],data,sizeof(data),enc))
			(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],enc,sizeof(data),dec))
			(*err2)++;
		else if(memcmp(data,dec,sizeof(data)))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],data,sizeof(data),enc))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],enc,sizeof(data),dec))
			(*err1)++;
		else if(memcmp(data,dec,sizeof(data)))(*err)++;

		if(!zero)continue;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(a->blkcipher_encrypt(blk1[i],NULL,sizeof(data),enc))
			(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,sizeof(data),dec))
			(*err2)++;
		else if(memcmp(enc,dec,sizeof(data)))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],NULL,sizeof(data),enc))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,sizeof(data),dec))
			(*err1)++;
		else if(memcmp(enc,dec,sizeof(data)))(*err)++;
	}

	if(!stream)goto out;

	for(i=imin;i<imax;i++)
	{
		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(a->blkcipher_encrypt(blk1[i],data,sizeof(data)-4,enc))
			(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],enc,sizeof(data)-4,dec))
			(*err2)++;
		else if(memcmp(data,dec,sizeof(data)-4))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],data,sizeof(data)-4,enc))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],enc,sizeof(data)-4,dec))
			(*err1)++;
		else if(memcmp(data,dec,sizeof(data)-4))(*err)++;

		if(!zero)continue;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(a->blkcipher_encrypt(blk1[i],NULL,sizeof(data)-4,enc))
			(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,sizeof(data)-4,dec))
			(*err2)++;
		else if(memcmp(enc,dec,sizeof(data)-4))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],NULL,sizeof(data)-4,enc))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,sizeof(data)-4,dec))
			(*err1)++;
		else if(memcmp(enc,dec,sizeof(data)-4))(*err)++;
	}

	if(stream<2)goto out;

	for(i=imin;i<imax;i++)
	{
		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(a->blkcipher_encrypt(blk1[i],data,4,enc))(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],data+4,16,enc+4))(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],data+20,sizeof(data)-24,
			enc+20))(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],data+sizeof(data)-4,4,
			enc+sizeof(data)-4))(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],enc,4,dec))(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],enc+4,16,dec+4))(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],enc+20,sizeof(data)-24,
			dec+20))(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],enc+sizeof(data)-4,4,
			dec+sizeof(data)-4))(*err2)++;
		else if(memcmp(data,dec,sizeof(data)))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],data,4,enc))(*err2)++;
		else if(b->blkcipher_encrypt(blk2[i],data+4,16,enc+4))(*err2)++;
		else if(b->blkcipher_encrypt(blk2[i],data+20,sizeof(data)-24,
			enc+20))(*err2)++;
		else if(b->blkcipher_encrypt(blk2[i],data+sizeof(data)-4,4,
			enc+sizeof(data)-4))(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],enc,4,dec))(*err1)++;
		else if(a->blkcipher_decrypt(blk1[i],enc+4,16,dec+4))(*err1)++;
		else if(a->blkcipher_decrypt(blk1[i],enc+20,sizeof(data)-24,
			dec+20))(*err1)++;
		else if(a->blkcipher_decrypt(blk1[i],enc+sizeof(data)-4,4,
			dec+sizeof(data)-4))(*err1)++;
		else if(memcmp(data,dec,sizeof(data)))(*err)++;

		if(!zero)continue;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(a->blkcipher_encrypt(blk1[i],NULL,4,enc))
			(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],NULL,16,enc+4))
			(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],NULL,sizeof(data)-24,
			enc+20))(*err1)++;
		else if(a->blkcipher_encrypt(blk1[i],NULL,4,enc+sizeof(data)-4))
			(*err1)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,4,dec))
			(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,16,dec+4))
			(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,sizeof(data)-24,
			dec+20))(*err2)++;
		else if(b->blkcipher_decrypt(blk2[i],NULL,4,dec+sizeof(data)-4))
			(*err2)++;
		else if(memcmp(enc,dec,sizeof(data)))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,data,sizeof(data));
		a->blkcipher_reset(blk1[i],iv);
		b->blkcipher_reset(blk2[i],iv);

		if(b->blkcipher_encrypt(blk2[i],NULL,4,enc))
			(*err1)++;
		else if(b->blkcipher_encrypt(blk2[i],NULL,16,enc+4))
			(*err1)++;
		else if(b->blkcipher_encrypt(blk2[i],NULL,sizeof(data)-24,
			enc+20))(*err1)++;
		else if(b->blkcipher_encrypt(blk2[i],NULL,4,enc+sizeof(data)-4))
			(*err1)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,4,dec))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,16,dec+4))
			(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,sizeof(data)-24,
			dec+20))(*err2)++;
		else if(a->blkcipher_decrypt(blk1[i],NULL,4,dec+sizeof(data)-4))
			(*err2)++;
		else if(memcmp(enc,dec,sizeof(data)))(*err)++;
	}

out:	for(i=imin;i<imax;i++)
	{
		if(blk1[i])a->blkcipher_exit(blk1[i]);
		if(blk2[i])b->blkcipher_exit(blk2[i]);
	}
}

static int test_blkcipher_item(void **ctx,int cipher,int mode,int zero,
	int stream)
{
	int i;
	int j;
	int cerr=0;
	int err[5];
	char *cname;
	char *mname;
	char bfr[64];

	switch(cipher)
	{
	case USICRYPT_AES:
		cname="aes";
		break;
	case USICRYPT_CAMELLIA:
		cname="camellia";
		break;
	default:cname="unknown";
		break;
	}

	switch(mode)
	{
	case USICRYPT_ECB:
		mname="ecb";
		break;
	case USICRYPT_CBC:
		mname="cbc";
		break;
	case USICRYPT_CTS:
		mname="cts";
		break;
	case USICRYPT_CFB:
		mname="cfb";
		break;
	case USICRYPT_CFB8:
		mname="cfb8";
		break;
	case USICRYPT_OFB:
		mname="ofb";
		break;
	case USICRYPT_CTR:
		mname="ctr";
		break;
	default:mname="unknown";
		break;
	}

	memset(err,0,sizeof(err));
	sprintf(bfr,"usicrypt_blkcipher_...(%s,%s)",cname,mname);
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_blkcipher_pair(ctx[i],ctx[j],
		&cerr,&err[i],&err[j],cipher,mode,zero,stream,0,3,
		&blkops[i],&blkops[j]);
	return printres(bfr,cerr,err);
}

static int test_blkcipher(void **ctx)
{
	int i;
	int cipher;
	int err=0;

	for(i=0;i<2;i++)
	{
		switch(i)
		{
		case 0:	cipher=USICRYPT_AES;
			break;
		case 1:	cipher=USICRYPT_CAMELLIA;
			break;
		}

		err+=test_blkcipher_item(ctx,cipher,USICRYPT_ECB,0,0);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_CBC,0,0);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_CTS,0,1);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_CFB,0,2);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_CFB8,0,2);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_OFB,1,2);
		err+=test_blkcipher_item(ctx,cipher,USICRYPT_CTR,1,2);
	}

	return err;
}

static int test_blkcipher_chacha(void **ctx)
{
	int i;
	int j;
	int x;
	int cerr=0;
	int err[5];

	memset(err,0,sizeof(err));
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER >= 0x10100000L
		x=1;
#else
		if(i==0||j==0)x=0;
		else x=1;
#endif
#if MBEDTLS_VERSION_NUMBER < 0x020c0000
		if(i==1||j==1)x=0;
#endif
		if(x)test_blkcipher_pair(ctx[i],ctx[j],&cerr,&err[i],&err[j],
			USICRYPT_CHACHA20,USICRYPT_STREAM,0,1,2,3,
			&blkops[i],&blkops[j]);
	}
	return printres("usicrypt_blkcipher_...(chacha20,stream)",cerr,err);
}

static struct dskops
{
	void *(*init)(void *,int,int,void *,int);
	int (*encrypt)(void *,void *,void *,int,void *);
	int (*decrypt)(void *,void *,void *,int,void *);
	void (*exit)(void *);
} dskops[5]=
{
	{
		xssl_dskcipher_init,xssl_dskcipher_encrypt,
		xssl_dskcipher_decrypt,xssl_dskcipher_exit,
	},
	{
		mbed_dskcipher_init,mbed_dskcipher_encrypt,
		mbed_dskcipher_decrypt,mbed_dskcipher_exit,
	},
	{
		wolf_dskcipher_init,wolf_dskcipher_encrypt,
		wolf_dskcipher_decrypt,wolf_dskcipher_exit,
	},
	{
		gcry_dskcipher_init,gcry_dskcipher_encrypt,
		gcry_dskcipher_decrypt,gcry_dskcipher_exit,
	},
	{
		nttl_dskcipher_init,nttl_dskcipher_encrypt,
		nttl_dskcipher_decrypt,nttl_dskcipher_exit,
	},
};

static void test_dskcipher_pair(void *ctx1,void *ctx2,int *err,int *err1,
	int *err2,int cipher,int mode,struct dskops *a,struct dskops *b)
{
	int i;
	int em1;
	int em2;
	int imin=0;
	int imax=0;
	int bits=0;
	void *dsk1;
	void *dsk2;
	unsigned char key1[64];
	unsigned char key2[64];
	unsigned char iv[16];
	unsigned char plain[256];
	unsigned char enc[256];
	unsigned char dec[256];

	em1=*err1;
	em2=*err2;

	switch(mode)
	{
	case USICRYPT_XTS:
		imin=2;
		imax=4;
		break;
	case USICRYPT_ESSIV:
		imin=0;
		imax=3;
		break;
	}

	for(i=imin;i<imax;i++)
	{
		switch(i)
		{
		case 0:	bits=128;
			break;
		case 1:	bits=192;
			break;
		case 2:	bits=256;
			break;
		case 3:	bits=512;
			break;
		}

		dsk1=NULL;
		dsk2=NULL;

		usicrypt_random(NULL,key1,sizeof(key1));
		memcpy(key2,key1,sizeof(key1));
		if(!(dsk1=a->init(ctx1,cipher,mode,key1,bits)))(*err1)++;
		if(!(dsk2=b->init(ctx2,cipher,mode,key2,bits)))(*err2)++;
		if(*err1!=em1||*err2!=em2)goto out;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,plain,sizeof(plain));
		if(a->encrypt(dsk1,iv,plain,sizeof(plain),enc))(*err1)++;
		else if(b->decrypt(dsk2,iv,enc,sizeof(enc),dec))(*err2)++;
		else if(memcmp(plain,dec,sizeof(plain)))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,plain,sizeof(plain));
		if(b->encrypt(dsk2,iv,plain,sizeof(plain),enc))(*err2)++;
		else if(a->decrypt(dsk1,iv,enc,sizeof(enc),dec))(*err1)++;
		else if(memcmp(plain,dec,sizeof(plain)))(*err)++;

		if(mode==USICRYPT_ESSIV)goto out;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,plain,sizeof(plain));
		if(a->encrypt(dsk1,iv,plain,sizeof(plain)-1,enc))(*err1)++;
		else if(b->decrypt(dsk2,iv,enc,sizeof(enc)-1,dec))(*err2)++;
		else if(memcmp(plain,dec,sizeof(plain)-1))(*err)++;

		usicrypt_random(NULL,iv,sizeof(iv));
		usicrypt_random(NULL,plain,sizeof(plain));
		if(b->encrypt(dsk2,iv,plain,sizeof(plain)-1,enc))(*err2)++;
		else if(a->decrypt(dsk1,iv,enc,sizeof(enc)-1,dec))(*err1)++;
		else if(memcmp(plain,dec,sizeof(plain)-1))(*err)++;

out:		if(dsk1)a->exit(dsk1);
		if(dsk2)b->exit(dsk2);
	}
}

static int test_dskcipher_item(void **ctx,int cipher,int mode)
{
	int i;
	int j;
	int cerr=0;
	int err[5];
	char *cname;
	char *mname;
	char bfr[64];

	switch(cipher)
	{
	case USICRYPT_AES:
		cname="aes";
		break;
	case USICRYPT_CAMELLIA:
		cname="camellia";
		break;
	default:cname="unknown";
		break;
	}

	switch(mode)
	{
	case USICRYPT_XTS:
		mname="xts";
		break;
	case USICRYPT_ESSIV:
		mname="essiv";
		break;
	default:mname="unknown";
		break;
	}

	memset(err,0,sizeof(err));
	sprintf(bfr,"usicrypt_dskcipher_...(%s,%s)",cname,mname);
	for(i=0;i<5;i++)for(j=i+1;j<5;j++)test_dskcipher_pair(ctx[i],ctx[j],
		&cerr,&err[i],&err[j],cipher,mode,&dskops[i],&dskops[j]);
	return printres(bfr,cerr,err);
}

static int test_dskcipher(void **ctx)
{
	int i;
	int cipher;
	int err=0;

	for(i=0;i<2;i++)
	{
		switch(i)
		{
		case 0:	cipher=USICRYPT_AES;
			break;
		case 1:	cipher=USICRYPT_CAMELLIA;
			break;
		}

		err+=test_dskcipher_item(ctx,cipher,USICRYPT_XTS);
		err+=test_dskcipher_item(ctx,cipher,USICRYPT_ESSIV);
	}

	return err;
}

static struct aeadops
{
	void *(*init)(void *,int,void *,int,int,int);
	int (*encrypt)(void *,void *,void *,int,void *,int,void *,void *);
	int (*decrypt)(void *,void *,void *,int,void *,int,void *,void *);
	int (*encrypt_iov)(void *,void *,void *,int,struct usicrypt_iov *,
		int,void *,void *);
	int (*decrypt_iov)(void *,void *,void *,int,struct usicrypt_iov *,
		int,void *,void *);
	void (*exit)(void *);
} aeadops[5]=
{
	{
		xssl_aeadcipher_init,xssl_aeadcipher_encrypt,
		xssl_aeadcipher_decrypt,xssl_aeadcipher_encrypt_iov,
		xssl_aeadcipher_decrypt_iov,xssl_aeadcipher_exit,
	},
	{
		mbed_aeadcipher_init,mbed_aeadcipher_encrypt,
		mbed_aeadcipher_decrypt,mbed_aeadcipher_encrypt_iov,
		mbed_aeadcipher_decrypt_iov,mbed_aeadcipher_exit,
	},
	{
		wolf_aeadcipher_init,wolf_aeadcipher_encrypt,
		wolf_aeadcipher_decrypt,wolf_aeadcipher_encrypt_iov,
		wolf_aeadcipher_decrypt_iov,wolf_aeadcipher_exit,
	},
	{
		gcry_aeadcipher_init,gcry_aeadcipher_encrypt,
		gcry_aeadcipher_decrypt,gcry_aeadcipher_encrypt_iov,
		gcry_aeadcipher_decrypt_iov,gcry_aeadcipher_exit,
	},
	{
		nttl_aeadcipher_init,nttl_aeadcipher_encrypt,
		nttl_aeadcipher_decrypt,nttl_aeadcipher_encrypt_iov,
		nttl_aeadcipher_decrypt_iov,nttl_aeadcipher_exit,
	},
};

static void test_aeadcipher_pair(void *ctx1,void *ctx2,int *err,int *err1,
	int *err2,int cipher,int klen,int ilen,int tlen,struct aeadops *a,
	struct aeadops *b)
{
	int em1;
	int em2;
	void *aead1;
	void *aead2;
	struct usicrypt_iov iov[6];
	unsigned char iv[16];
	unsigned char tag[16];
	unsigned char key1[32];
	unsigned char key2[32];
	unsigned char data[256];
	unsigned char aad[256];
	unsigned char enc[256];
	unsigned char dec[256];

	em1=(*err1);
	em2=(*err2);

	usicrypt_random(NULL,key1,sizeof(key1));
	memcpy(key2,key1,sizeof(key2));

	if(!(aead1=a->init(ctx1,cipher,key1,klen,ilen,tlen)))(*err1)++;
	if(!(aead2=b->init(ctx2,cipher,key2,klen,ilen,tlen)))(*err2)++;
	if((*err1)!=em1||(*err2)!=em2)goto out;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(a->encrypt(aead1,iv,data,sizeof(data),NULL,0,enc,tag))(*err1)++;
	else if(b->decrypt(aead2,iv,enc,sizeof(enc),NULL,0,dec,tag))(*err2)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(b->encrypt(aead2,iv,data,sizeof(data),NULL,0,enc,tag))(*err2)++;
	else if(a->decrypt(aead1,iv,enc,sizeof(enc),NULL,0,dec,tag))(*err1)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(a->encrypt(aead1,iv,data,sizeof(data),aad,sizeof(aad),enc,tag))
		(*err1)++;
	else if(b->decrypt(aead2,iv,enc,sizeof(enc),aad,sizeof(aad),dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(b->encrypt(aead2,iv,data,sizeof(data),aad,sizeof(aad),enc,tag))
		(*err2)++;
	else if(a->decrypt(aead1,iv,enc,sizeof(enc),aad,sizeof(aad),dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(a->encrypt(aead1,iv,data,sizeof(data)-1,NULL,0,enc,tag))(*err1)++;
	else if(b->decrypt(aead2,iv,enc,sizeof(enc)-1,NULL,0,dec,tag))(*err2)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(b->encrypt(aead2,iv,data,sizeof(data)-1,NULL,0,enc,tag))(*err2)++;
	else if(a->decrypt(aead1,iv,enc,sizeof(enc)-1,NULL,0,dec,tag))(*err1)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(a->encrypt(aead1,iv,data,sizeof(data)-1,aad,sizeof(aad)-1,enc,tag))
		(*err1)++;
	else if(b->decrypt(aead2,iv,enc,sizeof(enc)-1,aad,sizeof(aad)-1,dec,
		tag))(*err2)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(b->encrypt(aead2,iv,data,sizeof(data)-1,aad,sizeof(aad)-1,enc,tag))
		(*err2)++;
	else if(a->decrypt(aead1,iv,enc,sizeof(enc)-1,aad,sizeof(aad)-1,dec,
		tag))(*err1)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	iov[0].data=aad;
	iov[0].length=40;
	iov[1].data=aad+40;
	iov[1].length=24;
	iov[2].data=aad+64;
	iov[2].length=sizeof(aad)-64;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(a->encrypt_iov(aead1,iv,data,sizeof(data),NULL,0,enc,tag))(*err1)++;
	else if(b->decrypt_iov(aead2,iv,enc,sizeof(enc),NULL,0,dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(b->encrypt_iov(aead2,iv,data,sizeof(data),NULL,0,enc,tag))(*err2)++;
	else if(a->decrypt_iov(aead1,iv,enc,sizeof(enc),NULL,0,dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(a->encrypt_iov(aead1,iv,data,sizeof(data),iov,3,enc,tag))(*err1)++;
	else if(b->decrypt_iov(aead2,iv,enc,sizeof(enc),iov,3,dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(b->encrypt_iov(aead2,iv,data,sizeof(data),iov,3,enc,tag))(*err2)++;
	else if(a->decrypt_iov(aead1,iv,enc,sizeof(enc),iov,3,dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	iov[0].data=aad;
	iov[0].length=8;
	iov[1].data=aad+8;
	iov[1].length=4;
	iov[2].data=aad+12;
	iov[2].length=16;
	iov[3].data=aad+28;
	iov[3].length=20;
	iov[4].data=aad+48;
	iov[4].length=16;
	iov[5].data=aad+64;
	iov[5].length=sizeof(aad)-64;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(a->encrypt_iov(aead1,iv,data,sizeof(data),iov,6,enc,tag))(*err1)++;
	else if(b->decrypt_iov(aead2,iv,enc,sizeof(enc),iov,6,dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(b->encrypt_iov(aead2,iv,data,sizeof(data),iov,6,enc,tag))(*err2)++;
	else if(a->decrypt_iov(aead1,iv,enc,sizeof(enc),iov,6,dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)))(*err)++;

	iov[0].data=aad;
	iov[0].length=8;
	iov[1].data=aad+8;
	iov[1].length=4;
	iov[2].data=aad+12;
	iov[2].length=16;
	iov[3].data=aad+28;
	iov[3].length=20;
	iov[4].data=aad+48;
	iov[4].length=16;
	iov[5].data=aad+64;
	iov[5].length=sizeof(aad)-65;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(a->encrypt_iov(aead1,iv,data,sizeof(data)-1,NULL,0,enc,tag))
		(*err1)++;
	else if(b->decrypt_iov(aead2,iv,enc,sizeof(enc)-1,NULL,0,dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));

	if(b->encrypt_iov(aead2,iv,data,sizeof(data)-1,NULL,0,enc,tag))
		(*err2)++;
	else if(a->decrypt_iov(aead1,iv,enc,sizeof(enc)-1,NULL,0,dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(a->encrypt_iov(aead1,iv,data,sizeof(data)-1,iov,6,enc,tag))(*err1)++;
	else if(b->decrypt_iov(aead2,iv,enc,sizeof(enc)-1,iov,6,dec,tag))
		(*err2)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

	usicrypt_random(NULL,iv,sizeof(iv));
	usicrypt_random(NULL,data,sizeof(data));
	usicrypt_random(NULL,aad,sizeof(aad));

	if(b->encrypt_iov(aead2,iv,data,sizeof(data)-1,iov,6,enc,tag))(*err2)++;
	else if(a->decrypt_iov(aead1,iv,enc,sizeof(enc)-1,iov,6,dec,tag))
		(*err1)++;
	else if(memcmp(data,dec,sizeof(data)-1))(*err)++;

out:	if(aead1)a->exit(aead1);
	if(aead2)b->exit(aead2);
}

static void test_aeadcipher_item(void **ctx,int *cerr, int *err,
	int cipher,int klen,int ilen,int tlen,int nombed,int noxssl)
{
	int i;
	int j;

	for(i=0;i<5;i++)for(j=i+1;j<5;j++)
	{
		if(i==0||j==0)if(noxssl)continue;
#if MBEDTLS_VERSION_NUMBER < 0x020c0000
		if(i==1||j==1)if(nombed)continue;
#endif
#if LIBWOLFSSL_VERSION_HEX >= 0x03012002
		if((i==2||j==2)&&cipher==USICRYPT_AES_GCM&&tlen<12)continue;
#endif
		test_aeadcipher_pair(ctx[i],ctx[j],cerr,&err[i],&err[j],
			cipher,klen,ilen,tlen,&aeadops[i],&aeadops[j]);
	}
}

static int test_aeadcipher(void **ctx)
{
	int i;
	int j;
	int k;
	int l;
	int noxssl;
	int sum=0;
	int cerr;
	int err[5];
	char bfr[64];
	struct
	{
		char *name;
		int cipher;
		int nombed;
		int nkey;
		int niv;
		int ntag;
		int key[3];
		int iv[16];
		int tag[16];
	} conf[3]=
	{
		{
			"aes/gcm",
			USICRYPT_AES_GCM,0,3,16,7,
			{128,192,256},
			{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16},
			{4,8,12,13,14,15,16}
		},
		{
			"aes/ccm",
			USICRYPT_AES_CCM,0,3,7,7,
			{128,192,256},
			{7,8,9,10,11,12,13},
			{4,6,8,10,12,14,16}
		},
		{
			"chacha20/poly1305",
			USICRYPT_CHACHA20_POLY1305,1,1,1,1,
			{256},
			{12},
			{16}
		}
	};

	for(i=0;i<3;i++)
	{
		cerr=0;
		memset(err,0,sizeof(err));

		if(i==2)
		{
#if defined(LIBRESSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER >= 0x10100000L
			noxssl=0;
#else
			noxssl=1;
#endif
		}
		else noxssl=0;

		for(j=0;j<conf[i].nkey;j++)for(k=0;k<conf[i].niv;k++)
			for(l=0;l<conf[i].ntag;l++)test_aeadcipher_item(ctx,
				&cerr,err,conf[i].cipher,conf[i].key[j],
				conf[i].iv[k],conf[i].tag[l],conf[i].nombed,
				noxssl);

		sprintf(bfr,"usicrypt_aeadcipher_...(%s)",conf[i].name);
		sum+=printres(bfr,cerr,err);
	}

	return sum;
}

static int test_util_cipher_padding(void *ctx)
{
	int i;
	int j;
	int val;
	int err=0;
	unsigned char bfr[48];
	unsigned char cmp[48];

	memset(cmp,0xff,sizeof(cmp));

	for(i=0;i<=32;i++)
	{
		memset(bfr,0xff,i);
		val=usicrypt_cipher_padding_add(ctx,NULL,i);
		if(!(i&0xf)&&val!=16)err++;
		else if(16-val!=(i&0xf))err++;
		else if(usicrypt_cipher_padding_add(ctx,bfr,i)!=val)err++;
		else if(usicrypt_cipher_padding_get(ctx,bfr,i+val)!=val)err++;
		else if(memcmp(bfr,cmp,i))err++;
		else for(j=i;j<i+val;j++)if(bfr[j]!=val)
		{
			err++;
			break;
		}
	}

	printf("usicrypt_cipher_padding_...():");
	if(err)printf(" util failed");
	if(!err)printf(" OK");
	printf("\n");

	return err;
}

static int test_util_lfsr(void *ctx)
{
	int i;
	int j;
	int err=0;
	unsigned long long ref;
	unsigned long long count;
	void *lfsr;
	unsigned char start[16];
	unsigned char val[16];

	for(i=8;i<=24;i+=8)
	{
		ref=1;
		ref<<=i;
		ref-=1;

		while(1)
		{
			usicrypt_random(NULL,start,sizeof(start));
			for(j=0;j<(i>>3);j++)if(start[j])break;
			if(j!=(i>>3))break;
		}

		if(!(lfsr=usicrypt_lfsr_init(ctx,i,start)))
		{
			err++;
			continue;
		}

		count=0;
		do
		{
			usicrypt_lfsr_next(lfsr,val);
			count++;
		} while(memcmp(start,val,i>>3));

		if(count!=ref)err++;

		usicrypt_lfsr_exit(lfsr);

		if(!(lfsr=usicrypt_lfsr_init(ctx,i,NULL)))
		{
			err++;
			continue;
		}

		usicrypt_lfsr_next(lfsr,start);

		count=0;
		do
		{
			usicrypt_lfsr_next(lfsr,val);
			count++;
		} while(memcmp(start,val,i>>3));

		if(count!=ref)err++;

		usicrypt_lfsr_exit(lfsr);
	}

	for(i=32;i<=128;i+=8)
	{
		ref=30000000;

		while(1)
		{
			usicrypt_random(NULL,start,sizeof(start));
			for(j=0;j<(i>>3);j++)if(start[j])break;
			if(j!=(i>>3))break;
		}

		if(!(lfsr=usicrypt_lfsr_init(ctx,i,start)))
		{
			err++;
			continue;
		}

		count=0;
		do
		{
			usicrypt_lfsr_next(lfsr,val);
			count++;
		} while(memcmp(start,val,i>>3)&&count!=ref);

		if(count!=ref)err++;

		usicrypt_lfsr_exit(lfsr);

		if(!(lfsr=usicrypt_lfsr_init(ctx,i,NULL)))
		{
			err++;
			continue;
		}

		usicrypt_lfsr_next(lfsr,start);

		count=0;
		do
		{
			usicrypt_lfsr_next(lfsr,val);
			count++;
		} while(memcmp(start,val,i>>3)&&count!=ref);

		if(count!=ref)err++;

		usicrypt_lfsr_exit(lfsr);
	}

	printf("usicrypt_lfsr_...():");
	if(err)printf(" util failed");
	if(!err)printf(" OK");
	printf("\n");

	return err;
}

static int test_util_memclear(void *ctx)
{
	int i;
	int j;
	int err=0;
	unsigned char bfr[65536];

	for(i=1;i<sizeof(bfr);i+=43)
	{
		memset(bfr,0xff,sizeof(bfr));

		usicrypt_memclear(ctx,bfr,i);

		for(j=0;j<i;j++)if(bfr[j])
		{
			err++;
			break;
		}

		for(j=i;j<sizeof(bfr);j++)if(bfr[j]!=0xff)
		{
			err++;
			break;
		}
	}

	printf("usicrypt_memclear():");
	if(err)printf(" util failed");
	if(!err)printf(" OK");
	printf("\n");

	return err;
}

int main(int argc,char *argv[])
{
	int c;
	int cont=0;
	int loop=0;
	unsigned int cnt=0;
	unsigned int tot=0;
	int err=0;
	void *glob[5];
	void *ctx[5];

	while((c=getopt(argc,argv,"clx"))!=-1)switch(c)
	{
	case 'c':
		cont=1;
		break;
	case 'l':
		loop=1;
		break;
	case 'x':
		expensive=1;
		break;
	default:return 1;
	}

	memset(ctx,0,sizeof(ctx));
	memset(glob,0,sizeof(glob));

	if(!(glob[0]=xssl_global_init(NULL,NULL)))err++;
	else if(!(ctx[0]=xssl_thread_init(glob[0])))err++;

	if(!(glob[1]=mbed_global_init(NULL,NULL)))err++;
	if(!(ctx[1]=mbed_thread_init(glob[1])))err++;

	if(!(glob[2]=wolf_global_init(NULL,NULL)))err++;
	if(!(ctx[2]=wolf_thread_init(glob[2])))err++;

	if(!(glob[3]=gcry_global_init(NULL,NULL)))err++;
	if(!(ctx[3]=gcry_thread_init(glob[3])))err++;

	if(!(glob[4]=nttl_global_init(NULL,NULL)))err++;
	if(!(ctx[4]=nttl_thread_init(glob[4])))err++;

	if(!err)do
	{
		err+=test_random(ctx);
		err+=test_digest_size(ctx);
		err+=test_digest(ctx);
		err+=test_hmac(ctx);
		err+=test_pbkdf2(ctx);
		err+=test_hkdf(ctx);
		err+=test_base64(ctx);
		err+=test_rsa(ctx);
		err+=test_dh(ctx);
		err+=test_ec(ctx);
		err+=test_ed25519(ctx);
		err+=test_ed448(ctx);
		err+=test_x25519(ctx);
		err+=test_x448(ctx);
		err+=test_cmac(ctx);
		err+=test_cipher_block_size(ctx);
		err+=test_blkcipher(ctx);
		err+=test_blkcipher_chacha(ctx);
		err+=test_dskcipher(ctx);
		err+=test_aeadcipher(ctx);
		err+=test_util_cipher_padding(ctx[0]);
		err+=test_util_lfsr(ctx[0]);
		err+=test_util_memclear(ctx[0]);
		if(err)tot++;
		err=0;
		if(cont||loop)printf("round %u errors %d\n",++cnt,tot);
	} while(cont||(loop&&!tot));
	else printf("Init failed, can't do tests.\n");

	if(ctx[0])xssl_thread_exit(ctx[0]);
	if(glob[0])xssl_global_exit(glob[0]);

	if(ctx[1])mbed_thread_exit(ctx[1]);
	if(glob[1])mbed_global_exit(glob[1]);

	if(ctx[2])wolf_thread_exit(ctx[2]);
	if(glob[2])wolf_global_exit(glob[2]);

	if(ctx[3])gcry_thread_exit(ctx[3]);
	if(glob[3])gcry_global_exit(glob[3]);

	if(ctx[4])nttl_thread_exit(ctx[4]);
	if(glob[4])nttl_global_exit(glob[4]);

	if(tot)printf("Some tests failed.\n");

	return err?1:0;
}
