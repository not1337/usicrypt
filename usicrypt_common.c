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
/*                                 Headers                                    */
/******************************************************************************/

#if defined(__x86_64) || defined(__i386)
#include <fcntl.h>
#include <unistd.h>
#include <cpuid.h>
#include <x86intrin.h>
#ifndef __RDRND__
#ifndef __DISABLE_RDRND__
#define __DISABLE_RDRND__
#endif
#endif
#ifndef __RDSEED__
#ifndef __DISABLE_RDSEED__
#define __DISABLE_RDSEED__
#endif
#endif
#elif defined(_WIN64) || defined(_WIN32)
#include <Ntsecapi.h>
#include <intrin.h>
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
	defined(__NetBSD__)
#include <fcntl.h>
#include <unistd.h>
#endif
#include <string.h>

/******************************************************************************/
/*                            Common Support Stuff                            */
/******************************************************************************/


#if !defined(USICRYPT_NO_BASE64) && !defined(USICRYPT_ORLP25519)

static const struct
{
	const char *head;
	const char *tail;
	const int hlen;
	const int tlen;
} USICRYPT(pemtab)[4]=
{
	{
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC) || !defined(USICRYPT_NO_X25519) || \
	!defined(USICRYPT_NO_ED25519)
		"-----BEGIN PUBLIC KEY-----",
		"-----END PUBLIC KEY-----",
		26,24,
#endif
	},
	{
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_EC) || \
	!defined(USICRYPT_NO_ED25519)
		"-----BEGIN PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		27,25,
#endif
	},
	{
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_EC)
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"-----END ENCRYPTED PRIVATE KEY-----",
		37,35,
#endif
	},
	{
#ifndef USICRYPT_NO_DH
		"-----BEGIN DH PARAMETERS-----",
		"-----END DH PARAMETERS-----",
		29,27,
#endif
	},
};

#endif

static int USICRYPT(get_features)(void)
{
	int features=0;

#if defined(__x86_64) || defined(__i386)
	int max;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;

	if((max=__get_cpuid_max(0,NULL))<1)return 0;
	__cpuid(1,eax,ebx,ecx,edx);
	if(ecx&bit_AES)features|=1;
	if(ecx&bit_RDRND)features|=2;
	if(max>=7)
	{
		__cpuid_count(7,0,eax,ebx,ecx,edx);
		if(ebx&bit_RDSEED)features|=4;
	}
#elif defined(_WIN64) || defined(_WIN32)
	int max;
	unsigned int data[4];

	__cpuid(data,0);
	if((max=data[0])<1)return 0;
	__cpuidex(data,1,0);
	if(data[2]&(1<<25))features|=1;
	if(data[2]&(1<<30))features|=2;
	if(max>=7)
	{
		__cpuidex(data,7,0);
		if(data[1]&(1<<18))features|=4;
	}
#endif
	return features;
}

static int USICRYPT(rdrand)(void *data)
{
#if defined(__x86_64) || defined(__i386) || defined(_WIN64) || defined(_WIN32)
#ifndef __DISABLE_RDRND__
#if !defined(__x86_64) && !defined(_WIN64)
	if(L(_rdrand32_step(data)&&_rdrand32_step(data+4)))return 0;
#else
	if(L(_rdrand64_step(data)))return 0;
#endif
#endif
#endif
	return -1;
}

static int USICRYPT(rdseed)(void *data)
{
#if defined(__x86_64) || defined(__i386) || defined(_WIN64) || defined(_WIN32)
#ifndef __DISABLE_RDSEED__
#if !defined(__x86_64) && !defined(_WIN64)
	if(L(_rdseed32_step(data)&&_rdseed32_step(data+4)))return 0;
#else
	if(L(_rdseed64_step(data)))return 0;
#endif
#endif
#endif
	return -1;
}

static int USICRYPT(osrandom)(void *data,int len)
{
#if defined(__linux__)
	int fd;
	size_t l;

	if(U((fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC))==-1))return -1;
	l=read(fd,data,len);
	close(fd);
	if(L(l==len))return 0;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	int fd;
	size_t l;

	if(U((fd=open("/dev/urandom",O_RDONLY))==-1))return -1;
	l=read(fd,data,len);
	close(fd);
	if(L(l==len))return 0;
#elif defined(_WIN64) || defined(_WIN32)
#warning Somebody needs to implement CryptGenRandom or RtlGenRandom
#endif
	return -1;
}

static int USICRYPT(get_random)(void *data,int len)
{
	static int features=-1;
	unsigned char *ptr=data;
	unsigned long long tmp;

	if(U(features==-1))features=USICRYPT(get_features)();

	if(features&4)for(;len>=8;len-=8,ptr+=8)
		if(USICRYPT(rdseed)(ptr))break;
	if(features&2)for(;len>=8;len-=8,ptr+=8)
		if(USICRYPT(rdrand)(ptr))break;
	if(!len)return 0;
	if(len<8)
	{
		if((features&4)&&!USICRYPT(rdseed)(&tmp))
			for(;len;len--,tmp>>=8)*ptr++=(unsigned char)tmp;
		if(!len)return 0;
		if((features&2)&&!USICRYPT(rdrand)(&tmp))
			for(;len;len--,tmp>>=8)*ptr++=(unsigned char)tmp;
		if(!len)return 0;
	}
	return USICRYPT(osrandom)(ptr,len);
}

static void USICRYPT(do_memclear)(void *data,int len)
{
	memset(data,0,len);
}

#ifndef USICRYPT_ORLP25519

static void *USICRYPT(do_realloc)(void *ctx,void *data,int olen,int nlen)
{
	void *tmp;
	if(U(olen==nlen))return data;
	if(U(!(tmp=malloc(nlen))))
	{
		if(olen<nlen)goto err1;
		((struct usicrypt_thread *)ctx)->global->
			memclear(data+nlen,olen-nlen);
		return data;
	}
	memcpy(tmp,data,nlen);
err1:	((struct usicrypt_thread *)ctx)->global->memclear(data,olen);
	free(data);
	return tmp;
}

void *USICRYPT(dh_to_pem)(void *ctx,void *data,int dlen,int *rlen)
{
#if !defined(USICRYPT_NO_DH) && !defined(USICRYPT_NO_BASE64)
	int l;
	int b64len;
	char *b64;
	char *src;
	char *ptr;
	char *r=NULL;

	if(U(!(src=b64=USICRYPT(base64_encode)(ctx,data,dlen,&b64len))))
		goto err1;

	*rlen=b64len+((b64len+63)>>6)+USICRYPT(pemtab)[3].hlen+
		USICRYPT(pemtab)[3].tlen+2;
	if(U(!(ptr=r=malloc(*rlen+1))))goto err2;

	memcpy(ptr,USICRYPT(pemtab)[3].head,USICRYPT(pemtab)[3].hlen);
	ptr+=USICRYPT(pemtab)[3].hlen;
	*ptr++='\n';
	while(b64len)
	{
		l=(b64len>64?64:b64len);
		memcpy(ptr,src,l);
		b64len-=l;
		src+=l;
		ptr+=l;
		*ptr++='\n';
	}
	memcpy(ptr,USICRYPT(pemtab)[3].tail,USICRYPT(pemtab)[3].tlen);
	ptr+=USICRYPT(pemtab)[3].tlen;
	*ptr++='\n';
	*ptr=0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(b64,b64len);
	free(b64);
err1:	return r;
#else
	return NULL;
#endif
}

void *USICRYPT(pem_to_dh)(void *ctx,void *data,int dlen,int *rlen)
{
#if !defined(USICRYPT_NO_DH) && !defined(USICRYPT_NO_BASE64)
	int i;
	int mode;
	int start;
	int type;
	int len;
	char *d=data;
	char *tmp;
	unsigned char *r=NULL;

	if(U(!(tmp=malloc(dlen))))goto err1;

	for(i=0,mode=0,len=0,type=0;i<dlen&&mode!=2;i++)switch(mode)
	{
	case 0:	if(d[i]==' '||d[i]=='\t'||d[i]=='\r'||d[i]=='\n')continue;
		start=i;
		mode=1;
		break;
	case 1:	if(d[i]!='\r'&&d[i]!='\n')continue;
		while(i>start&&(d[i-1]==' '||d[i-1]=='\t'))i--;
		if(!type)
		{
			if(i-start!=USICRYPT(pemtab)[3].hlen||
				memcmp(d+start,USICRYPT(pemtab)[3].head,
					i-start))goto err2;
			type=1;
			mode=0;
		}
		else if(d[start]=='-')
		{
			if(i-start!=USICRYPT(pemtab)[3].tlen||
				memcmp(d+start,USICRYPT(pemtab)[3].tail,
					i-start))goto err2;
			mode=2;
		}
		else
		{
			memcpy(tmp+len,d+start,i-start);
			len+=i-start;
			mode=0;
		}
		break;
	}

	if(U(!len)||U(len&3))goto err2;
	if(U(!(r=USICRYPT(base64_decode)(ctx,tmp,len,rlen))))goto err2;
	if(L(!usicrypt_dh_cmp_params(ctx,r,*rlen,r,*rlen)))goto err2;

	((struct usicrypt_thread *)ctx)->global->memclear(r,*rlen);
	free(r);
	r=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,dlen);
	free(tmp);
err1:	return r;
#else
	return NULL;
#endif
}

void *USICRYPT(p8_to_pem)(void *ctx,void *data,int dlen,int *rlen)
{
#ifndef USICRYPT_NO_BASE64
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC) || !defined(USICRYPT_NO_X25519) || \
	!defined(USICRYPT_NO_ED25519)
	int l;
	int idx=0;
	int b64len;
	char *b64;
	char *src;
	char *ptr;
	char *r=NULL;

	if(usicrypt_pub_type_from_p8(ctx,data,dlen)==-1)
		switch(usicrypt_key_type_from_p8(ctx,data,dlen))
	{
	case -1:goto err1;
	case USICRYPT_PBES2:
		idx++;
	default:idx++;
		break;
	}

	if(U(!USICRYPT(pemtab)[idx].head))goto err1;
	if(U(!(src=b64=USICRYPT(base64_encode)(ctx,data,dlen,&b64len))))
		goto err1;

	*rlen=b64len+((b64len+63)>>6)+USICRYPT(pemtab)[idx].hlen+
		USICRYPT(pemtab)[idx].tlen+2;
	if(U(!(ptr=r=malloc(*rlen+1))))goto err2;

	memcpy(ptr,USICRYPT(pemtab)[idx].head,USICRYPT(pemtab)[idx].hlen);
	ptr+=USICRYPT(pemtab)[idx].hlen;
	*ptr++='\n';
	while(b64len)
	{
		l=(b64len>64?64:b64len);
		memcpy(ptr,src,l);
		b64len-=l;
		src+=l;
		ptr+=l;
		*ptr++='\n';
	}
	memcpy(ptr,USICRYPT(pemtab)[idx].tail,USICRYPT(pemtab)[idx].tlen);
	ptr+=USICRYPT(pemtab)[idx].tlen;
	*ptr++='\n';
	*ptr=0;

err2:	((struct usicrypt_thread *)ctx)->global->memclear(b64,b64len);
	free(b64);
err1:	return r;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

void *USICRYPT(pem_to_p8)(void *ctx,void *data,int dlen,int *rlen)
{
#ifndef USICRYPT_NO_BASE64
#if !defined(USICRYPT_NO_RSA) || !defined(USICRYPT_NO_DH) || \
	!defined(USICRYPT_NO_EC) || !defined(USICRYPT_NO_X25519) || \
	!defined(USICRYPT_NO_ED25519)
	int i;
	int mode;
	int start;
	int type;
	int len;
	char *d=data;
	char *tmp;
	unsigned char *r=NULL;

	if(U(!(tmp=malloc(dlen))))goto err1;

	for(i=0,mode=0,len=0,type=-1;i<dlen&&mode!=2;i++)switch(mode)
	{
	case 0:	if(d[i]==' '||d[i]=='\t'||d[i]=='\r'||d[i]=='\n')continue;
		start=i;
		mode=1;
		break;
	case 1:	if(d[i]!='\r'&&d[i]!='\n')continue;
		while(i>start&&(d[i-1]==' '||d[i-1]=='\t'))i--;
		if(U(type==-1))
		{
			for(type=0;type<3;type++)if(USICRYPT(pemtab)[type].head)
				if(i-start==USICRYPT(pemtab)[type].hlen&&
				!memcmp(d+start,USICRYPT(pemtab)[type].head,
					i-start))break;
			if(U(type==3))goto err2;
			mode=0;
		}
		else if(d[start]=='-')
		{
			if(i-start!=USICRYPT(pemtab)[type].tlen||
				memcmp(d+start,USICRYPT(pemtab)[type].tail,
					i-start))goto err2;
			mode=2;
		}
		else
		{
			memcpy(tmp+len,d+start,i-start);
			len+=i-start;
			mode=0;
		}
		break;
	}

	if(U(!len)||U(len&3))goto err2;
	if(U(!(r=USICRYPT(base64_decode)(ctx,tmp,len,rlen))))goto err2;
	switch(type)
	{
	case 0:	if(U(usicrypt_pub_type_from_p8(ctx,r,*rlen)==-1))goto err3;
		break;
	case 1:	if(U((mode=usicrypt_key_type_from_p8(ctx,r,*rlen))==-1))
			goto err3;
		if(U(mode==USICRYPT_PBES2))goto err3;
		break;
	case 2:	if(U(usicrypt_key_type_from_p8(ctx,r,*rlen)!=USICRYPT_PBES2))
			goto err3;
		break;
	}
	goto err2;

err3:	((struct usicrypt_thread *)ctx)->global->memclear(r,*rlen);
	free(r);
	r=NULL;
err2:	((struct usicrypt_thread *)ctx)->global->memclear(tmp,dlen);
	free(tmp);
err1:	return r;
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

#endif
