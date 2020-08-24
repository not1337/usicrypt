# usicrypt, a unifying crypto library wrapper for low level functions
#
# (c) 2017-2020 Andreas Steinmetz
#
# Any OSI approved license of your choice applies, see the file LICENSE
# for details.

#
# set preferred compiler and options
#
CC=gcc
CFLAGS=-O3 -g
LDFLAGS=
AR=ar
ARFLAGS=
#
# Select any of the following targets
#
#TARGET=-DUSICRYPT_GCRY
#TARGET=-DUSICRYPT_MBED
#TARGET=-DUSICRYPT_NTTL
#TARGET=-DUSICRYPT_WOLF
TARGET=-DUSICRYPT_XSSL
#
# if you know that the selected crypto library natively supports ED25519,
# you can define the following to prevent external source build
#USICRYPT_NO_ED25519=1
#
# if you know that the selected crypto library natively supports X448 as
# well as ED448, you can define the following to prevent external source build
#USICRYPT_NO_DECAF=1
#
# Enable the following and add '-Wl,-gc-sections' to your link command
# which links against the usicrypt library to actually remove all
# unreferenced code:
#CFLAGS+=-fdata-sections -ffunction-sections
#
# Enable the following and add '-flto -fuse-linker-plugin' to your link
# command which links against the usicrypt library to enable the link time
# optimizer
#CFLAGS+=-flto
#ARFLAGS+=--plugin `./findliblto.sh $(CC)`
#
# If you use OpenSSL 1.0.x or LibreSSL and don't intend to use threads
# enable the following:
#CFLAGS+=-DUSICRYPT_NO_THREADS
#
# If you use gcc on x86_64 or x86 enable the following to enable runtime
# support of RDRAND/RDSEED instructions:
CFLAGS+=-mrdrnd -mrdseed
#
# Uncomment any of the following options if you don't require some feature:
#CFLAGS+=-DUSICRYPT_NO_RSA
#CFLAGS+=-DUSICRYPT_NO_DH
#CFLAGS+=-DUSICRYPT_NO_EC
#CFLAGS+=-DUSICRYPT_NO_X25519
#CFLAGS+=-DUSICRYPT_NO_ED25519
#CFLAGS+=-DUSICRYPT_NO_X448
#CFLAGS+=-DUSICRYPT_NO_ED448
#CFLAGS+=-DUSICRYPT_NO_DIGEST
#CFLAGS+=-DUSICRYPT_NO_HMAC
#CFLAGS+=-DUSICRYPT_NO_PBKDF2
#CFLAGS+=-DUSICRYPT_NO_HKDF
#CFLAGS+=-DUSICRYPT_NO_BASE64
#CFLAGS+=-DUSICRYPT_NO_IOV
#CFLAGS+=-DUSICRYPT_NO_SHA1
#CFLAGS+=-DUSICRYPT_NO_SHA256
#CFLAGS+=-DUSICRYPT_NO_SHA384
#CFLAGS+=-DUSICRYPT_NO_SHA512
#CFLAGS+=-DUSICRYPT_NO_CMAC
#CFLAGS+=-DUSICRYPT_NO_AES
#CFLAGS+=-DUSICRYPT_NO_CAMELLIA
#CFLAGS+=-DUSICRYPT_NO_CHACHA
#CFLAGS+=-DUSICRYPT_NO_STREAM
#CFLAGS+=-DUSICRYPT_NO_ECB
#CFLAGS+=-DUSICRYPT_NO_CBC
#CFLAGS+=-DUSICRYPT_NO_CTS
#CFLAGS+=-DUSICRYPT_NO_CFB
#CFLAGS+=-DUSICRYPT_NO_CFB8
#CFLAGS+=-DUSICRYPT_NO_OFB
#CFLAGS+=-DUSICRYPT_NO_CTR
#CFLAGS+=-DUSICRYPT_NO_XTS
#CFLAGS+=-DUSICRYPT_NO_ESSIV
#CFLAGS+=-DUSICRYPT_NO_GCM
#CFLAGS+=-DUSICRYPT_NO_CCM
#CFLAGS+=-DUSICRYPT_NO_POLY

#
# samples if libraries are in non default locations
#
#CFLAGS+=-I/usr/local/test/wolfssl315/include
#LDFLAGS+=-L/usr/local/test/wolfssl315/lib -Wl,-rpath,/usr/local/test/wolfssl315/lib

#CFLAGS+=-I/usr/local/test/libressl24/include
#LDFLAGS+=-L/usr/local/test/libressl24/lib -Wl,-rpath,/usr/local/test/libressl24/lib

#CFLAGS+=-I/usr/local/test/libressl25/include
#LDFLAGS+=-L/usr/local/test/libressl25/lib -Wl,-rpath,/usr/local/test/libressl25/lib

#CFLAGS+=-I/usr/local/test/openssl11/include
#LDFLAGS+=-L/usr/local/test/openssl11/lib -Wl,-rpath,/usr/local/test/openssl11/lib

ifndef USICRYPT_NO_ED25519
USIED25519=usicrypt_ed25519.o
USITED25519=usicrypt_ed25519.to
USISHED25519=usicrypt_ed25519.po
ED25519OBJS=add_scalar.eo fe.eo ge.eo key_exchange.eo keypair.eo sc.eo seed.eo sha512.eo sign.eo verify.eo
ED25519SHOBJS=add_scalar.epo fe.epo ge.epo key_exchange.epo keypair.epo sc.epo seed.epo sha512.epo sign.epo verify.epo
else
USIED25519=
USITED25519=
USISHED25519=
ED25519OBJS=
ED25519SHOBJS=
endif
ifndef USICRYPT_NO_DECAF
USIDECAF=decaf-448/obj/usicrypt_dcaf.o
USITDECAF=decaf-448/obj/usicrypt_dcaf.to
USISHDECAF=decaf-448/obj/usicrypt_dcaf.lo
DECAFOBJS=decaf-448/obj/decaf.o decaf-448/obj/decaf_tables.o
DECAFOBJS+=decaf-448/obj/eddsa.o decaf-448/obj/scalar.o 
DECAFOBJS+=decaf-448/obj/f_arithmetic.o decaf-448/obj/f_generic.o
DECAFOBJS+=decaf-448/obj/f_impl.o decaf-448/obj/shake.o
DECAFOBJS+=decaf-448/obj/utils.o
DECASHFOBJS=decaf-448/obj/decaf.lo decaf-448/obj/decaf_tables.lo
DECASHFOBJS+=decaf-448/obj/eddsa.lo decaf-448/obj/scalar.lo 
DECASHFOBJS+=decaf-448/obj/f_arithmetic.lo decaf-448/obj/f_generic.lo
DECASHFOBJS+=decaf-448/obj/f_impl.lo decaf-448/obj/shake.lo
DECASHFOBJS+=decaf-448/obj/utils.lo
else
USIDECAF=
USITDECAF=
USISHDECAF=
DECAFOBJS=
DECAFSHOBJS=
endif

all: libusicrypt.a libusicrypt-pic.a

libusicrypt.a: usicrypt_gcry.o usicrypt_mbed.o usicrypt_nttl.o \
	usicrypt_wolf.o usicrypt_util.o usicrypt_xssl.o $(USIED25519) \
	$(ED25519OBJS) $(USIDECAF) $(DECAFOBJS)
	$(AR) rcu $(ARFLAGS) $@ $^

usicrypt_gcry.o: usicrypt_gcry.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_mbed.o: usicrypt_mbed.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_nttl.o: usicrypt_nttl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_wolf.o: usicrypt_wolf.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_util.o: usicrypt_util.c usicrypt_internal.h usicrypt.h
usicrypt_xssl.o: usicrypt_xssl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c

decaf-448/obj/usicrypt_dcaf.o:
	make -C decaf-448 USIARFLAGS="$(ARFLAGS)"

libusicrypt-pic.a: usicrypt_gcry.po usicrypt_mbed.po usicrypt_nttl.po \
	usicrypt_wolf.po usicrypt_util.po usicrypt_xssl.po $(USISHED25519) \
	$(ED25519SHOBJS) $(USISHDECAF) $(DECAFSHOBJS)
	$(AR) rcu $(ARFLAGS) $@ $^

usicrypt_gcry.po: usicrypt_gcry.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_mbed.po: usicrypt_mbed.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_nttl.po: usicrypt_nttl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_wolf.po: usicrypt_wolf.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_util.po: usicrypt_util.c usicrypt_internal.h usicrypt.h
usicrypt_xssl.po: usicrypt_xssl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c

decaf-448/obj/usicrypt_dcaf.lo:
	make -C decaf-448 USIARFLAGS="$(ARFLAGS)"

usicrypt_test: usicrypt_test.to usicrypt_gcry.to usicrypt_nttl.to \
	usicrypt_mbed.to usicrypt_wolf.to usicrypt_util.to usicrypt_xssl.to \
	$(USITED25519) $(ED25519OBJS) $(USITDECAF) $(DECAFOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto -lmbedcrypto -lwolfssl -lgcrypt \
		-lhogweed -lnettle -lgmp

usicrypt_test.to: usicrypt_test.c usicrypt.h
usicrypt_gcry.to: usicrypt_gcry.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_mbed.to: usicrypt_mbed.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_nttl.to: usicrypt_nttl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_wolf.to: usicrypt_wolf.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_util.to: usicrypt_util.c usicrypt_internal.h usicrypt.h
usicrypt_xssl.to: usicrypt_xssl.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c
usicrypt_ed25519.to: usicrypt_ed25519.c usicrypt_internal.h usicrypt.h \
	usicrypt_common.c github-orlp-ed25519/src/ed25519.h

decaf-448/obj/usicrypt_dcaf.to:
	make -C decaf-448 USIARFLAGS="$(ARFLAGS)"

clean:
	make -C decaf-448 clean
	rm -f usicrypt_test *.to *.po *.o *.eo *.epo *.a core

%.to : %.c
	$(CC) -Wall $(CFLAGS) -DUSICRYPT_TEST -c -o $@ $<

%.po : %.c
	$(CC) -Wall $(CFLAGS) $(TARGET) -fPIC -c -o $@ $<

%.o : %.c
	$(CC) -Wall $(CFLAGS) $(TARGET) -c -o $@ $<

%.eo : github-orlp-ed25519/src/%.c
	$(CC) -Wall $(CFLAGS) -DED25519_NO_SEED -c -o $@ $<

%.epo : github-orlp-ed25519/src/%.c
	$(CC) -Wall $(CFLAGS) -DED25519_NO_SEED -fPIC -c -o $@ $<

