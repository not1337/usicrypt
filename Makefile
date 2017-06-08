# usicrypt, a unifying crypto library wrapper for low level functions
#
# (c) 2017 Andreas Steinmetz
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
#
# Select any of the following targets
#
#TARGET=-DUSICRYPT_GCRY
#TARGET=-DUSICRYPT_MBED
#TARGET=-DUSICRYPT_NTTL
#TARGET=-DUSICRYPT_WOLF
TARGET=-DUSICRYPT_XSSL
#
# Enable the following and add '-Wl,-gc-sections' to your link command
# which links against the usicrypt library to actually remove all
# unreferenced code:
#CFLAGS+=-fdata-sections -ffunction-sections
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

CFLAGS+=-I/usr/local/test/wolfssl310/include
LDFLAGS+=-L/usr/local/test/wolfssl310/lib -Wl,-rpath,/usr/local/test/wolfssl310/lib

#CFLAGS+=-I/usr/local/test/libressl24/include
#LDFLAGS+=-L/usr/local/test/libressl24/lib -Wl,-rpath,/usr/local/test/libressl24/lib

#CFLAGS+=-I/usr/local/test/libressl25/include
#LDFLAGS+=-L/usr/local/test/libressl25/lib -Wl,-rpath,/usr/local/test/libressl25/lib

#CFLAGS+=-I/usr/local/test/openssl11/include
#LDFLAGS+=-L/usr/local/test/openssl11/lib -Wl,-rpath,/usr/local/test/openssl11/lib

all: libusicrypt.a libusicrypt-pic.a

libusicrypt.a: usicrypt_gcry.o usicrypt_mbed.o usicrypt_nttl.o \
	usicrypt_wolf.o usicrypt_util.o usicrypt_xssl.o
	$(AR) rcu $@ $^

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

libusicrypt-pic.a: usicrypt_gcry.po usicrypt_mbed.po usicrypt_nttl.po \
	usicrypt_wolf.po usicrypt_util.po usicrypt_xssl.po
	$(AR) rcu $@ $^

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

usicrypt_test: usicrypt_test.to usicrypt_gcry.to usicrypt_nttl.to \
	usicrypt_mbed.to usicrypt_wolf.to usicrypt_util.to usicrypt_xssl.to
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

clean:
	rm -f usicrypt_test *.to *.po *.o *.a core

%.to : %.c
	$(CC) -Wall $(CFLAGS) -DUSICRYPT_TEST -c -o $@ $<

%.po : %.c
	$(CC) -Wall $(CFLAGS) $(TARGET) -fPIC -c -o $@ $<

%.o : %.c
	$(CC) -Wall $(CFLAGS) $(TARGET) -c -o $@ $<
