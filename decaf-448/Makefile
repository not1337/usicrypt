VER=1.0

all: usicrypt_dcaf.o usicrypt_dcaf.lo usicrypt_dcaf.to

usicrypt_dcaf.o: usicrypt_dcaf.c lib/libdecaf-nonpic.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	gcc -Wall -O2 -I.. -Iinclude -c -o usicrypt_dcaf.tmp.o $<
	ld -r -o $@ usicrypt_dcaf.tmp.o -Llib -ldecaf-nonpic

usicrypt_dcaf.to: usicrypt_dcaf.c lib/libdecaf-nonpic.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	gcc -Wall -O2 -I.. -Iinclude -DUSICRYPT_TEST -c \
		-o usicrypt_dcaf.tmp.to $<
	ld -r -o $@ usicrypt_dcaf.tmp.to -Llib -ldecaf-nonpic

usicrypt_dcaf.lo: usicrypt_dcaf.c lib/libdecaf-pic.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	gcc -Wall -O2 -I.. -Iinclude -fPIC -c -o usicrypt_dcaf.tmp.lo $<
	ld -r -o $@ usicrypt_dcaf.tmp.lo -Llib -ldecaf-pic

include/decaf/ed448.h: lib/libdecaf-pic.a lib/libdecaf-nonpic.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/ed448.h $@

include/decaf/shake.h: lib/libdecaf-pic.a lib/libdecaf-nonpic.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/shake.h $@

include/decaf/sha512.h: lib/libdecaf-pic.a lib/libdecaf-nonpic.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/sha512.h $@

include/decaf/point_448.h: lib/libdecaf-pic.a lib/libdecaf-nonpic.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/point_448.h $@

include/decaf/common.h: lib/libdecaf-pic.a lib/libdecaf-nonpic.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/common.h $@

lib/libdecaf-pic.a: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p lib
	cp $^ $@

lib/libdecaf-nonpic.a: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p lib
	cp $^ $@

goldilocks-$(VER)/nonpic/lib/libdecaf.a: goldilocks-$(VER)/Makefile.non-pic
	make -C goldilocks-$(VER) -f Makefile.non-pic nonpic/lib/libdecaf.a \
		CC=gcc

goldilocks-$(VER)/build/lib/libdecaf.a: goldilocks-$(VER)/Makefile.pic
	make -C goldilocks-$(VER) -f Makefile.pic build/lib/libdecaf.a CC=gcc

goldilocks-$(VER)/Makefile.non-pic: goldilocks-$(VER)/Makefile
	sed -e 's/ -fPIC//' -e 's#build/#nonpic/#g' -e 's/-march=native//' \
		$^ > $@
	echo "" >> $@
	echo '$$(BUILD_LIB)/libdecaf.a: $$(LIBCOMPONENTS)' >> $@
	echo '	ar rcu $$@ $$^' >> $@

goldilocks-$(VER)/Makefile.pic: goldilocks-$(VER)/Makefile
	sed -e 's/-march=native//' $^ > $@
	echo "" >> $@
	echo '$$(BUILD_LIB)/libdecaf.a: $$(LIBCOMPONENTS)' >> $@
	echo '	ar rcu $$@ $$^' >> $@

clean:
	rm -rf goldilocks-$(VER)/src/GENERATED goldilocks-$(VER)/nonpic \
		goldilocks-$(VER)/build goldilocks-$(VER)/Makefile.non-pic \
		goldilocks-$(VER)/Makefile.pic usicrypt_dcaf.tmp.lo \
		usicrypt_dcaf.tmp.o usicrypt_dcaf.lo usicrypt_dcaf.o \
		usicrypt_dcaf.tmp.to usicrypt_dcaf.to lib include
