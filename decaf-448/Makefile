VER=1.0

TARGETS=obj/decaf.o obj/decaf_tables.o obj/eddsa.o obj/scalar.o
TARGETS+=obj/f_arithmetic.o obj/f_generic.o obj/f_impl.o
TARGETS+=obj/shake.o obj/utils.o

TARGETS+=obj/decaf.lo obj/decaf_tables.lo obj/eddsa.lo obj/scalar.lo
TARGETS+=obj/f_arithmetic.lo obj/f_generic.lo obj/f_impl.lo
TARGETS+=obj/shake.lo obj/utils.lo

TARGETS+=obj/usicrypt_dcaf.o obj/usicrypt_dcaf.lo obj/usicrypt_dcaf.to

all: $(TARGETS)

obj/decaf.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/ed448goldilocks/decaf.o $@

obj/decaf_tables.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/ed448goldilocks/decaf_tables.o $@

obj/eddsa.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/ed448goldilocks/eddsa.o $@

obj/scalar.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/ed448goldilocks/scalar.o $@

obj/f_arithmetic.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/p448/f_arithmetic.o $@

obj/f_generic.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/p448/f_generic.o $@

obj/f_impl.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/p448/f_impl.o $@

obj/shake.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/shake.o $@

obj/utils.o: goldilocks-$(VER)/nonpic/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/nonpic/obj/utils.o $@

obj/decaf.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/ed448goldilocks/decaf.o $@

obj/decaf_tables.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/ed448goldilocks/decaf_tables.o $@

obj/eddsa.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/ed448goldilocks/eddsa.o $@

obj/scalar.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/ed448goldilocks/scalar.o $@

obj/f_arithmetic.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/p448/f_arithmetic.o $@

obj/f_generic.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/p448/f_generic.o $@

obj/f_impl.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/p448/f_impl.o $@

obj/shake.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/shake.o $@

obj/utils.lo: goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p obj
	cp goldilocks-$(VER)/build/obj/utils.o $@

obj/usicrypt_dcaf.o: usicrypt_dcaf.c goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	mkdir -p obj
	gcc -Wall $(USIFLAGS) $(TARGET) -I.. -Iinclude -c -o $@ $<

obj/usicrypt_dcaf.to: usicrypt_dcaf.c goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	mkdir -p obj
	gcc -Wall $(USIFLAGS) -DUSICRYPT_TEST -I.. -Iinclude -c -o $@ $<

obj/usicrypt_dcaf.lo: usicrypt_dcaf.c goldilocks-$(VER)/build/lib/libdecaf.a \
	include/decaf/ed448.h include/decaf/shake.h include/decaf/sha512.h \
	include/decaf/point_448.h include/decaf/common.h
	mkdir -p obj
	gcc -Wall $(USIFLAGS) $(TARGET) -I.. -Iinclude -fPIC -c -o $@ $<

include/decaf/ed448.h: goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/ed448.h $@

include/decaf/shake.h: goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/shake.h $@

include/decaf/sha512.h: goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/sha512.h $@

include/decaf/point_448.h: goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/point_448.h $@

include/decaf/common.h: goldilocks-$(VER)/nonpic/lib/libdecaf.a \
	goldilocks-$(VER)/build/lib/libdecaf.a
	mkdir -p include/decaf
	cp goldilocks-$(VER)/src/GENERATED/include/decaf/common.h $@

goldilocks-$(VER)/nonpic/lib/libdecaf.a: goldilocks-$(VER)/Makefile.non-pic
	make -C goldilocks-$(VER) -f Makefile.non-pic nonpic/lib/libdecaf.a \
		CC=gcc OFLAGS= GENFLAGS="$(USIFLAGS)" ARFLAGS="$(USIARFLAGS)" \
		XLDFLAGS="-Wno-lto-type-mismatch" ARCHFLAGS=""

goldilocks-$(VER)/build/lib/libdecaf.a: goldilocks-$(VER)/Makefile.pic
	make -C goldilocks-$(VER) -f Makefile.pic build/lib/libdecaf.a CC=gcc \
		OFLAGS= GENFLAGS="$(USIFLAGS)" ARFLAGS="$(USIARFLAGS)" \
		XLDFLAGS="-Wno-lto-type-mismatch" ARCHFLAGS=""

goldilocks-$(VER)/Makefile.non-pic: goldilocks-$(VER)/Makefile
	sed 's#build/#nonpic/#g' $^ > $@
	echo "" >> $@
	echo '$$(BUILD_LIB)/libdecaf.a: $$(LIBCOMPONENTS)' >> $@
	echo '	ar rcu $$(ARFLAGS) $$@ $$^' >> $@

goldilocks-$(VER)/Makefile.pic: goldilocks-$(VER)/Makefile
	cp $^ $@
	echo "" >> $@
	echo '$$(BUILD_LIB)/libdecaf.a: $$(LIBCOMPONENTS)' >> $@
	echo '	ar rcu $$(ARFLAGS) $$@ $$^' >> $@

clean:
	rm -rf goldilocks-$(VER)/src/GENERATED goldilocks-$(VER)/nonpic \
		goldilocks-$(VER)/build goldilocks-$(VER)/Makefile.non-pic \
		goldilocks-$(VER)/Makefile.pic usicrypt_dcaf.tmp.lo \
		usicrypt_dcaf.tmp.o usicrypt_dcaf.lo usicrypt_dcaf.o \
		usicrypt_dcaf.tmp.to usicrypt_dcaf.to obj include
