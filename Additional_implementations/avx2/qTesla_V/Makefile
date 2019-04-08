CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
endif

AVX2=-D _AVX2_ -mavx2

AR=ar rcs
RANLIB=ranlib

CFLAGS = -std=gnu11 -O3 -D $(ARCHITECTURE) $(AVX2) -D __LINUX__ -fomit-frame-pointer
LDFLAGS=-lm -L/usr/lib/ -lssl -lcrypto 

ifeq "$(CC)" "gcc"
    CFLAGS+= -march=native
endif

DFLAG=
ifeq "$(DEBUG)" "TRUE"
    DFLAG=-DDEBUG
endif

OBJECTS_ASM_V = objs_V/s_consts.o objs/poly_mul2048.o objs/sparse_mul16.o
OBJECTS_EXTRAS = objs/fips202x4.o objs/KeccakP-1600-times4-SIMD256.o

OBJECTS_V = objs_V/sign.o objs_V/pack.o objs_V/sample.o objs_V/gauss.o objs_V/poly.o objs_V/consts.o $(OBJECTS_ASM_V) objs/fips202.o objs/random.o $(OBJECTS_EXTRAS)
SOURCE_TEST = tests/cpucycles.c tests/test_qtesla.c
SOURCE_KATS_GEN  = tests/rng.c tests/PQCgenKAT_sign.c
SOURCE_KATS_TEST = tests/rng.c tests/PQCtestKAT_sign.c

all: lib_V tests

objs_V/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_V_ $< -o $@

objs/random.o: random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) random/random.c -o objs/random.o

objs/fips202.o: sha3/fips202.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) sha3/fips202.c -o objs/fips202.o
	
objs/fips202x4.o: sha3/fips202x4.c
	$(CC) -c $(CFLAGS) sha3/fips202x4.c -o objs/fips202x4.o

objs/KeccakP-1600-times4-SIMD256.o: sha3/keccak4x/KeccakP-1600-times4-SIMD256.c
	$(CC) -c $(CFLAGS) sha3/keccak4x/KeccakP-1600-times4-SIMD256.c -o objs/KeccakP-1600-times4-SIMD256.o

objs/poly_mul2048.o: poly_mul2048.S
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) poly_mul2048.S -o objs/poly_mul2048.o

objs/sparse_mul16.o: sparse_mul16.S
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) sparse_mul16.S -o objs/sparse_mul16.o

lib_V: $(OBJECTS_V)
	rm -rf lib_V
	mkdir lib_V
	$(AR) lib_V/libqtesla.a $^
	$(RANLIB) lib_V/libqtesla.a

tests: lib_V
	$(CC) $(CFLAGS) -L./lib_V -D _qTESLA_V_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-V $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_V -D _qTESLA_V_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-V $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_V -D _qTESLA_V_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-V $(ARM_SETTING)

.PHONY: clean

clean:
	rm -rf objs* lib* test_qtesla-* PQCgenKAT_sign-* PQCtestKAT_sign-* PQCsignKAT_qTesla*