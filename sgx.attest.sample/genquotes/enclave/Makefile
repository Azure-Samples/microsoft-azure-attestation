# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(CXX_COMPILER) --libs)

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../remoteattestation.edl --trusted --trusted-dir ../common
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I. -I.. -std=c++11 -DOE_API_VERSION=2 ecalls.cpp ../common/attestation.cpp ../common/crypto.cpp ../common/dispatcher.cpp
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) -I.. -DOE_API_VERSION=2 ../common/remoteattestation_t.c
	$(CXX) -o genquote_enclave attestation.o crypto.o ecalls.o dispatcher.o remoteattestation_t.o $(LDFLAGS)

sign:
	oesign sign -e genquote_enclave -c enc.conf -k private.pem
	cp genquote_enclave.signed genquote_enclave.debug.signed
	oesign sign -e genquote_enclave -c enc.conf.release -k private.pem
	cp genquote_enclave.signed genquote_enclave.release.signed
	oesign sign -e genquote_enclave -c enc.conf.prodid -k private.pem
	cp genquote_enclave.signed genquote_enclave.prodid.signed
	oesign sign -e genquote_enclave -c enc.conf.securityversion -k private.pem
	cp genquote_enclave.signed genquote_enclave.securityversion.signed

clean:
	rm -f *.o genquote_enclave *.signed ../common/remoteattestation_t.* ../common/remoteattestation_args.h *.pem enclave_b_pubkey.h
