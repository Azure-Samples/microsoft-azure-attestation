# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

all: build

build:
	@ echo "Build using: $(CC), $(CXX)"
	@ $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include
	$(CC) -c $(CFLAGS) $(CINCLUDES) enclave_u.c
	$(CXX) -c $(CXXFLAGS) -I. -I/usr/include host.cpp
	$(CXX) -o genquote_sgx_host host.o enclave_u.o -lcrypto $(LDFLAGS)

clean:
	rm -vf genquote_sgx_host *.o enclave_*.*


