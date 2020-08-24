# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

all:
	$(MAKE) genkey
	$(MAKE) build
	$(MAKE) sign

private.pem:
	openssl genrsa -out $@ -3 3072

public.pem: private.pem
	openssl rsa -in $< -out $@ -pubout

genkey: public.pem

gentrusted:
	$(SGX_EDGER8R) --trusted enclave.edl --search-path ./ --search-path $(SGX_SDK)/include

build: gentrusted
	@ echo "Build using: $(CC), $(CXX), SGX_DEBUG=$(SGX_DEBUG)"
	$(CXX) -c $(CXXFLAGS) $(ENCLAVE_CPP_FLAGS) ecalls.cpp
	$(CC) -c $(CFLAGS) $(ENCLAVE_C_FLAGS) enclave_t.c
	$(CXX) -o genquote_enclave ecalls.o enclave_t.o $(ENCLAVE_LINK_FLAGS)

ifeq ($(SGX_DEBUG), 1)
sign:
	@$(SGX_ENCLAVE_SIGNER) sign -key private.pem -enclave genquote_enclave -out genquote_enclave.debug.signed -config enc.config.xml

else
sign:
	@$(SGX_ENCLAVE_SIGNER) sign -key private.pem -enclave genquote_enclave -out genquote_enclave.release.signed -config enc.config.release.xml
	@$(SGX_ENCLAVE_SIGNER) sign -key private.pem -enclave genquote_enclave -out genquote_enclave.prodid.signed -config enc.config.prodid.xml
	@$(SGX_ENCLAVE_SIGNER) sign -key private.pem -enclave genquote_enclave -out genquote_enclave.securityversion.signed -config enc.config.securityversion.xml

endif

clean:
	rm -vf *.o genquote_enclave *.signed enclave_*.* *.pem

