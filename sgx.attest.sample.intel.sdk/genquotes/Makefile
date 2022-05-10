# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build run

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

ifeq ($(SGX_DEBUG), 1)
run:
	host/genquote_sgx_host ./enclave/genquote_enclave.debug.signed             enclave.info.debug.json

else
run:
	host/genquote_sgx_host ./enclave/genquote_enclave.release.signed           enclave.info.release.json
	host/genquote_sgx_host ./enclave/genquote_enclave.prodid.signed            enclave.info.prodid.json
	host/genquote_sgx_host ./enclave/genquote_enclave.securityversion.signed   enclave.info.securityversion.json

endif


