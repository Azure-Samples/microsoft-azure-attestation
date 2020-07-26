# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/genquote_host ./enclave/genquote_enclave.debug.signed              enclave.info.debug.json
	host/genquote_host ./enclave/genquote_enclave.release.signed            enclave.info.release.json
	host/genquote_host ./enclave/genquote_enclave.prodid.signed             enclave.info.prodid.json
	host/genquote_host ./enclave/genquote_enclave.securityversion.signed    enclave.info.securityversion.json

runone:
	host/genquote_host ./enclave/genquote_enclave.prodid.signed             enclave.info.prodid.json
