######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
DCAP_LIBRARY_NAME := sgx_dcap_ql
UAE_LIBRARY_NAME := sgx_quote_ex

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	URTS_LIBRARY_NAME := sgx_urts_sim
else
	URTS_LIBRARY_NAME := sgx_urts
endif

CFLAGS := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes -I$(SGX_SDK)/include

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        CFLAGS += -DNDEBUG -DEDEBUG -UDEBUG
else
        CFLAGS += -DNDEBUG -UEDEBUG -UDEBUG
endif

CXXFLAGS := $(CFLAGS) -std=c++11
LDFLAGS := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(URTS_LIBRARY_NAME) -lpthread -l$(DCAP_LIBRARY_NAME) -l$(UAE_LIBRARY_NAME)

ifneq ($(SGX_MODE), HW)
	LDFLAGS += -lsgx_uae_service_sim
	TRTS_LIBRARY_NAME := sgx_trts_sim
	SERVICE_LIBRARY_NAME := sgx_tservice_sim
else
	LDFLAGS += -lsgx_uae_service
	TRTS_LIBRARY_NAME := sgx_trts
	SERVICE_LIBRARY_NAME := sgx_tservice
endif

CRYPTO_LIBRARY_NAME := sgx_tcrypto

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

ENCLAVE_INCLUDE_PATHS := -I. -I.. -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	ENCLAVE_C_FLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
	ENCLAVE_C_FLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif
ENCLAVE_C_FLAGS += $(ENCLAVE_INCLUDE_PATHS)
ENCLAVE_CPP_FLAGS := $(ENCLAVE_C_FLAGS) -std=c++11 -nostdinc++
ENCLAVE_LINK_FLAGS := $(LDFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(TRTS_LIBRARY_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(CRYPTO_LIBRARY_NAME) -l$(SERVICE_LIBRARY_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections



