#!/bin/bash

# This optional helper script is provided for sample convenience. Dependencies may
# instead be preinstalled and the verifier built directly with CMake and make.

# abort on nonzero exitstatus
set -o errexit
# abort on unbound variable
set -o nounset   
# do not hide errors within pipes
set -o pipefail  

function __msg() {
    echo -e "    $*"
}

function __msg_stage() {
    echo -e "********************************************************************"
    echo -e "*   $*"
    echo -e "********************************************************************"
}

echo >&2 "WARNING: This sample is provided for informational purposes only and is not"
echo >&2 "a production best-practices solution. This optional convenience script changes"
echo >&2 "the local build environment and is used at your own risk. It targets Ubuntu"
echo >&2 "22.04 and is not guaranteed to work across other distributions, releases, or"
echo >&2 "machine configurations. You may preinstall the dependencies and build directly"
echo >&2 "with CMake and make instead."

__msg_stage "Setup Environment"

__msg_stage "Update and Upgrade System"
sudo apt update && sudo apt -y upgrade

__msg_stage "Configure the Intel and Microsoft APT Repositories"
# This step and the next one below are based on the Open Enclave's documentation with a few adjustments.
# See: https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_host_verify_Ubuntu_22.04.md
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

__msg_stage "Install the Intel and Open Enclave Host-Verify packages and dependencies"
# This step also installs the az-dcap-client package which is necessary for performing remote attestation in Azure.
# A general implementation for using Intel DCAP outside the Azure environment is coming soon.
# https://github.com/microsoft/azure-dcap-client
sudo apt update
sudo apt -y install make cmake g++ llvm-11 libssl-dev libcurl4-openssl-dev libprotobuf23 libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave-hostverify

__msg_stage "Read and execute the content of openenclaverc"
# This step is needed for pkg-config oehostverify-$(CXX) ... command to function properly.
echo "source /opt/openenclave/share/openenclave/openenclaverc" >> ~/.bashrc
# This step is needed for supressing the WARNING (it is not an error, it is a warning!) message:
# Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'
echo 'export AZDCAP_DEBUG_LOG_LEVEL=None' >> ~/.bashrc
export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}"
export CMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH:-}"
source ~/.bashrc

__msg_stage "Build"

rm -rvf ./out
mkdir -pv out
export LOCAL_ROOT="$(dirname $(pwd))"
echo $LOCAL_ROOT
cd out/
cmake ../
make

./jwt-verifier

