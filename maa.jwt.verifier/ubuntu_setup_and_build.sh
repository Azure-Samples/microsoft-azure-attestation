#!/bin/bash

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

__msg_stage "Setup Environment"

__msg_stage "Update and Upgrade System"
sudo apt update && sudo apt -y upgrade

__msg_stage "Configure the Intel and Microsoft APT Repositories"
# This step and the next one below are based on the Open Enclave's documentation with a few adjustments.
# See: https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_host_verify_Ubuntu_18.04.md
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

__msg_stage "Install the Intel and Open Enclave Host-Verify packages and dependencies"
# This step also installs the az-dcap-client package which is necessary for performing remote attestation in Azure.
# A general implementation for using Intel DCAP outside the Azure environment is coming soon.
# https://github.com/microsoft/azure-dcap-client
sudo apt update
sudo apt -y install make cmake g++ libssl-dev libcurl4-openssl-dev libsgx-dcap-ql libsgx-dcap-ql-dev az-dcap-client open-enclave-hostverify

__msg_stage "Read and execute the content of openenclaverc"
# This step is needed for pkg-config oehostverify-$(CXX) ... command to function properly.
echo "source /opt/openenclave/share/openenclave/openenclaverc" >> ~/.bashrc
# This step is needed for supressing the WARNING (it is not an error, it is a warning!) message:
# Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'
echo 'export AZDCAP_DEBUG_LOG_LEVEL=None' >> ~/.bashrc
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

