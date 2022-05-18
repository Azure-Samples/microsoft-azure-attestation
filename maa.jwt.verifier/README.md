## About

JWT Verifier takes advantage of the Open Enclave SDK API call [oe_verify_attestation_certificate](https://openenclave.io/apidocs/v0.17/enclave_8h_a3b75c5638360adca181a0d945b45ad86.html#a3b75c5638360adca181a0d945b45ad86). See also https://openenclave.io/apidocs/v0.17/index.html .

This function performs a custom validation on the input certificate. This validation includes extracting an attestation evidence extension from the certificate before validating this evidence.

`jwt-verifier` builds and runs on Windows and Ubuntu Linux. The tool performs the following steps:
- [ ] Parses MAA JWT;
- [ ] Sends a request to MAA to get certificates;
- [ ] Deserialize JSON Web Keys and finds x.509 certificates for the key;
- [ ] Looks up for the MAA x509 extension;
- [ ] Verifies the certificate using oe_verify_attestation_certificate OpenEnclave API.
 
## Windows | Build and Run

### Prerequisites
- Dev System with Windows Server 2019
- MAA JWT sample token as an input for the verification

### Install Tools
#### Optional Setup
- `[Optional]` This step is needed if Internet Explorer is used for the file downloads **and** `file download` option is disabled there. In Internet Explorer enable the file download in Internet Explorer.
    - Open Internet Explorer.
    - Click Tools and then options.
    - Click on the security tab.
    - Select the Internet Zone.
    - Click on the Custom Level Button and then scroll down to Download.
    - Make sure to enable File download.
    - Click Apply and Ok
    - Restart Internet Explorer

#### Required Tools
1. Download and install Git from https://git-scm.com/download/win
2. Download and install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
3. Download and install latest stabel CMake version [CMake v3.23.1](https://github.com/Kitware/CMake/releases/download/v3.23.1/cmake-3.23.1-windows-x86_64.msi). If the link does not work, see https://cmake.org/download/

### Get Sources
Open Git Bash:
- `[Optional]` Setup the Git Bash with a new SSH key for the GirHub portal:
    - Gegerate New SSH Key: `ssh-keygen -t ed25519 -C "<EMAIL>"`
    - Go through the settings prompt and provide wanted values for the key
    - `eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519 && cat ~/.ssh/id_ed25519.pub`
    - Add the new SSH key to the GitHub keys: https://github.com/settings/keys
    - `git config --global user.email "you@example.com"`
    - `git config --global user.name "Your Name"`

- Clone the repo
```
git clone  --recursive git@github.com:Azure-Samples/microsoft-azure-attestation.git
```

Or in GitBash or PowerShell:

```
git clone  --recursive https://github.com/Azure-Samples/microsoft-azure-attestation.git
```

### Set-up Environment and Run the Tool
- In PowerShell, change directory
```
cd microsoft-azure-attestation\maa.jwt.verifier
```

- Execute the script win_setup_and_build.ps1 or, if desired, manually follow the script's steps:
```
.\win_setup_and_build.ps1
```
> These steps include installation of the dependencies (nuget, vkpkg packages), creating the project via CMake, and building it.
> Note that the intial execution of the script takes several minutes because it downloads and builds the dependencies.

- Get your MAA JWT for verification to the system.
- Change directory and run the tool:

```
cd <PATH-TO-EXE>
.\jwt-verifier.exe <PATH-TO-JWT>\jwt.txt
```

The tool suceeded if returned:
```
---     SUCCESS - Verified attestation certificate quote
```

## Linux | Build and Run

### Prerequisites
- Dev System with Ubuntu_18.04
- MAA JWT sample token as an input for the verification

### Get Sources
- `[Optional]` Setup the Git Bash with a new SSH key for the GirHub portal:
    - Gegerate New SSH Key: `ssh-keygen -t ed25519 -C "<EMAIL>"`
    - Go through the settings prompt and provide wanted values for the key
    - `eval "$(ssh-agent -s)" && ssh-add ~/.ssh/id_ed25519 && cat ~/.ssh/id_ed25519.pub`
    - Add the new SSH key to the GitHub keys: https://github.com/settings/keys
    - `git config --global user.email "you@example.com"`
    - `git config --global user.name "Your Name"`

- Clone the repo
```
git clone --recursive git@github.com:Azure-Samples/microsoft-azure-attestation.git
```

Or 

```
git clone --recursive https://github.com/Azure-Samples/microsoft-azure-attestation.git
```

### Set-up Environment and Run the Tool
- Change directory
```
cd microsoft-azure-attestation/maa.jwt.verifier
```

- Execute the script ubuntu_setup_and_build.sh or, if desired, manually follow the script's steps:
```
./ubuntu_setup_and_build.sh
```

- `[Optional]` Check the tool's usage syntax:
```
./out/jwt-verifier
```

- Get your MAA JWT for verification to the system.
- Change directory and verify quote in JWT:
```
./out/jwt-verifier [options] <jwt-filename>
```

For instance:
```
./out/jwt-verifier -v ~/samples/jwt.txt
```

