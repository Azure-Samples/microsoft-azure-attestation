# MAA JWT Verifier Sample

## Purpose

This sample demonstrates the certificate-evidence portion of validating a Microsoft Azure Attestation (MAA) JWT. It:

1. Reads the `jku` and `kid` values from the JWT header.
2. Retrieves the corresponding JSON Web Key Set.
3. Selects the signing certificate identified by `kid`.
4. Extracts the legacy Open Enclave/SGX attestation extension (`1.3.6.1.4.1.311.105.1`).
5. Calls `oe_verify_attestation_certificate` and exposes the verified enclave identity through a callback.

The sample supports only signing certificates that contain this legacy SGX extension. It does not verify signing certificates that use other attestation-evidence formats.

This code is intended as a reference for integrating certificate-evidence verification. Consumers must implement the validation required by the remote-attestation standards and security policy applicable to their environment before using the result for a security decision.

## Get the Source

Install Git before continuing. Clone the repository with its submodules, then change to the repository root.

On Windows, run the following commands from a PowerShell prompt:

```powershell
git clone --recursive https://github.com/Azure-Samples/microsoft-azure-attestation.git
Set-Location .\microsoft-azure-attestation
```

On Ubuntu, run the following commands from a Bash shell:

```bash
git clone --recursive https://github.com/Azure-Samples/microsoft-azure-attestation.git
cd microsoft-azure-attestation
```

The remaining instructions assume the current directory is this repository root.

## Build Scripts

The Windows and Ubuntu scripts are optional convenience helpers. They download dependencies, modify the local build environment, and build the verifier. Review each script before running it. The scripts are provided for sample use and are not guaranteed to work on every operating-system release or machine configuration.

Dependencies may instead be installed separately and the project built directly with CMake.

## Input

The verifier reads a compact MAA JWT from the first line of the input file. The JWT must reference a reachable JSON Web Key Set whose selected signing certificate contains the legacy SGX extension described above.

This sample demonstrates the older validation flow for MAA signing certificates that contain the legacy Open Enclave/SGX extension. It does not support the newer generic attestation-evidence format used by current MAA signing certificates.

## Windows

### Windows Prerequisites

- 64-bit Windows with PowerShell
- Git
- CMake
- MSBuild with the Visual C++ build tools
- Internet access for dependency downloads

### Build on Windows

Open a PowerShell prompt and run the helper from the repository root:

```powershell
Set-Location .\maa.jwt.verifier
.\win_setup_and_build.ps1
```

The script attempts to locate MSBuild automatically. Optionally, if it cannot find MSBuild, use the following commands in the same PowerShell prompt to find it with `vswhere.exe`:

```powershell
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
& $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\MSBuild.exe'
```

Pass the returned path to the build script, for example:

```powershell
.\win_setup_and_build.ps1 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
```

The executable is written to `tmp\out\Debug\jwt-verifier.exe`.

### Run on Windows

From the `maa.jwt.verifier` directory, run:

```powershell
.\tmp\out\Debug\jwt-verifier.exe [--verbose] <path-to-jwt-file>
```

## Ubuntu Linux

### Ubuntu Prerequisites

- 64-bit Ubuntu 22.04
- `sudo` access for package installation
- Internet access for dependency downloads

Local SGX hardware is not required to verify evidence already contained in a signing certificate. The helper can therefore run on an Ubuntu 22.04 host, container, or WSL distribution.

### Build on Ubuntu

Run the helper from the repository root:

```bash
cd maa.jwt.verifier
./ubuntu_setup_and_build.sh
```

The script configures package repositories, installs host-verification dependencies, updates the shell environment, and writes the executable to `out/jwt-verifier`.

### Run on Ubuntu

From the `maa.jwt.verifier` directory, run:

```bash
./out/jwt-verifier [--verbose] <path-to-jwt-file>
```

### Run Ubuntu Locally with Docker

Docker Desktop can be used to build and run the Linux verifier locally without an Ubuntu host. Configure Docker Desktop to use Linux containers.

From the repository root, open a PowerShell prompt and create an Ubuntu 22.04 container with the repository mounted at `/workspace`:

```powershell
docker run --name maa-jwt-verifier -it -v "${PWD}:/workspace" -w /workspace/maa.jwt.verifier ubuntu:22.04
```

The prompt is now a Bash shell inside the Ubuntu container. Install `sudo`, then run the existing setup and build helper:

```bash
apt-get update
apt-get install -y sudo
./ubuntu_setup_and_build.sh
```

Run the verifier from the same Bash shell. The JWT file must be under the mounted repository so that it is available inside the container:

```bash
./out/jwt-verifier [--verbose] /workspace/<path-to-jwt-file>
```

After leaving the container, reopen its Bash shell from a PowerShell prompt with:

```powershell
docker start -ai maa-jwt-verifier
```

Remove the container from a PowerShell prompt when it is no longer needed:

```powershell
docker rm maa-jwt-verifier
```

## Output

When Open Enclave verifies the certificate evidence successfully, the tool prints:

```text
---     SUCCESS - Verified attestation certificate quote
```

With `--verbose`, it also prints the identity values returned to the verification callback.
