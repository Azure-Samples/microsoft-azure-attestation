# This optional helper script is provided for sample convenience. Dependencies may
# instead be preinstalled and the verifier built directly with CMake and MSBuild.

Write-Warning @"
This sample is provided for informational purposes only and is not a production
best-practices solution. This optional convenience script changes the local build
environment and is used at your own risk. It is not guaranteed to work across all
Windows versions or machine configurations. You may preinstall the dependencies
and build the verifier directly with CMake and MSBuild instead.
"@

# Update Submodules
#
git submodule update --init --recursive

# Define Local Directories
#
$cur_dir=Get-Location
$tmp_pkg_dir = Join-Path ([System.IO.Path]::GetTempPath()) "maa-jwt-verifier-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tmp_pkg_dir | Out-Null

# Download Nuget Tool
#
$nuget_file_name = "nuget.exe"
$nuget_source = "https://dist.nuget.org/win-x86-commandline/latest/$nuget_file_name"
$nuget_destination = "$tmp_pkg_dir\$nuget_file_name"
Invoke-WebRequest -Uri $nuget_source -OutFile $nuget_destination
dir $tmp_pkg_dir
$nuget_exe = "$nuget_destination"

# Download and Install OE Nuget Packages
#
$oe_version = "0.19.17"
$oe_name = "open-enclave.OEHOSTVERIFY"
$oe_nupkg_name = "$oe_name.$oe_version.nupkg"
$oe_source = "https://github.com/openenclave/openenclave/releases/download/v$oe_version/$oe_nupkg_name"
$oe_sha256 = "CDF192151D6C4C41C8246A71B3CA1C47000502F9EE9F54AEA91244D7EA007C44"
echo "OE Source = $oe_source"
$oe_destination = "$tmp_pkg_dir\$oe_nupkg_name"
Invoke-WebRequest -Uri $oe_source -OutFile $oe_destination
If((Get-FileHash -Path $oe_destination -Algorithm SHA256).Hash -ne $oe_sha256)
{
    throw "Open Enclave package checksum validation failed."
}
dir $tmp_pkg_dir

$oe_output_directory = "$tmp_pkg_dir\oe_installed_nupkg"
$oe_nuget_args = @('install', $oe_name, '-Source', $tmp_pkg_dir, '-OutputDirectory', $oe_output_directory, '-ExcludeVersion')
& $nuget_exe $oe_nuget_args
$oe_path = "$oe_output_directory\$oe_name\OEHOSTVERIFY\openenclave"
dir $oe_path

# Download and Install MS Azure DCAP Nuget Packages
#
$msdcap_version = "1.13.1"
$msdcap_name = "Microsoft.Azure.DCAP"
$msdcap_nupkg_name = "$msdcap_name.$msdcap_version.nupkg"
$msdcap_source = "https://github.com/microsoft/Azure-DCAP-Client/releases/download/$msdcap_version/microsoft.azure.dcap.$msdcap_version.nupkg"
$msdcap_sha256 = "1C2598EF5F195647666DC29E8B3C914AC4BD160F861539B53ADB8A24FF1FD8AC"
$msdcap_destination = "$tmp_pkg_dir\$msdcap_nupkg_name"
Invoke-WebRequest -Uri $msdcap_source -OutFile $msdcap_destination
If((Get-FileHash -Path $msdcap_destination -Algorithm SHA256).Hash -ne $msdcap_sha256)
{
    throw "Azure DCAP package checksum validation failed."
}
dir $tmp_pkg_dir

$msdcap_output_directory = "$tmp_pkg_dir\msdcap_installed_nupkg"
$msdcap_nuget_args = @('install', $msdcap_name, '-Source', $tmp_pkg_dir, '-OutputDirectory', $msdcap_output_directory, '-ExcludeVersion')
$msdcap_path = $msdcap_output_directory
$msdcap_nuget_path = "$msdcap_path\$msdcap_name"
& $nuget_exe $msdcap_nuget_args
# Install DCAP nuget
cd "$msdcap_nuget_path\tools"
$msdcap_library_path = "$tmp_pkg_dir\azure_dcap"
& ".\InstallAzureDCAP.ps1" $msdcap_library_path
dir $msdcap_path
dir $msdcap_library_path
[System.Environment]::SetEnvironmentVariable('AZDCAP_DEBUG_LOG_LEVEL','FATAL')

# Build and Install vcpkg Dependencies
#
$vcpkg_dir="$cur_dir\vendors\vcpkg"

cd $vcpkg_dir
.\bootstrap-vcpkg.bat -disableMetrics
.\vcpkg.exe integrate install
.\vcpkg.exe install curl[openssl] openssl --triplet x64-windows

$project_name = "jwt-verifier" 
$project_dir="$cur_dir"

cd $project_dir
$project_out = "$cur_dir\tmp\out"
If((Test-Path $project_out))
{
    Remove-Item $project_out -Force -Recurse
}
New-Item -ItemType Directory -Force -Path $project_out

cd $project_out 

cmake -DCMAKE_PREFIX_PATH="$oe_path\lib\openenclave\cmake" -DCMAKE_TOOLCHAIN_FILE="$vcpkg_dir/scripts/buildsystems/vcpkg.cmake" -DNUGET_PACKAGE_PATH="$msdcap_nuget_path" $project_dir

$msbuild_exe=$Args[0]
If($msbuild_exe -eq $null) {
    $msbuild_exe = (Get-ChildItem -Recurse -Path "C:\Program Files (x86)\Microsoft Visual Studio\" -Include "msbuild.exe").fullname | Select -First 1
}

& $msbuild_exe "$project_name.sln"

echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo ""

cd .\Debug
$project_exe_dir = Get-Location 
echo "$project_name.exe's location: $project_exe_dir"
dir $project_exe_dir 
echo "Returning to $cur_dir..."

cd $cur_dir

