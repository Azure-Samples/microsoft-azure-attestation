# Update Submodules
#
git submodule update --init --recursive

# Define Local Directories
#
$cur_dir=Get-Location
$tmp_pkg_dir = "$cur_dir\tmp"

If((Test-Path $tmp_pkg_dir))
{
    Remove-Item $tmp_pkg_dir -Force -Recurse
}
New-Item -ItemType Directory -Force -Path $tmp_pkg_dir

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
$oe_version = "0.17.7"
$oe_name = "open-enclave.OEHOSTVERIFY"
$oe_nupkg_name = "$oe_name.$oe_version.nupkg"
$oe_source = "https://github.com/openenclave/openenclave/releases/download/v$oe_version/$oe_nupkg_name"
echo "OE Source = $oe_source"
$oe_destination = "$tmp_pkg_dir\$oe_nupkg_name"
Invoke-WebRequest -Uri $oe_source -OutFile $oe_destination
dir $tmp_pkg_dir

$oe_output_directory = "$tmp_pkg_dir\oe_installed_nupkg"
$oe_nuget_args = @('install', $oe_name, '-Source', $tmp_pkg_dir, '-OutputDirectory', $oe_output_directory, '-ExcludeVersion')
#TODO try to copy to the TMP
$oe_path = "C:\$oe_name"
$oe_xcopy_args = @('/i', '/y', '/e', "$oe_output_directory\$oe_name\openenclave", $oe_path)
& $nuget_exe $oe_nuget_args
xcopy $oe_xcopy_args
dir $oe_path

# Download and Install MS Azure DCAP Nuget Packages
#
$msdcap_version = "1.10.0"
$msdcap_name = "Microsoft.Azure.DCAP"
$msdcap_nupkg_name = "$msdcap_name.$msdcap_version.nupkg"
$msdcap_source = "https://www.nuget.org/api/v2/package/Microsoft.Azure.DCAP/$msdcap_version"
$msdcap_destination = "$tmp_pkg_dir\$msdcap_nupkg_name"
Invoke-WebRequest -Uri $msdcap_source -OutFile $msdcap_destination
dir $tmp_pkg_dir

$msdcap_output_directory = "$tmp_pkg_dir\msdcap_installed_nupkg"
$msdcap_nuget_args = @('install', $msdcap_name, '-Source', $tmp_pkg_dir, '-OutputDirectory', $msdcap_output_directory, '-ExcludeVersion')
$msdcap_path = 'C:\azure_dcap'
$msdcap_nuget_path = "$msdcap_path\$msdcap_name"
& $nuget_exe $msdcap_nuget_args
$msdcap_xcopy_args = @('/i', '/y', '/e', $msdcap_output_directory, $msdcap_path)
xcopy $msdcap_xcopy_args
# Install DCAP nuget
cd "$msdcap_nuget_path\tools"
& ".\InstallAzureDCAP.ps1" "$msdcap_nuget_path/DCAP_Components/build/lib/native/Libraries"
dir $msdcap_path
dir "$msdcap_nuget_path/DCAP_Components/build/lib/native/Libraries"
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

