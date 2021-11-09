#pragma once
#include <windows.h>
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\resource.h>
#include <wil\result.h>
#pragma warning(pop)
#include <bcrypt.h>
#include <memory>
#include <vector>

class Sha256Hash
{
public:
    Sha256Hash(wil::unique_bcrypt_hash && hashHandle)
        : _hash(std::move(hashHandle))
    {}

    static std::unique_ptr<Sha256Hash> Create()
    {
        wil::unique_bcrypt_hash hashHandle;

        THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE,
            hashHandle.addressof(),
            nullptr,
            0,
            nullptr,
            0,
            0));

        return std::make_unique<Sha256Hash>(std::move(hashHandle));
    }

    std::vector<uint8_t> HashAndFinish(const std::vector<uint8_t> &input)
    {
        if (!input.empty() )
        {
            THROW_IF_NTSTATUS_FAILED(BCryptHashData(
                _hash.get(),
                const_cast<PUCHAR>(input.data()),
                static_cast<ULONG>(input.size()),
                0));
        }

        DWORD hashLength;
        DWORD cbResult;
        THROW_IF_NTSTATUS_FAILED(BCryptGetProperty(_hash.get(), BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &cbResult, 0));

        std::vector<uint8_t> returnValue = std::vector<uint8_t>(hashLength);

        THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
            _hash.get(),
            returnValue.data(),
            hashLength,
            0));

        return returnValue;
    }

private:
    wil::unique_bcrypt_hash _hash;
};

