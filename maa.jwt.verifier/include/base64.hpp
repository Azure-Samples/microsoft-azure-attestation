/***************************************************************************************
*    Title: Base64 encoding
*    Author: Martin Vorbrodt
*    Date: retrieved 12/06/2020
*    Code version: commit 920f9265ff763e8a89c6ee6385162dd6aec3dbad
*    Availability: https://github.com/mvorbrodt/blog/blob/master/src/base64.hpp
*    Code samples from https://vorbrodt.blog/
***************************************************************************************/

#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

namespace base64
{
	inline static const char kEncodeLookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	inline static const char kPadCharacter = '=';

	using byte = std::uint8_t;

	std::string encode(const std::vector<byte>& input);
	std::vector<byte> decode(const std::string& input);
}
