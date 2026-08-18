#pragma once

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <secblock.h>
#include <string>

namespace StormByte::Crypto::Implementation::KeyPair {
	/**
	 * @brief Encode a SecByteBlock to Base64 (public / non-secret material).
	 */
	std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& block) noexcept;

	/**
	 * @brief Decode Base64 into a SecByteBlock.
	 */
	CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& encoded) noexcept;

	/**
	 * @brief Wrap raw key bytes into a Password and wipe the source block.
	 */
	inline Password PasswordFromSecBlock(CryptoPP::SecByteBlock& block) noexcept
	{
		Password result(block.data(), block.size());
		Helpers::SecureWipe(block);
		return result;
	}
}
