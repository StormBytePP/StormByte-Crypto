/*
* Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
*
* This file is part of StormByte-Crypto.
*
* StormByte-Crypto is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License version 3
* or later, as published by the Free Software Foundation.
*
* StormByte-Crypto is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with StormByte-Crypto. If not, see
* <https://www.gnu.org/licenses/lgpl-3.0.html>.
*/

#pragma once

#include <StormByte/crypto/helpers/secure_wipe.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/visibility.h>

#include <secblock.h>
#include <string>

/**
 * @brief Private keypair implementation.
 */
namespace StormByte::Crypto::Implementation::KeyPair {
	/**
	 * @brief Encode a SecByteBlock as Base64.
	 * @param block Source.
	 * @return Base64 string.
	 */
	std::string EncodeSecBlockBase64(const CryptoPP::SecByteBlock& block) noexcept;

	/**
	 * @brief Decode Base64 into a SecByteBlock.
	 * @param encoded Base64.
	 * @return Decoded block.
	 */
	CryptoPP::SecByteBlock DecodeSecBlockBase64(const std::string& encoded) noexcept;

	/**
	 * @brief Wrap raw key bytes into a Password and wipe the source.
	 * @param block Source block (wiped).
	 * @return Password.
	 */
	inline Password PasswordFromSecBlock(CryptoPP::SecByteBlock& block) noexcept
	{
		Password result(block.data(), block.size());
		Helpers::SecureWipe(block);
		return result;
	}
}
