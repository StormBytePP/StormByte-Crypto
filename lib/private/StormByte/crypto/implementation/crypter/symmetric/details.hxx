/*
 * Copyright (C) 2024-2026 David C. Manuelda (StormBytePP)
 *
 * This file is part of StormByte-Crypto.
 *
 * StormByte-Crypto original source is dual-licensed:
 *
 * 1. GNU Lesser General Public License v3.0 (or later)
 *    You may redistribute and/or modify this file under the terms of the
 *    GNU Lesser General Public License as published by the Free Software
 *    Foundation, either version 3 of the License, or (at your option)
 *    any later version.
 *
 * 2. Commercial license
 *    Alternatively, this file may be used under the terms of a commercial
 *    license agreement with the copyright holder
 *    (David C. Manuelda <StormByte@gmail.com>).
 *
 * Both licenses apply only to original StormByte-Crypto source in this
 * repository. They do not cover other StormByte modules or any third-party
 * material shipped with this repository (including everything under
 * thirdparty/, in particular Crypto++, bundled libbzip2, the StormByte-Buffer
 * tree and the StormByte suite it vendors), which remains under its own license.
 *
 * Neither license grants any patent rights. Any patent licenses required
 * to use this software or third-party components must be obtained separately
 * from the patent holders.
 *
 * StormByte-Crypto is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with StormByte-Crypto. If not, see
 * <https://www.gnu.org/licenses/lgpl-3.0.html>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-StormByte-Commercial
 */

#pragma once

#include <StormByte/crypto/helpers/password_view.hxx>
#include <StormByte/crypto/implementation/crypter/details.hxx>
#include <StormByte/crypto/secure/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <cstddef>
#include <pwdbased.h>
#include <secblock.h>
#include <span>

/**
 * @brief Private symmetric crypter implementation.
 */
namespace StormByte::Crypto::Implementation::Crypter::Symmetric {
#ifdef STORMBYTE_CRYPTO_INSECURE_PBKDF2_ITERATIONS_FOR_CI
	inline constexpr unsigned int kPbkdf2Iterations = 1000;		///< CI only
#else
	inline constexpr unsigned int kPbkdf2Iterations = 600000;	///< Production
#endif

	/**
	 * @brief Derive a key with PBKDF2-HMAC.
	 * @tparam CryptoHMAC HMAC hash.
	 * @param key Pre-sized output.
	 * @param salt Salt.
	 * @param password Password.
	 * @return Crypto++ DeriveKey result, or 0.
	 */
	template<class CryptoHMAC>
	size_t DeriveKey(CryptoPP::SecByteBlock& key,
					const CryptoPP::SecByteBlock& salt,
					const Secure::Password& password) noexcept
	{
		try {
			CryptoPP::PKCS5_PBKDF2_HMAC<CryptoHMAC> pbkdf2;
			const unsigned char* pwdData = Helpers::PasswordAccess::Data(password);
			const std::size_t pwdSize = Helpers::PasswordAccess::Size(password);
			return pbkdf2.DeriveKey(
				key,
				key.size(),
				0,
				pwdData ? pwdData : reinterpret_cast<const uint8_t*>(""),
				pwdSize,
				salt,
				salt.size(),
				kPbkdf2Iterations
			);
		} catch (...) {
			return 0;
		}
	}

	/**
	 * @brief SetKeyWithIV when the type has it.
	 */
	template<typename CryptorT>
	auto SetKeyIVImpl(CryptorT& c,
					const CryptoPP::SecByteBlock& key, size_t keylen,
					const CryptoPP::SecByteBlock& iv, size_t ivlen, int)
		-> decltype(c.SetKeyWithIV(key, keylen, iv, ivlen), void())
	{
		c.SetKeyWithIV(key, keylen, iv, ivlen);
	}

	/**
	 * @brief Fallback: SetKeyWithoutResync + Resync.
	 */
	template<typename CryptorT>
	void SetKeyIVImpl(CryptorT& c,
					const CryptoPP::SecByteBlock& key, size_t keylen,
					const CryptoPP::SecByteBlock& iv, size_t ivlen, long)
	{
		c.SetKeyWithoutResync(key.data(), keylen, CryptoPP::g_nullNameValuePairs);
		c.Resync(iv.data(), static_cast<int>(ivlen));
	}

	/**
	 * @brief Set key and IV on a Crypto++ cipher.
	 */
	template<typename CryptorT>
	void SetKeyIV(CryptorT& c,
				const CryptoPP::SecByteBlock& key, size_t keylen,
				const CryptoPP::SecByteBlock& iv, size_t ivlen)
	{
		SetKeyIVImpl(c, key, keylen, iv, ivlen, 0);
	}
}
