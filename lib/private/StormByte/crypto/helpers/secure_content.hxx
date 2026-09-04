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

#include <StormByte/crypto/visibility.h>

#include <cstddef>
#include <secblock.h>

/**
 * @brief Private helpers of the Crypto module.
 */
namespace StormByte::Crypto::Helpers {
	/**
	 * @class SecureContent
	 * @brief Wiped byte buffer on Crypto++ SecByteBlock.
	 *
	 * Exact size; no terminator. Implementation only.
	 */
	class STORMBYTE_CRYPTO_PRIVATE SecureContent {
		public:
			/**
			 * @brief From raw bytes.
			 * @param data Source, or nullptr if size is 0.
			 * @param size Byte count.
			 */
			SecureContent(const void* data, std::size_t size) noexcept;

			/**
			 * @brief Copy constructor (deleted).
			 */
			SecureContent(const SecureContent&) = delete;

			/**
			 * @brief Copy assignment (deleted).
			 */
			SecureContent& operator=(const SecureContent&) = delete;

			/**
			 * @brief Zero the buffer.
			 */
			void Wipe() noexcept;

			/**
			 * @brief Stored size.
			 * @return Byte count.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Pointer to the bytes while this object lives.
			 * @return Data pointer.
			 */
			const unsigned char* Data() const noexcept;

			/**
			 * @brief Constant-time equality.
			 * @param other Other buffer.
			 * @return true if length and content match.
			 */
			bool Equal(const SecureContent& other) const noexcept;

		private:
			CryptoPP::SecByteBlock m_block;	///< Backing storage
	};
}
