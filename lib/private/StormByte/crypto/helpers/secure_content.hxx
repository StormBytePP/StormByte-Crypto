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
 * @namespace Helpers
 * @brief Private helpers for the Crypto module (headers are not installed).
 */
namespace StormByte::Crypto::Helpers {

	/**
	 * @class SecureContent
	 * @brief Opaque secure byte buffer backed by Crypto++ SecByteBlock.
	 *
	 * Stores an exact number of bytes (no forced null terminator).
	 * Must only be used from library implementation units.
	 */
	class STORMBYTE_CRYPTO_PRIVATE SecureContent {
		public:
			/**
			 * @brief Construct from raw bytes.
			 * @param data Pointer to source bytes (may be nullptr if size is 0).
			 * @param size Exact number of bytes to store.
			 */
			SecureContent(const void* data, std::size_t size) noexcept;

			SecureContent(const SecureContent&) = delete;
			SecureContent& operator=(const SecureContent&) = delete;

			/**
			 * @brief Securely zero the buffer.
			 */
			void Wipe() noexcept;

			/**
			 * @brief Byte length of the stored content.
			 * @return Size in bytes.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Pointer to the stored bytes (valid while this object lives).
			 * @return Pointer to the data, or valid empty pointer if size is 0.
			 */
			const unsigned char* Data() const noexcept;

			/**
			 * @brief Constant-time equality comparison.
			 * @param other The other buffer to compare with.
			 * @return true if lengths and contents match, false otherwise.
			 */
			bool Equal(const SecureContent& other) const noexcept;

		private:
			CryptoPP::SecByteBlock m_block;	///< Backing storage with cleanup allocator
	};
}
