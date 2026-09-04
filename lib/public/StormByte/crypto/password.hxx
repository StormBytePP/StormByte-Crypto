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
#include <memory>
#include <string>
#include <utility>

namespace StormByte::Crypto::Helpers {
	struct SecureContent;
	struct PasswordAccess;
}

/**
 * @brief Crypto module of the StormByte suite.
 */
namespace StormByte::Crypto {
	/**
	 * @class Password
	 * @brief Shared, wiped container for passwords and raw key material.
	 *
	 * Bytes live in a shared @ref Helpers::SecureContent and are wiped when
	 * the last owner is destroyed. Copies share the same buffer. There is no
	 * public view of the raw bytes.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Password {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief From a string. The argument is wiped before return.
			 * @param value Password characters.
			 */
			explicit Password(std::string value) noexcept;

			/**
			 * @brief From a C string up to the terminator. The source is not wiped.
			 * @param value Null-terminated password.
			 */
			explicit Password(const char* value) noexcept;

			/**
			 * @brief From raw bytes. Exact size; no terminator is added.
			 * @param data Bytes, or nullptr if size is 0.
			 * @param size Number of bytes.
			 */
			Password(const void* data, std::size_t size) noexcept;

			/**
			 * @brief Copy constructor. Shares the buffer.
			 * @param other Password to copy.
			 */
			Password(const Password& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Password to move.
			 */
			Password(Password&& other) noexcept = default;

			/**
			 * @brief Destructor. Wipes the buffer if this is the last owner.
			 */
			~Password() = default;

			/**
			 * @brief Copy assignment.
			 * @param other Password to copy.
			 * @return Reference to this password.
			 */
			Password& operator=(const Password& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Password to move.
			 * @return Reference to this password.
			 */
			Password& operator=(Password&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Stored size in bytes.
			 * @return Byte count.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Whether Size() is 0.
			 * @return true if empty.
			 */
			bool Empty() const noexcept;

			/**
			 * @brief true if the password is not empty.
			 */
			explicit operator bool() const noexcept;

			/**
			 * @brief Constant-time equality.
			 * @param other Other password.
			 * @return true if length and content match.
			 */
			bool operator==(const Password& other) const noexcept;

			/**
			 * @brief Inequality.
			 * @param other Other password.
			 * @return true if not equal.
			 */
			bool operator!=(const Password& other) const noexcept;

		private:
			friend struct Helpers::PasswordAccess;

			std::shared_ptr<Helpers::SecureContent> m_data;	///< Shared wiped storage
	};
}
