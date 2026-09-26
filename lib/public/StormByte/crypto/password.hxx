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
