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

#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/helpers/secure_content.hxx>

#include <cstddef>

/**
 * @namespace Helpers
 * @brief Private helpers for the Crypto module (headers are not installed).
 */
namespace StormByte::Crypto::Helpers {

	/**
	 * @struct PasswordAccess
	 * @brief Internal read access to @ref StormByte::Crypto::Password bytes.
	 *
	 * Only for library implementation. Not part of the public API.
	 */
	struct PasswordAccess {
		/**
		 * @brief Pointer to the password/key bytes.
		 * @param password The password instance.
		 * @return Pointer to the data, or nullptr if empty/invalid.
		 */
		static const unsigned char* Data(const Password& password) noexcept {
			return password.m_data ? password.m_data->Data() : nullptr;
		}

		/**
		 * @brief Exact byte length of the stored material.
		 * @param password The password instance.
		 * @return Size in bytes.
		 */
		static std::size_t Size(const Password& password) noexcept {
			return password.m_data ? password.m_data->Size() : 0;
		}
	};
}
