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

#include <StormByte/crypto/helpers/secure_content.hxx>
#include <StormByte/crypto/password.hxx>

#include <cstddef>

/**
 * @brief Private helpers of the Crypto module.
 */
namespace StormByte::Crypto::Helpers {
	/**
	 * @struct PasswordAccess
	 * @brief Read access to @ref StormByte::Crypto::Password bytes.
	 *
	 * Implementation only. Not installed.
	 */
	struct PasswordAccess {
		/**
		 * @brief Pointer to the stored bytes.
		 * @param password Password.
		 * @return Data pointer, or nullptr if empty.
		 */
		static const unsigned char* Data(const Password& password) noexcept {
			return password.m_data ? password.m_data->Data() : nullptr;
		}

		/**
		 * @brief Stored size in bytes.
		 * @param password Password.
		 * @return Byte count.
		 */
		static std::size_t Size(const Password& password) noexcept {
			return password.m_data ? password.m_data->Size() : 0;
		}
	};
}
