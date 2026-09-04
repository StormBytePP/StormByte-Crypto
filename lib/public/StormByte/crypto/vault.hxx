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

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <string>
#include <unordered_map>
#include <utility>

/**
 * @brief Crypto module of the StormByte suite.
 */
namespace StormByte::Crypto {
	/**
	 * @class Vault
	 * @brief Named collection of @ref Password objects.
	 *
	 * Move-only. Destroying the vault, or calling Clear()/Remove(), drops
	 * the last owner of each password and triggers the wipe.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Vault {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Empty vault.
			 */
			Vault() = default;

			/**
			 * @brief Copy constructor (deleted).
			 */
			Vault(const Vault&) = delete;

			/**
			 * @brief Move constructor.
			 * @param other Vault to move.
			 */
			Vault(Vault&& other) noexcept;

			/**
			 * @brief Destructor. Releases every stored password.
			 */
			~Vault() noexcept;

			/**
			 * @brief Copy assignment (deleted).
			 */
			Vault& operator=(const Vault&) = delete;

			/**
			 * @brief Move assignment.
			 * @param other Vault to move.
			 * @return Reference to this vault.
			 */
			Vault& operator=(Vault&& other) noexcept;
			/** @} */

			/**
			 * @brief Store or overwrite a named password.
			 * @param name Identifier.
			 * @param password Password to share.
			 */
			void Store(std::string name, Password password) noexcept;

			/**
			 * @brief Look up a password.
			 * @param name Identifier.
			 * @return Password, or an error if the name is missing.
			 * @note The returned Password shares the buffer.
			 */
			ExpectedPassword Get(const std::string& name) const noexcept;

			/**
			 * @brief Whether a name exists.
			 * @param name Identifier.
			 * @return true if present.
			 */
			bool Contains(const std::string& name) const noexcept;

			/**
			 * @brief Drop one password.
			 * @param name Identifier.
			 */
			void Remove(const std::string& name) noexcept;

			/**
			 * @brief Drop every password.
			 */
			void Clear() noexcept;

			/**
			 * @brief Number of stored passwords.
			 * @return Count.
			 */
			std::size_t Size() const noexcept;

			/**
			 * @brief Whether the vault is empty.
			 * @return true if Size() is 0.
			 */
			bool Empty() const noexcept;

		private:
			std::unordered_map<std::string, Password> m_passwords;	///< Named passwords
	};
}
