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

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/password.hxx>

/**
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Symmetric
	 * @brief Password-based symmetric crypter.
	 *
	 * Copies share the same @ref StormByte::Crypto::Password. The buffer is
	 * wiped when the last owner is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Symmetric: public Generic {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			Symmetric(const Symmetric& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			Symmetric(Symmetric&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Symmetric() noexcept override;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			Symmetric& operator=(const Symmetric& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			Symmetric& operator=(Symmetric&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Password used by this crypter.
			 * @return Shared password.
			 * @note Shares ownership of the underlying bytes.
			 */
			inline const class Password& Password() const noexcept {
				return m_password;
			}

			/**
			 * @brief Random password of raw bytes (not text).
			 * @param length Number of bytes.
			 * @return Password.
			 */
			static class Password RandomPassword(size_t length = 32) noexcept;

		protected:
			class Password m_password;	///< Shared password

			/**
			 * @brief Construct with a cipher and a password.
			 * @param type Cipher.
			 * @param password Password.
			 */
			inline Symmetric(enum Type type, class Password password):
				Generic(type), m_password(std::move(password)) {}
	};

	/**
	 * @brief Factory for a symmetric crypter.
	 * @param type Cipher.
	 * @param password Password.
	 * @return Crypter pointer, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(enum Type type, class Password password) noexcept;
}
