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

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

/**
 * @brief Ciphers of the Crypto module.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @enum Type
	 * @brief Available ciphers.
	 */
	enum class Type {
		AES_GCM,		///< AES-GCM
		AES,			///< AES-CBC
		Camellia,		///< Camellia-CBC
		ChaChaPoly,		///< ChaCha20-Poly1305
		ECC,			///< Elliptic-curve encryption
		Serpent,		///< Serpent-CBC
		RSA,			///< RSA
		TwoFish,		///< Twofish-CBC
	};

	/**
	 * @class Generic
	 * @brief Abstract crypter. Concrete ciphers derive from this.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Crypter to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Crypter to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Crypter to copy.
			 * @return Reference to this crypter.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Crypter to move.
			 * @return Reference to this crypter.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @name Encrypt
			 * @{
			 */
			/**
			 * @brief Encrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(input, output);
			}

			/**
			 * @brief Encrypt a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Encrypt a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(input, output, ReadMode::Move);
			}

			/**
			 * @brief Encrypt a Consumer into another Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with ciphertext.
			 */
			inline Buffer::Consumer Encrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoEncrypt(consumer, mode);
			}
			/** @} */

			/**
			 * @name Decrypt
			 * @{
			 */
			/**
			 * @brief Decrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(input, output);
			}

			/**
			 * @brief Decrypt a read-only buffer (copy).
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Decrypt a buffer, consuming it.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			inline bool Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(input, output, ReadMode::Move);
			}

			/**
			 * @brief Decrypt a Consumer into another Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with plaintext.
			 */
			inline Buffer::Consumer Decrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoDecrypt(consumer, mode);
			}
			/** @} */

			/**
			 * @brief Cipher of this crypter.
			 * @return Crypter type.
			 */
			inline enum Type Type() const noexcept {
				return m_type;
			}

		protected:
			enum Type m_type;	///< Cipher

			/**
			 * @brief Construct with a cipher.
			 * @param type Cipher.
			 */
			inline Generic(enum Type type):
				m_type(type) {}

			/**
			 * @brief Encrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Encrypt a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with ciphertext.
			 */
			virtual Buffer::Consumer DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Decrypt a byte span.
			 * @param input Input bytes.
			 * @param output Destination buffer.
			 * @return true on success.
			 */
			virtual bool DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Decrypt a Consumer.
			 * @param consumer Input consumer.
			 * @param mode Copy or move.
			 * @return Consumer with plaintext.
			 */
			virtual Buffer::Consumer DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

		private:
			/**
			 * @brief Encrypt a buffer with an explicit read mode.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoEncrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Decrypt a buffer with an explicit read mode.
			 * @param input Input buffer.
			 * @param output Destination buffer.
			 * @param mode Copy or move.
			 * @return true on success.
			 */
			bool DoDecrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;
	};
}
