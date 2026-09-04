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

#include <StormByte/clonable.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filesystem>
#include <optional>
#include <string>

/**
 * @brief Keypairs of the Crypto module.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @enum Type
	 * @brief Available keypair algorithms.
	 */
	enum class Type {
		DSA,		///< DSA
		ECC,		///< Elliptic-curve encryption
		ECDH,		///< ECDH
		ECDSA,		///< ECDSA
		ED25519,	///< Ed25519
		RSA,		///< RSA
		X25519,		///< X25519
	};

	/**
	 * @enum StorageFormat
	 * @brief On-disk encoding.
	 */
	enum class StorageFormat {
		PEM,	///< OpenSSL PEM
		DER,	///< Binary DER
	};

	/**
	 * @class Generic
	 * @brief Abstract keypair. Concrete algorithms derive from this.
	 *
	 * Public key is a non-secret string (typically Base64 SPKI DER).
	 * Private key, when present, is a @ref StormByte::Crypto::Password
	 * holding PKCS#8 or native DER and is wiped with the last owner.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @name Construction
			 * @{
			 */
			/**
			 * @brief Copy constructor.
			 * @param other Keypair to copy.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor.
			 * @param other Keypair to move.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Destructor. Drops the private-key handle.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment.
			 * @param other Keypair to copy.
			 * @return Reference to this keypair.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment.
			 * @param other Keypair to move.
			 * @return Reference to this keypair.
			 */
			Generic& operator=(Generic&& other) noexcept = default;
			/** @} */

			/**
			 * @brief Algorithm of this keypair.
			 * @return Keypair type.
			 */
			inline enum Type Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Public key string.
			 * @return Public material.
			 */
			inline const std::string& PublicKey() const noexcept {
				return m_public_key;
			}

			/**
			 * @brief Whether a private key is stored.
			 * @return true if present.
			 */
			inline bool HasPrivateKey() const noexcept {
				return m_private_key.has_value();
			}

			/**
			 * @brief Private key, if any.
			 * @return Shared Password, or empty.
			 */
			inline const std::optional<Password>& PrivateKey() const noexcept {
				return m_private_key;
			}

			/**
			 * @name Persistence
			 * @{
			 */
			/**
			 * @brief Write public and private files under a directory. Private key unencrypted.
			 * @param directory Existing directory.
			 * @param baseName File stem.
			 * @param format PEM or DER.
			 * @return true on success.
			 */
			bool Save(const std::filesystem::path& directory, const std::string& baseName, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Write public and private files. Private key encrypted (prefer PEM).
			 * @param directory Existing directory.
			 * @param baseName File stem.
			 * @param encryptPassword Password for the private file.
			 * @param format Prefer PEM when encrypting.
			 * @return true on success.
			 */
			bool Save(const std::filesystem::path& directory, const std::string& baseName, const Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Write only the public key.
			 * @param filePath Destination.
			 * @param format PEM or DER.
			 * @return true on success.
			 */
			bool SavePublic(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Write only the private key, unencrypted.
			 * @param filePath Destination.
			 * @param format PEM or DER.
			 * @return true on success.
			 */
			bool SavePrivate(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Write only the private key, encrypted (prefer PEM).
			 * @param filePath Destination.
			 * @param encryptPassword Password.
			 * @param format Prefer PEM.
			 * @return true on success.
			 */
			bool SavePrivate(const std::filesystem::path& filePath, const Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;
			/** @} */

		protected:
			enum Type m_type;						///< Algorithm
			std::string m_public_key;				///< Public material
			std::optional<Password> m_private_key;	///< Private material, if any

			/**
			 * @brief Construct with algorithm and material.
			 * @param type Algorithm.
			 * @param public_key Public material.
			 * @param private_key Optional private Password.
			 */
			inline Generic(enum Type type, std::string public_key, std::optional<Password> private_key = std::nullopt):
				m_type(type), m_public_key(std::move(public_key)), m_private_key(std::move(private_key)) {}
	};

	/**
	 * @brief Generate a keypair.
	 * @param type Algorithm.
	 * @param bits Key size in bits.
	 * @return Keypair pointer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, unsigned short bits) noexcept;

	/**
	 * @brief Load from separate public and private files. Format is auto-detected.
	 * @param publicKeyPath Public file, or empty.
	 * @param privateKeyPath Private file, or empty. No default: a single path is @ref Load(const std::filesystem::path&).
	 * @return Keypair pointer, or nullptr.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept;

	/**
	 * @brief Load from separate files; decrypt the private key if needed.
	 * @param publicKeyPath Public file, or empty.
	 * @param privateKeyPath Private file.
	 * @param password Password for an encrypted private key.
	 * @return Keypair pointer, or nullptr.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath, const Password& password) noexcept;

	/**
	 * @brief Load from one file (public, private, or concatenated PEM).
	 * @param path Key file.
	 * @return Keypair pointer, or nullptr.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path) noexcept;

	/**
	 * @brief Load from one file; decrypt if needed.
	 * @param path Key file.
	 * @param password Password for encrypted private material.
	 * @return Keypair pointer, or nullptr.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path, const Password& password) noexcept;
}
