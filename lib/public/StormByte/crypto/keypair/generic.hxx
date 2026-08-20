#pragma once

#include <StormByte/clonable.hxx>
#include <StormByte/crypto/password.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

#include <filesystem>
#include <optional>
#include <string>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @enum Type
	 * @brief The types of keypairs available.
	 */
	enum class Type {
		DSA,		///< Digital Signature Algorithm keypair
		ECC,		///< Elliptic Curve Cryptography keypair
		ECDH,		///< Elliptic Curve Diffie-Hellman keypair
		ECDSA,		///< ECDSA signature keypair
		ED25519,	///< ED25519 signature keypair
		RSA,		///< RSA keypair
		X25519,		///< X25519 key exchange keypair
	};

	/**
	 * @enum StorageFormat
	 * @brief On-disk encoding for key material.
	 *
	 * PEM is the usual OpenSSL text form (Base64 + BEGIN/END headers).
	 * DER is raw ASN.1 binary (also used for many .cer/.crt key blobs).
	 */
	enum class StorageFormat {
		PEM,	///< OpenSSL-compatible PEM (text)
		DER,	///< Binary DER / CER-style ASN.1
	};

	/**
	 * @class Generic
	 * @brief A generic keypair class.
	 *
	 * The public key is stored as a non-secret string (typically Base64 of SPKI DER).
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * holding PKCS#8 (or algorithm-native) DER bytes, zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic keypair to copy from.
			 */
			Generic(const Generic& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic keypair to move from.
			 */
			Generic(Generic&& other) noexcept = default;

			/**
			 * @brief Virtual destructor.
			 *
			 * Releases ownership of the private key handle. The underlying
			 * secret is zeroized when no other @ref Password still shares it.
			 */
			virtual ~Generic() noexcept = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic keypair to copy from.
			 * @return Reference to this Generic keypair.
			 */
			Generic& operator=(const Generic& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic keypair to move from.
			 * @return Reference to this Generic keypair.
			 */
			Generic& operator=(Generic&& other) noexcept = default;

			/**
			 * @brief Gets the type of the keypair.
			 * @return The type of the keypair.
			 */
			inline enum Type Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Gets the public key.
			 * @return A const reference to the public key string.
			 */
			inline const std::string& PublicKey() const noexcept {
				return m_public_key;
			}

			/**
			 * @brief Whether a private key is present.
			 * @return true if a private key is stored, false otherwise.
			 */
			inline bool HasPrivateKey() const noexcept {
				return m_private_key.has_value();
			}

			/**
			 * @brief Gets the private key, if present.
			 * @return Optional containing a @ref Password that shares ownership
			 *         of the private key material, or empty if none is stored.
			 * @note Do not create long-lived plain @c std::string copies of the
			 *       password contents; that bypasses the secure lifecycle.
			 */
			inline const std::optional<Password>& PrivateKey() const noexcept {
				return m_private_key;
			}

			/**
			 * @brief Save public and private keys as separate files under a directory.
			 *
			 * Writes @p baseName + public/private suffixes according to @p format
			 * (e.g. @c name.pub.pem / @c name.pem, or @c .der).
			 * Private key is stored unencrypted.
			 *
			 * @param directory Directory that must already exist.
			 * @param baseName Base file name without extension.
			 * @param format PEM or DER.
			 * @return true on success, false otherwise.
			 */
			bool Save(const std::filesystem::path& directory, const std::string& baseName, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Save public and private keys as separate files; encrypt the private key.
			 *
			 * Public key is always plain. Private key uses OpenSSL-compatible
			 * traditional PEM encryption when @p format is PEM (AES-256-CBC).
			 * DER + password is not written as raw DER (would be ambiguous);
			 * prefer PEM when encrypting.
			 *
			 * @param directory Directory that must already exist.
			 * @param baseName Base file name without extension.
			 * @param encryptPassword Password used to encrypt the private key.
			 * @param format Prefer @ref StorageFormat::PEM when encrypting.
			 * @return true on success, false otherwise.
			 */
			bool Save(const std::filesystem::path& directory, const std::string& baseName, const Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Save only the public key to a single file.
			 * @param filePath Destination file path.
			 * @param format PEM or DER.
			 * @return true on success, false otherwise.
			 */
			bool SavePublic(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Save only the private key (unencrypted) to a single file.
			 * @param filePath Destination file path.
			 * @param format PEM or DER.
			 * @return true on success, false otherwise.
			 */
			bool SavePrivate(const std::filesystem::path& filePath, StorageFormat format = StorageFormat::PEM) const noexcept;

			/**
			 * @brief Save only the private key encrypted to a single file.
			 * @param filePath Destination file path.
			 * @param encryptPassword Password used to encrypt the private key.
			 * @param format Prefer PEM (OpenSSL traditional encrypted private key).
			 * @return true on success, false otherwise.
			 */
			bool SavePrivate(const std::filesystem::path& filePath, const Password& encryptPassword, StorageFormat format = StorageFormat::PEM) const noexcept;

		protected:
			enum Type m_type;						///< The type of keypair
			std::string m_public_key;				///< The public key (non-secret)
			std::optional<Password> m_private_key;	///< The private key (secret), if any

			/**
			 * @brief Constructor
			 * @param type The type of keypair.
			 * @param public_key The public key material.
			 * @param private_key Optional private key wrapped in @ref Password.
			 */
			inline Generic(enum Type type, std::string public_key, std::optional<Password> private_key = std::nullopt):
				m_type(type), m_public_key(std::move(public_key)), m_private_key(std::move(private_key)) {}
	};

	/**
	 * @brief Factory method to generate a keypair.
	 * @param type The type of keypair to generate.
	 * @param bits The key size in bits.
	 * @return A pointer to the created keypair.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Create(Type type, unsigned short bits) noexcept;

	/**
	 * @brief Load a keypair from separate public and private key files.
	 *
	 * Format (PEM vs DER) is auto-detected from content.
	 * Pass an empty @p privateKeyPath for public-only, or an empty @p publicKeyPath
	 * when the private file alone is enough (public will be derived when possible).
	 * If the private key is encrypted, use the overload that takes a @ref Password.
	 *
	 * @param publicKeyPath Path to the public key file (may be empty).
	 * @param privateKeyPath Path to the private key file (may be empty).
	 * @return A pointer to the loaded keypair, or nullptr on failure.
	 *
	 * @note @p privateKeyPath has no default argument so that a single-path
	 *       call resolves unambiguously to @ref Load(const std::filesystem::path&).
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept;

	/**
	 * @brief Load from separate files; decrypt private key with @p password if needed.
	 * @param publicKeyPath Path to the public key file (may be empty).
	 * @param privateKeyPath Path to the private key file.
	 * @param password Password for an encrypted private key.
	 * @return A pointer to the loaded keypair, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath, const Password& password) noexcept;

	/**
	 * @brief Load from a single file (auto-detect contents).
	 *
	 * Supported layouts:
	 * - Public only
	 * - Private only (public is derived when possible)
	 * - Concatenated PEM blocks (private + public)
	 *
	 * @param path Path to the key file.
	 * @return A pointer to the loaded keypair, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path) noexcept;

	/**
	 * @brief Load from a single file; decrypt if the private material is encrypted.
	 * @param path Path to the key file.
	 * @param password Password for encrypted private key material.
	 * @return A pointer to the loaded keypair, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType Load(const std::filesystem::path& path, const Password& password) noexcept;
}
