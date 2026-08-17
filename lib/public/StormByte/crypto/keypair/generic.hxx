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
		DSA,													///< Digital Signature Algorithm keypair
		ECC,													///< Elliptic Curve Cryptography keypair
		ECDH,													///< Elliptic Curve Diffie-Hellman keypair
		ECDSA,													///< ECDSA signature keypair
		ED25519,												///< ED25519 signature keypair
		RSA,													///< RSA keypair
		X25519,													///< X25519 key exchange keypair
	};

	/**
	 * @class Generic
	 * @brief A generic keypair class.
	 *
	 * The public key is stored as a non-secret string (typically Base64/PEM body).
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so that sensitive material is reference-counted and zeroized when the last
	 * owner is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic keypair to copy from.
			 */
			Generic(const Generic& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic keypair to move from.
			 */
			Generic(Generic&& other) noexcept					= default;

			/**
             * @brief Virtual destructor.
             *
             * Releases ownership of the private key handle. The underlying
             * secret is zeroized when no other @ref Password still shares it.
             */
            virtual ~Generic() noexcept							= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic keypair to copy from.
			 * @return Reference to this Generic keypair.
			 */
			Generic& operator=(const Generic& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic keypair to move from.
			 * @return Reference to this Generic keypair.
			 */
			Generic& operator=(Generic&& other) noexcept		= default;

			/**
			 * @brief Gets the type of the keypair.
			 * @return The type of the keypair.
			 */
			inline enum Type 									Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Gets the public key.
			 * @return A const reference to the public key string.
			 */
			inline const std::string& 							PublicKey() const noexcept {
				return m_public_key;
			}

			/**
			 * @brief Whether a private key is present.
			 * @return true if a private key is stored, false otherwise.
			 */
			inline bool 										HasPrivateKey() const noexcept {
				return m_private_key.has_value();
			}

			/**
			 * @brief Gets the private key, if present.
			 * @return Optional containing a @ref Password that shares ownership
			 *         of the private key material, or empty if none is stored.
			 * @note Do not create long-lived plain @c std::string copies of the
			 *       password contents; that bypasses the secure lifecycle.
			 */
			inline const std::optional<Password>& 				PrivateKey() const noexcept {
				return m_private_key;
			}

			/**
			 * @brief Saves the keypair to the specified directory.
			 * @param path The directory path to save the keys.
			 * @param name The base name for the key files.
			 * @return true if the keypair was saved successfully, false otherwise.
			 */
			virtual bool 										Save(const std::filesystem::path& path, const std::string& name) const noexcept;

		protected:
			enum Type m_type;									///< The type of keypair
			std::string m_public_key;							///< The public key (non-secret)
			std::optional<Password> m_private_key;				///< The private key (secret), if any

			/**
			 * @brief Constructor
			 * @param type The type of keypair.
			 * @param public_key The public key material.
			 * @param private_key Optional private key wrapped in @ref Password.
			 */
			inline 												Generic(enum Type type, std::string public_key, std::optional<Password> private_key = std::nullopt):
			m_type(type), m_public_key(std::move(public_key)), m_private_key(std::move(private_key)) {}
	};

	/**
	 * @brief Factory method to generate a keypair.
	 * @param type The type of keypair to generate.
	 * @param bits The key size in bits.
	 * @return A pointer to the created keypair.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Create(Type type, unsigned short bits) noexcept;

	/**
	 * @brief Load a keypair from public (and optional private) key files.
	 * @param publicKeyPath Path to the public key file.
	 * @param privateKeyPath Path to the private key file (may be empty).
	 * @return A pointer to the loaded keypair, or nullptr on failure.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept;
}
