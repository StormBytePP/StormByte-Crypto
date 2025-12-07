#pragma once

#include <StormByte/clonable.hxx>
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
	 * @brief A generic  class.
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
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 						= default;

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
			 * @brief Gets the type of keypair.
			 * @return The type of keypair.
			 */
			inline const std::string&							PublicKey() const noexcept {
				return m_public_key;
			}

			/**
			 * @brief Gets the private key of the keypair.
			 * @return The private key of the keypair.
			 */
			inline const std::optional<std::string>&			PrivateKey() const noexcept {
				return m_private_key;
			}

			/**
			 * @brief Gets the type of keypair.
			 * @return The type of keypair.
			 */
			inline enum Type 									Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Saves the keypair to the specified file paths.
			 * @param path The directory path to save the keys.
			 * @param name The base name for the key files.
			 * @return true if the keypair was saved successfully, false otherwise.
			 */
			bool 												Save(const std::filesystem::path& path, const std::string& name) const noexcept;

		protected:
			enum Type m_type;									///< The type of keypair
			std::string m_public_key;							///< The public key
			std::optional<std::string> m_private_key;			///< The private key

			/**
			 * @brief Constructor
			 * @param type The type of keypair.
			 */
			inline 												Generic(enum Type type, const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			m_type(type), m_public_key(public_key), m_private_key(private_key) {}

		private:
			
	};

	/**
	 * @brief Factory method to generate a keypair.
	 * @param type The type of keypair to generate.
	 * @param bits The key size in bits.
	 * @return A pointer to the created keypair.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Generate(Type type, unsigned short bits) noexcept;

	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Load(const std::filesystem::path& publicKeyPath, const std::filesystem::path& privateKeyPath) noexcept;
}