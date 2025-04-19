#pragma once

#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <optional>
#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class KeyPair
	 * @brief A class representing a public/private key pair.
	 * 
	 * A `KeyPair` can contain both a public key and a private key, or only a public key.
	 * - If only the public key is provided, the `KeyPair` can be used for encryption and signature verification.
	 * - If both the public and private keys are provided, the `KeyPair` can also be used for decryption and signing.
	 */
	class STORMBYTE_CRYPTO_PUBLIC KeyPair final {
		public:
			/**
			 * @brief Constructs a KeyPair with a public and private key.
			 * 
			 * This constructor creates a `KeyPair` that can be used for all cryptographic operations,
			 * including encryption, decryption, signing, and signature verification.
			 * 
			 * @param pub The public key.
			 * @param priv The private key.
			 */
			KeyPair(const std::string& pub, const std::string& priv) noexcept;

			/**
			 * @brief Constructs a KeyPair with a public key only.
			 * 
			 * This constructor creates a `KeyPair` that can only be used for encryption and signature verification.
			 * Decryption and signing operations will not be available because the private key is not provided.
			 * 
			 * @param pub The public key.
			 */
			KeyPair(const std::string& pub) noexcept;

			/**
			 * @brief Constructs a KeyPair with a public and private key (move version).
			 * 
			 * This constructor moves the public and private keys into the `KeyPair` instance.
			 * 
			 * @param pub The public key (rvalue reference).
			 * @param priv The private key (rvalue reference).
			 */
			KeyPair(std::string&& pub, std::string&& priv) noexcept;

			/**
			 * @brief Constructs a KeyPair with a public key only (move version).
			 * 
			 * This constructor moves the public key into the `KeyPair` instance.
			 * Decryption and signing operations will not be available because the private key is not provided.
			 * 
			 * @param pub The public key (rvalue reference).
			 */
			KeyPair(std::string&& pub) noexcept;

			/**
			 * @brief Copy constructor
			 * 
			 * Creates a copy of the given `KeyPair` instance.
			 * 
			 * @param other The `KeyPair` instance to copy.
			 */
			KeyPair(const KeyPair& other) 					= default;

			/**
			 * @brief Move constructor
			 * 
			 * Moves the given `KeyPair` instance into the current instance.
			 * 
			 * @param other The `KeyPair` instance to move.
			 */
			KeyPair(KeyPair&& other) noexcept 				= default;

			/**
			 * @brief Destructor
			 * 
			 * Cleans up the `KeyPair` instance. This includes releasing any resources associated with the public
			 * and private keys.
			 */
			~KeyPair() noexcept 							= default;

			/**
			 * @brief Copy assignment operator
			 * 
			 * Assigns the values from the given `KeyPair` instance to the current instance.
			 * 
			 * @param other The `KeyPair` instance to copy.
			 * @return A reference to the current instance.
			 */
			KeyPair& operator=(const KeyPair& other) 		= default;

			/**
			 * @brief Move assignment operator
			 * 
			 * Moves the values from the given `KeyPair` instance to the current instance.
			 * 
			 * @param other The `KeyPair` instance to move.
			 * @return A reference to the current instance.
			 */
			KeyPair& operator=(KeyPair&& other) noexcept 	= default;

			/**
			 * @brief Returns the public key.
			 * 
			 * The public key is always available in a `KeyPair` and can be used for encryption and signature verification.
			 * 
			 * @return The public key as a string.
			 */
			const std::string& 								PublicKey() const noexcept;

			/**
			 * @brief Returns the private key.
			 * 
			 * The private key is optional in a `KeyPair`. If the private key is not available, the `KeyPair` can only
			 * be used for encryption and signature verification. Decryption and signing will not be possible.
			 * 
			 * @return The private key as an optional string. If the private key is not available, the optional will be empty.
			 */
			const std::optional<std::string>& 				PrivateKey() const noexcept;

			/**
			 * @brief Generates a random key pair using the specified algorithm and key size.
			 * 
			 * This method generates both a public and private key, creating a `KeyPair` that can be used for all cryptographic operations.
			 * 
			 * @param algo The algorithm to use for key generation.
			 * @param key_size The size of the key to generate.
			 * @return An Expected containing the generated KeyPair or an error.
			 */
			[[nodiscard]]
			static Expected<KeyPair, Exception> 			Generate(const Algorithm::Asymmetric& algo, const size_t& key_size) noexcept;

			[[nodiscard]]
			static Expected<KeyPair, Exception> 			Generate(const Algorithm::Asymmetric& algo, const std::string& curve_name) noexcept;

			/**
			 * @brief Generates a random key pair for signing using the specified algorithm and key size.
			 * 
			 * This method generates both a public and private key, creating a `KeyPair` that can be used for signing and signature verification.
			 * 
			 * @param algo The signing algorithm to use.
			 * @param key_size The size of the key to generate.
			 * @return An Expected containing the generated KeyPair or an error.
			 */
			[[nodiscard]]
			static Expected<KeyPair, Exception> 			Generate(const Algorithm::Sign& algo, const size_t& key_size) noexcept;

			[[nodiscard]]
			static Expected<KeyPair, Exception> 			Generate(const Algorithm::Sign& algo, const std::string& curve_name) noexcept;

		private:
			std::string m_public_key; ///< The public key.
			std::optional<std::string> m_private_key; ///< The private key (optional).
	};
}