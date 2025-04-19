#pragma once

#include <StormByte/crypto/keypair.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Secret
	 * @brief A class for managing shared secret operations.
	 *
	 * This class provides methods for generating key pairs and deriving shared secrets
	 * using various secret-sharing algorithms (e.g., ECDH).
	 */
	class STORMBYTE_CRYPTO_PUBLIC Secret final {
		public:
			/**
			 * @brief Constructs a Secret instance with an algorithm and a key pair.
			 * 
			 * This constructor initializes the `Secret` instance with the specified secret-sharing algorithm
			 * and a key pair. The key pair is used for deriving shared secrets.
			 * 
			 * @param algorithm The secret-sharing algorithm to use.
			 * @param key_pair The key pair to use for shared secret operations.
			 */
			explicit Secret(const Algorithm::SecretShare& algorithm, const KeyPair& key_pair) noexcept;

			/**
			 * @brief Constructs a Secret instance with an algorithm and a key pair (move version).
			 * 
			 * This constructor initializes the `Secret` instance with the specified secret-sharing algorithm
			 * and a key pair. The key pair is moved into the instance to avoid unnecessary copying.
			 * 
			 * @param algorithm The secret-sharing algorithm to use.
			 * @param key_pair The key pair to use for shared secret operations (rvalue reference).
			 */
			explicit Secret(const Algorithm::SecretShare& algorithm, KeyPair&& key_pair) noexcept;

			/**
			 * @brief Copy constructor for the Secret class.
			 * 
			 * Creates a copy of the given `Secret` instance.
			 * 
			 * @param secret The `Secret` instance to copy.
			 */
			Secret(const Secret& secret) 					= default;

			/**
			 * @brief Move constructor for the Secret class.
			 * 
			 * Moves the given `Secret` instance into the current instance.
			 * 
			 * @param secret The `Secret` instance to move.
			 */
			Secret(Secret&& secret) noexcept 				= default;

			/**
			 * @brief Destructor for the Secret class.
			 * 
			 * Cleans up the `Secret` instance.
			 */
			~Secret() noexcept 								= default;

			/**
			 * @brief Copy assignment operator for the Secret class.
			 * 
			 * Assigns the values from the given `Secret` instance to the current instance.
			 * 
			 * @param secret The `Secret` instance to copy.
			 * @return A reference to the updated `Secret` instance.
			 */
			Secret& operator=(const Secret& secret) 		= default;

			/**
			 * @brief Move assignment operator for the Secret class.
			 * 
			 * Moves the values from the given `Secret` instance to the current instance.
			 * 
			 * @param secret The `Secret` instance to move.
			 * @return A reference to the updated `Secret` instance.
			 */
			Secret& operator=(Secret&& secret) noexcept 	= default;

			/**
			 * @brief Sets the peer's public key for shared secret derivation.
			 * 
			 * This method sets the public key of the peer, which is required for deriving the shared secret.
			 * 
			 * @param peer_public_key The public key of the peer.
			 */
			void 											PeerPublicKey(const std::string& peer_public_key) noexcept;

			/**
			 * @brief Derives the shared secret using the private key and the peer's public key.
			 * 
			 * This method derives the shared secret by combining the private key of the local key pair
			 * with the public key of the peer. The derived shared secret can be used for secure communication.
			 * 
			 * @return An Expected containing the derived shared secret or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception> 				Content() const noexcept;

			/**
			 * @brief Returns the key pair associated with this Secret instance.
			 * 
			 * This method returns the key pair used by the `Secret` instance for shared secret operations.
			 * 
			 * @return The key pair.
			 */
			[[nodiscard]]
			const KeyPair& KeyPair() const noexcept;

		private:
			Algorithm::SecretShare m_algorithm; 			///< The secret-sharing algorithm to use.
			class KeyPair m_key_pair;           			///< The key pair used for shared secret operations.
			std::string m_peer_public_key;      			///< The peer's public key.
	};
}