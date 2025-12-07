#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ED25519
	 * @brief An ED25519 keypair class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ED25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param public_key The public key.
			 * @param private_key The private key (optional).
			 */
			inline ED25519(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			Generic(Type::ED25519, public_key, private_key) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ED25519 keypair to copy from.
			 */
			ED25519(const ED25519& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other ED25519 keypair to move from.
			 */
			ED25519(ED25519&& other) noexcept					= default;

			/**
			 * @brief Destructor
			 */
			~ED25519() noexcept									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ED25519 keypair to copy from.
			 * @return Reference to this ED25519 keypair.
			 */
			ED25519& operator=(const ED25519& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ED25519 keypair to move from.
			 * @return Reference to this ED25519 keypair.
			 */
			ED25519& operator=(ED25519&& other) noexcept		= default;

			/**
			 * @brief Clone the ED25519 keypair.
			 * @return A pointer to the cloned ED25519 keypair.
			 */
			PointerType 										Clone() const noexcept override {
				return std::make_shared<ED25519>(*this);
			}

			/**
			 * @brief Move the ED25519 keypair.
			 * @return A pointer to the moved ED25519 keypair.
			 */
			PointerType 										Move() noexcept override {
				return std::make_shared<ED25519>(std::move(*this));
			}

			/**
			 * @brief Generates a new ED25519 keypair.
			 * @param key_size The key size in bits (must be 256 for ED25519).
			 * @return A pointer to the generated ED25519 keypair, or nullptr on failure.
			 */
			static PointerType									Generate(unsigned short key_size = 256) noexcept;
	};
}
