#pragma once

#include <StormByte/crypto/secret/generic.hxx>
#include <StormByte/crypto/keypair/x25519.hxx>

/**
 * @namespace Secret
 * @brief The namespace containing all the secret-related classes.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @class X25519
	 * @brief A generic secret class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 													X25519(KeyPair::Generic::PointerType keypair):
			Generic(Type::X25519, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 													X25519(const KeyPair::X25519& keypair):
			Generic(Type::X25519, keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 													X25519(KeyPair::X25519&& keypair):
			Generic(Type::X25519, keypair.Move()) {}

			/**
			 * @brief Copy constructor
			 * @param other The other X25519 secret to copy from.
			 */
			X25519(const X25519& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other X25519 secret to move from.
			 */
			X25519(X25519&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~X25519() noexcept 										= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other X25519 secret to copy from.
			 * @return Reference to this X25519 secret.
			 */
			X25519& operator=(const X25519& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other X25519 secret to move from.
			 * @return Reference to this X25519 secret.
			 */
			X25519& operator=(X25519&& other) noexcept				= default;

			/**
			 * @brief Clone the X25519 secret.
			 * @return A pointer to the cloned X25519 secret.
			 */
			inline PointerType 										Clone() const noexcept override {
				return std::make_shared<X25519>(*this);
			}

			/**
			 * @brief Move the X25519 secret.
			 * @return A pointer to the moved X25519 secret.
			 */
			inline PointerType 										Move() noexcept override {
				return std::make_shared<X25519>(std::move(*this));
			}

		private:
			/**
			 * @brief Shares the secret with a peer using their public key.
			 * @param peerPublicKey The peer's public key.
			 * @return An optional string containing the shared secret, or std::nullopt on failure.
			 */
			std::optional<std::string>								DoShare(const std::string& peerPublicKey) const noexcept override;
	};
}