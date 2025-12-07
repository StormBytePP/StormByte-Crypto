#pragma once

#include <StormByte/crypto/secret/generic.hxx>
#include <StormByte/crypto/keypair/ecdh.hxx>

/**
 * @namespace Secret
 * @brief The namespace containing all the secret-related classes.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @class ECDH
	 * @brief A generic secret class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												ECDH(KeyPair::Generic::PointerType keypair):
			Generic(Type::ECDH, keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												ECDH(const KeyPair::ECDH& keypair):
			Generic(Type::ECDH, keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												ECDH(KeyPair::ECDH&& keypair):
			Generic(Type::ECDH, keypair.Move()) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDH secret to copy from.
			 */
			ECDH(const ECDH& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDH secret to move from.
			 */
			ECDH(ECDH&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~ECDH() noexcept 									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDH secret to copy from.
			 * @return Reference to this ECDH secret.
			 */
			ECDH& operator=(const ECDH& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDH secret to move from.
			 * @return Reference to this ECDH secret.
			 */
			ECDH& operator=(ECDH&& other) noexcept				= default;

			/**
			 * @brief Clone the ECDH secret.
			 * @return A pointer to the cloned ECDH secret.
			 */
			inline PointerType 									Clone() const noexcept override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move the ECDH secret.
			 * @return A pointer to the moved ECDH secret.
			 */
			inline PointerType 									Move() noexcept override {
				return std::make_shared<ECDH>(std::move(*this));
			}

		private:
			/**
			 * @brief Shares the secret with a peer using their public key.
			 * @param peerPublicKey The peer's public key.
			 * @return An optional string containing the shared secret, or std::nullopt on failure.
			 */
			std::optional<std::string>							DoShare(const std::string& peerPublicKey) const noexcept override;
	};
}