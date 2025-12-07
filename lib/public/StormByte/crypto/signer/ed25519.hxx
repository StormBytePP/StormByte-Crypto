#pragma once

#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/crypto/keypair/ed25519.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class ED25519
	 * @brief A generic signer signer class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ED25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 														ED25519(KeyPair::Generic::PointerType keypair):
			Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 														ED25519(const KeyPair::ED25519& keypair):
			Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 														ED25519(KeyPair::ED25519&& keypair):
			Generic(Type::ED25519, keypair) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ED25519 signer to copy from.
			 */
			ED25519(const ED25519& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other ED25519 signer to move from.
			 */
			ED25519(ED25519&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~ED25519() noexcept 										= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ED25519 signer to copy from.
			 * @return Reference to this ED25519 signer.
			 */
			ED25519& operator=(const ED25519& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ED25519 signer to move from.
			 * @return Reference to this ED25519 signer.
			 */
			ED25519& operator=(ED25519&& other) noexcept				= default;

			/**
			 * @brief Clone the ED25519 signer.
			 * @return A pointer to the cloned ED25519 signer.
			 */
			PointerType 												Clone() const noexcept override {
				return std::make_shared<ED25519>(*this);
			}

			/**
			 * @brief Move the ED25519 signer.
			 * @return A pointer to the moved ED25519 signer.
			 */
			PointerType 												Move() noexcept override {
				return std::make_shared<ED25519>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the signing logic.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if signing was successful, false otherwise.
			 */
			bool 														DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the signing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to sign.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the signed data.
			 */
			Buffer::Consumer 											DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the verification logic.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			bool 														DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept override;
			/**
			 * @brief Implementation of the verification logic for Consumer buffers.
			 * @param consumer The Consumer buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the verified data.
			 */
			bool 														DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept override;
	};
}