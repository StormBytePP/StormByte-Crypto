#pragma once

#include <StormByte/crypto/signer/generic.hxx>
#include <StormByte/crypto/keypair/dsa.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @class DSA
	 * @brief A generic signer signer class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC DSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													DSA(KeyPair::Generic::PointerType keypair):
			Generic(Type::DSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													DSA(const KeyPair::DSA& keypair):
			Generic(Type::DSA, keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													DSA(KeyPair::DSA&& keypair):
			Generic(Type::DSA, keypair) {}

			/**
			 * @brief Copy constructor
			 * @param other The other DSA signer to copy from.
			 */
			DSA(const DSA& other)									= default;

			/**
			 * @brief Move constructor
			 * @param other The other DSA signer to move from.
			 */
			DSA(DSA&& other) noexcept								= default;

			/**
			 * @brief Virtual destructor
			 */
			~DSA() noexcept 										= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other DSA signer to copy from.
			 * @return Reference to this DSA signer.
			 */
			DSA& operator=(const DSA& other)						= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other DSA signer to move from.
			 * @return Reference to this DSA signer.
			 */
			DSA& operator=(DSA&& other) noexcept					= default;

			/**
			 * @brief Clone the DSA signer.
			 * @return A pointer to the cloned DSA signer.
			 */
			PointerType 											Clone() const noexcept override {
				return std::make_shared<DSA>(*this);
			}

			/**
			 * @brief Move the DSA signer.
			 * @return A pointer to the moved DSA signer.
			 */
			PointerType 											Move() noexcept override {
				return std::make_shared<DSA>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the signing logic.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if signing was successful, false otherwise.
			 */
			bool 													DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the signing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to sign.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the signed data.
			 */
			Buffer::Consumer 										DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the verification logic.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			bool 													DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept override;
			/**
			 * @brief Implementation of the verification logic for Consumer buffers.
			 * @param consumer The Consumer buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the verified data.
			 */
			bool 													DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept override;
	};
}