#pragma once

#include <StormByte/crypto/keypair/generic.hxx>
#include <StormByte/crypto/password.hxx>

#include <optional>
#include <string>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class DSA
	 * @brief A DSA keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC DSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline 												DSA(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
			Generic(Type::DSA, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other DSA keypair to copy from.
			 */
			DSA(const DSA& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other DSA keypair to move from.
			 */
			DSA(DSA&& other) noexcept							= default;

			/**
			 * @brief Destructor
			 */
			~DSA() noexcept override							= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other DSA keypair to copy from.
			 * @return Reference to this DSA keypair.
			 */
			DSA& operator=(const DSA& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other DSA keypair to move from.
			 * @return Reference to this DSA keypair.
			 */
			DSA& operator=(DSA&& other) noexcept				= default;

			/**
			 * @brief Clone the DSA keypair.
			 * @return A pointer to the cloned DSA keypair.
			 */
			PointerType 										Clone() const override {
				return std::make_shared<DSA>(*this);
			}

			/**
			 * @brief Move this DSA keypair into a new owning pointer.
			 * @return A pointer to the moved DSA keypair.
			 */
			PointerType 										Move() override {
				return std::make_shared<DSA>(std::move(*this));
			}

			/**
			 * @brief Generate a new DSA keypair.
			 * @param bits The key size in bits.
			 * @return A pointer to the generated DSA keypair, or nullptr on failure.
			 */
			static PointerType 									Generate(unsigned short bits) noexcept;
	};
}
