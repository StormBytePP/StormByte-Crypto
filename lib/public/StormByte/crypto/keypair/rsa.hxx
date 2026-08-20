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
	 * @class RSA
	 * @brief An RSA keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC RSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline RSA(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::RSA, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other RSA keypair to copy from.
			 */
			RSA(const RSA& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other RSA keypair to move from.
			 */
			RSA(RSA&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~RSA() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other RSA keypair to copy from.
			 * @return Reference to this RSA keypair.
			 */
			RSA& operator=(const RSA& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other RSA keypair to move from.
			 * @return Reference to this RSA keypair.
			 */
			RSA& operator=(RSA&& other) noexcept = default;

			/**
			 * @brief Clone the RSA keypair.
			 * @return A pointer to the cloned RSA keypair.
			 */
			PointerType Clone() const override {
				return std::make_shared<RSA>(*this);
			}

			/**
			 * @brief Move this RSA keypair into a new owning pointer.
			 * @return A pointer to the moved RSA keypair.
			 */
			PointerType Move() override {
				return std::make_shared<RSA>(std::move(*this));
			}

			/**
			 * @brief Generate a new RSA keypair.
			 * @param bits The key size in bits.
			 * @return A pointer to the generated RSA keypair, or nullptr on failure.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
