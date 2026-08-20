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
	 * @class ED25519
	 * @brief An ED25519 keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ED25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline ED25519(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::ED25519, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ED25519 keypair to copy from.
			 */
			ED25519(const ED25519& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ED25519 keypair to move from.
			 */
			ED25519(ED25519&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ED25519() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ED25519 keypair to copy from.
			 * @return Reference to this ED25519 keypair.
			 */
			ED25519& operator=(const ED25519& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ED25519 keypair to move from.
			 * @return Reference to this ED25519 keypair.
			 */
			ED25519& operator=(ED25519&& other) noexcept = default;

			/**
			 * @brief Clone the ED25519 keypair.
			 * @return A pointer to the cloned ED25519 keypair.
			 */
			PointerType Clone() const override {
				return std::make_shared<ED25519>(*this);
			}

			/**
			 * @brief Move this ED25519 keypair into a new owning pointer.
			 * @return A pointer to the moved ED25519 keypair.
			 */
			PointerType Move() override {
				return std::make_shared<ED25519>(std::move(*this));
			}

			/**
			 * @brief Generate a new ED25519 keypair.
			 * @param bits Ignored (ED25519 is fixed-size); kept for API uniformity.
			 * @return A pointer to the generated ED25519 keypair, or nullptr on failure.
			 */
			static PointerType Generate(unsigned short bits = 0) noexcept;
	};
}
