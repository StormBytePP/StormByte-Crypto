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
	 * @class ECDH
	 * @brief An Elliptic Curve Diffie-Hellman keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64/PEM body).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline ECDH(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
				Generic(Type::ECDH, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDH keypair to copy from.
			 */
			ECDH(const ECDH& other) = default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDH keypair to move from.
			 */
			ECDH(ECDH&& other) noexcept = default;

			/**
			 * @brief Destructor
			 */
			~ECDH() noexcept override = default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDH keypair to copy from.
			 * @return Reference to this ECDH keypair.
			 */
			ECDH& operator=(const ECDH& other) = default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDH keypair to move from.
			 * @return Reference to this ECDH keypair.
			 */
			ECDH& operator=(ECDH&& other) noexcept = default;

			/**
			 * @brief Clone the ECDH keypair.
			 * @return A pointer to the cloned ECDH keypair.
			 */
			PointerType Clone() const override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move this ECDH keypair into a new owning pointer.
			 * @return A pointer to the moved ECDH keypair.
			 */
			PointerType Move() override {
				return std::make_shared<ECDH>(std::move(*this));
			}

			/**
			 * @brief Generate a new ECDH keypair.
			 * @param bits The curve size in bits (e.g. 256).
			 * @return A pointer to the generated ECDH keypair, or nullptr on failure.
			 */
			static PointerType Generate(unsigned short bits) noexcept;
	};
}
