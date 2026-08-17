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
	 * @class X25519
	 * @brief An X25519 key exchange keypair class.
	 *
	 * The private key, when present, is stored as a @ref StormByte::Crypto::Password
	 * so sensitive material is reference-counted and zeroized when the last owner
	 * is destroyed.
	 */
	class STORMBYTE_CRYPTO_PUBLIC X25519 final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param publicKey The public key material (typically Base64).
			 * @param privateKey Optional private key wrapped in @ref Password.
			 */
			inline 												X25519(std::string publicKey, std::optional<Password> privateKey = std::nullopt):
			Generic(Type::X25519, std::move(publicKey), std::move(privateKey)) {}

			/**
			 * @brief Copy constructor
			 * @param other The other X25519 keypair to copy from.
			 */
			X25519(const X25519& other)							= default;

			/**
			 * @brief Move constructor
			 * @param other The other X25519 keypair to move from.
			 */
			X25519(X25519&& other) noexcept						= default;

			/**
			 * @brief Destructor
			 */
			~X25519() noexcept override							= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other X25519 keypair to copy from.
			 * @return Reference to this X25519 keypair.
			 */
			X25519& operator=(const X25519& other)				= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other X25519 keypair to move from.
			 * @return Reference to this X25519 keypair.
			 */
			X25519& operator=(X25519&& other) noexcept			= default;

			/**
			 * @brief Clone the X25519 keypair.
			 * @return A pointer to the cloned X25519 keypair.
			 */
			PointerType 										Clone() const override {
				return std::make_shared<X25519>(*this);
			}

			/**
			 * @brief Move this X25519 keypair into a new owning pointer.
			 * @return A pointer to the moved X25519 keypair.
			 */
			PointerType 										Move() override {
				return std::make_shared<X25519>(std::move(*this));
			}

			/**
			 * @brief Generate a new X25519 keypair.
			 * @param bits Ignored (X25519 is fixed-size); kept for API uniformity.
			 * @return A pointer to the generated X25519 keypair, or nullptr on failure.
			 */
			static PointerType 									Generate(unsigned short bits = 0) noexcept;
	};
}
