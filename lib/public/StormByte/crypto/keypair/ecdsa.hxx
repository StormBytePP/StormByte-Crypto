#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ECDSA
	 * @brief An ECDSA keypair class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param public_key The public key.
			 * @param private_key The private key (optional).
			 */
			inline ECDSA(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			Generic(Type::ECDSA, public_key, private_key) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDSA keypair to copy from.
			 */
			ECDSA(const ECDSA& other)							= default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDSA keypair to move from.
			 */
			ECDSA(ECDSA&& other) noexcept						= default;

			/**
			 * @brief Destructor
			 */
			~ECDSA() noexcept									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDSA keypair to copy from.
			 * @return Reference to this ECDSA keypair.
			 */
			ECDSA& operator=(const ECDSA& other)				= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDSA keypair to move from.
			 * @return Reference to this ECDSA keypair.
			 */
			ECDSA& operator=(ECDSA&& other) noexcept			= default;

			/**
			 * @brief Clone the ECDSA keypair.
			 * @return A pointer to the cloned ECDSA keypair.
			 */
			PointerType 										Clone() const noexcept override {
				return std::make_shared<ECDSA>(*this);
			}

			/**
			 * @brief Move the ECDSA keypair.
			 * @return A pointer to the moved ECDSA keypair.
			 */
			PointerType 										Move() noexcept override {
				return std::make_shared<ECDSA>(std::move(*this));
			}

			/**
			 * @brief Generates a new ECDSA keypair.
			 * @param key_size The size of the key in bits (256, 384, or 521).
			 * @return A pointer to the generated ECDSA keypair, or nullptr on failure.
			 */
			static PointerType 									Generate(unsigned short key_size = 256) noexcept;
	};
}
