#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ECDH
	 * @brief A ECDH keypair class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECDH final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param public_key The public key.
			 * @param private_key The private key (optional).
			 */
			inline ECDH(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			Generic(Type::ECDH, public_key, private_key) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECDH keypair to copy from.
			 */
			ECDH(const ECDH& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other ECDH keypair to move from.
			 */
			ECDH(ECDH&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~ECDH() noexcept 									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECDH keypair to copy from.
			 * @return Reference to this ECDH keypair.
			 */
			ECDH& operator=(const ECDH& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECDH keypair to move from.
			 * @return Reference to this ECDH keypair.
			 */
			ECDH& operator=(ECDH&& other) noexcept				= default;

			/**
			 * @brief Clone the ECDH keypair.
			 * @return A pointer to the cloned ECDH keypair.
			 */
			PointerType 										Clone() const noexcept override {
				return std::make_shared<ECDH>(*this);
			}

			/**
			 * @brief Move the ECDH keypair.
			 * @return A pointer to the moved ECDH keypair.
			 */
			PointerType 										Move() noexcept override {
				return std::make_shared<ECDH>(std::move(*this));
			}

			/**
			 * @brief Generate a new ECDH keypair.
			 * @param key_size The size of the key in bits.
			 * @return A pointer to the generated ECDH keypair.
			 */
			static PointerType 									Generate(unsigned short key_size = 2048) noexcept;
	};
}