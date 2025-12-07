#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class DSA
	 * @brief A DSA keypair class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC DSA final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param public_key The public key.
			 * @param private_key The private key (optional).
			 */
			inline DSA(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			Generic(Type::DSA, public_key, private_key) {}

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
			 * @brief Virtual destructor
			 */
			~DSA() noexcept 									= default;

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
			PointerType 										Clone() const noexcept override {
				return std::make_shared<DSA>(*this);
			}

			/**
			 * @brief Move the DSA keypair.
			 * @return A pointer to the moved DSA keypair.
			 */
			PointerType 										Move() noexcept override {
				return std::make_shared<DSA>(std::move(*this));
			}

			/**
			 * @brief Generate a new DSA keypair.
			 * @param key_size The size of the key in bits.
			 * @return A pointer to the generated DSA keypair.
			 */
			static PointerType 									Generate(unsigned short key_size = 2048) noexcept;
	};
}