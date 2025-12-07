#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace KeyPair
 * @brief The namespace containing all the keypair-related classes.
 */
namespace StormByte::Crypto::KeyPair {
	/**
	 * @class ECC
	 * @brief A ECC keypair class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ECC final: public Generic {
		public:
			/**
			 * @brief Constructor
			 * @param public_key The public key.
			 * @param private_key The private key (optional).
			 */
			inline ECC(const std::string& public_key, std::optional<std::string> private_key = std::nullopt):
			Generic(Type::ECC, public_key, private_key) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ECC keypair to copy from.
			 */
			ECC(const ECC& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other ECC keypair to move from.
			 */
			ECC(ECC&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			~ECC() noexcept 									= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ECC keypair to copy from.
			 * @return Reference to this ECC keypair.
			 */
			ECC& operator=(const ECC& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ECC keypair to move from.
			 * @return Reference to this ECC keypair.
			 */
			ECC& operator=(ECC&& other) noexcept				= default;

			/**
			 * @brief Clone the ECC keypair.
			 * @return A pointer to the cloned ECC keypair.
			 */
			PointerType 										Clone() const noexcept override {
				return std::make_shared<ECC>(*this);
			}

			/**
			 * @brief Move the ECC keypair.
			 * @return A pointer to the moved ECC keypair.
			 */
			PointerType 										Move() noexcept override {
				return std::make_shared<ECC>(std::move(*this));
			}

			/**
			 * @brief Generate a new ECC keypair.
			 * @param key_size The size of the key in bits.
			 * @return A pointer to the generated ECC keypair.
			 */
			static PointerType 									Generate(unsigned short key_size = 256) noexcept;
	};
}