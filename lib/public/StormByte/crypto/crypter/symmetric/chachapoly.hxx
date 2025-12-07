#pragma once

#include <StormByte/crypto/crypter/symmetric/generic.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class ChaChaPoly
	 * @brief A symmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC ChaChaPoly final: public Symmetric {
		public:
			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 */
			inline 													ChaChaPoly(const std::string& password):
			Symmetric(Type::ChaChaPoly, password) {}

			/**
			 * @brief Copy constructor
			 * @param other The other ChaChaPoly crypter to copy from.
			 */
			ChaChaPoly(const ChaChaPoly& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other ChaChaPoly crypter to move from.
			 */
			ChaChaPoly(ChaChaPoly&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~ChaChaPoly() noexcept 							= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other ChaChaPoly crypter to copy from.
			 * @return Reference to this ChaChaPoly crypter.
			 */
			ChaChaPoly& operator=(const ChaChaPoly& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other ChaChaPoly crypter to move from.
			 * @return Reference to this ChaChaPoly crypter.
			 */
			ChaChaPoly& operator=(ChaChaPoly&& other) noexcept		= default;

			/**
			 * @brief Clone the ChaChaPoly crypter.
			 * @return A pointer to the cloned ChaChaPoly crypter.
			 */
			inline PointerType 										Clone() const noexcept override {
				return std::make_shared<ChaChaPoly>(*this);
			}

			/**
			 * @brief Move the ChaChaPoly crypter.
			 * @return A pointer to the moved ChaChaPoly crypter.
			 */
			inline PointerType 										Move() noexcept override {
				return std::make_shared<ChaChaPoly>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the encryption logic.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool 													DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the encryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			Buffer::Consumer 										DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the decryption logic.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool 													DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**	
			 * @brief Implementation of the decryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			Buffer::Consumer 										DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}