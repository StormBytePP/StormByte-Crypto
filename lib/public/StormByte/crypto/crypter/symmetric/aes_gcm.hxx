#pragma once

#include <StormByte/crypto/crypter/symmetric/generic.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class AES_GCM
	 * @brief A symmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC AES_GCM final: public Symmetric {
		public:
			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 */
			inline 												AES_GCM(const std::string& password):
			Symmetric(Type::AES_GCM, password) {}

			/**
			 * @brief Copy constructor
			 * @param other The other AES_GCM crypter to copy from.
			 */
			AES_GCM(const AES_GCM& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other AES_GCM crypter to move from.
			 */
			AES_GCM(AES_GCM&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~AES_GCM() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other AES_GCM crypter to copy from.
			 * @return Reference to this AES_GCM crypter.
			 */
			AES_GCM& operator=(const AES_GCM& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other AES_GCM crypter to move from.
			 * @return Reference to this AES_GCM crypter.
			 */
			AES_GCM& operator=(AES_GCM&& other) noexcept		= default;

			/**
			 * @brief Clone the AES_GCM crypter.
			 * @return A pointer to the cloned AES_GCM crypter.
			 */
			inline PointerType 									Clone() const noexcept override {
				return std::make_shared<AES_GCM>(*this);
			}

			/**
			 * @brief Move the AES_GCM crypter.
			 * @return A pointer to the moved AES_GCM crypter.
			 */
			inline PointerType 									Move() noexcept override {
				return std::make_shared<AES_GCM>(std::move(*this));
			}

		private:
			/**
			 * @brief Implementation of the encryption logic.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool 												DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**
			 * @brief Implementation of the encryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			Buffer::Consumer 									DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;

			/**
			 * @brief Implementation of the decryption logic.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool 												DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept override;

			/**	
			 * @brief Implementation of the decryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			Buffer::Consumer 									DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept override;
	};
}