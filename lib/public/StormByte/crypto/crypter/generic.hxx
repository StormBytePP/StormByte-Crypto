#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/typedefs.hxx>
#include <StormByte/crypto/visibility.h>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @enum Type
	 * @brief The types of crypters available.
	 */
	enum class Type {
		AES_GCM,												///< AES Galois/Counter Mode
		AES,													///< AES Cipher Block Chaining Mode
		Camellia,												///< Camellia Cipher Block Chaining Mode
		ChaChaPoly,												///< ChaCha20-Poly1305 Authenticated Encryption
		ECC,													///< Elliptic Curve Cryptography Encryption
		Serpent,												///< Serpent Cipher Block Chaining Mode
		RSA,													///< RSA Asymmetric Encryption
		TwoFish,												///< TwoFish Cipher Block Chaining Mode
	};

	/**
	 * @class Generic
	 * @brief A generic crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic crypter to copy from.
			 */
			Generic(const Generic& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic crypter to move from.
			 */
			Generic(Generic&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic crypter to copy from.
			 * @return Reference to this Generic crypter.
			 */
			Generic& operator=(const Generic& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic crypter to move from.
			 * @return Reference to this Generic crypter.
			 */
			Generic& operator=(Generic&& other) noexcept		= default;

			/**
			 * @brief Encrypt data from input buffer to output buffer.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			inline bool 										Encrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(input, output);
			}

			/**
			 * @brief Encrypt data from input buffer to output buffer.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			inline bool 										Encrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Encrypt data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @return true if encryption was successful, false otherwise.
			 */
			inline bool 										Encrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoEncrypt(input, output, ReadMode::Move);
			}

			/**
			 * @brief Encrypt data from a Consumer buffer.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			inline Buffer::Consumer 							Encrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoEncrypt(consumer, mode);
			}

			/**
			 * @brief Decrypt data from input buffer to output buffer.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			inline bool 										Decrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(input, output);
			}

			/**
			 * @brief Decrypt data from input buffer to output buffer.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			inline bool 										Decrypt(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Decrypt data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @return true if decryption was successful, false otherwise.
			 */
			inline bool 										Decrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoDecrypt(input, output, ReadMode::Move);
			}

			/**
			 * @brief Decrypt data from a Consumer buffer.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			inline Buffer::Consumer 							Decrypt(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoDecrypt(consumer, mode);
			}

			/**
			 * @brief Gets the type of crypter.
			 * @return The type of crypter.
			 */
			inline enum Type 									Type() const noexcept {
				return m_type;
			}

		protected:
			enum Type m_type;									///< The type of crypter

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 */
			inline 												Generic(enum Type type):
			m_type(type) {}

		private:
			/**
			 * @brief Implementation of the decryption logic.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if decryption was successful, false otherwise.
			 */
			bool 												DoDecrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the encryption logic.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if encryption was successful, false otherwise.
			 */
			virtual bool 										DoEncrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the encryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to encrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the encrypted data.
			 */
			virtual Buffer::Consumer 							DoEncrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Implementation of the encryption logic.
			 * @param input The input buffer to encrypt.
			 * @param output The output buffer to write the encrypted data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if encryption was successful, false otherwise.
			 */
			bool 												DoEncrypt(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the decryption logic.
			 * @param input The input buffer to decrypt.
			 * @param output The output buffer to write the decrypted data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if decryption was successful, false otherwise.
			 */
			virtual bool 										DoDecrypt(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the decryption logic for Consumer buffers.
			 * @param consumer The Consumer buffer to decrypt.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the decrypted data.
			 */
			virtual Buffer::Consumer 							DoDecrypt(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;
	};
}