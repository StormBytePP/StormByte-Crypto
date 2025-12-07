#pragma once

#include <StormByte/buffer/consumer.hxx>
#include <StormByte/clonable.hxx>
#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace Signer
 * @brief The namespace containing all the signer-related classes.
 */
namespace StormByte::Crypto::Signer {
	/**
	 * @enum Type
	 * @brief The types of signers available.
	 */
	enum class Type {
		DSA,															///< Digital Signature Algorithm
		ECDSA,															///< Elliptic Curve Digital Signature Algorithm
		ED25519,														///< Edwards-curve Digital Signature Algorithm
		RSA,															///< RSA Asymmetric Signing
	};

	/**
	 * @class Generic
	 * @brief A generic signer class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic signer to copy from.
			 */
			Generic(const Generic& other)								= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic signer to move from.
			 */
			Generic(Generic&& other) noexcept							= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 								= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic signer to copy from.
			 * @return Reference to this Generic signer.
			 */
			Generic& operator=(const Generic& other)					= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic signer to move from.
			 * @return Reference to this Generic signer.
			 */
			Generic& operator=(Generic&& other) noexcept				= default;

			/**
			 * @brief Gets the keypair used for asymmetric encryption.
			 * @return The keypair.
			 */
			KeyPair::Generic::PointerType 							KeyPair() const noexcept {
				return m_keypair;
			}

			/**
			 * @brief Sign data from input span to output buffer.
			 * @param input The input data span to sign.
			 * @param output The output buffer to write the signed data to.
			 * @return true if signing was successful, false otherwise.
			 */
			inline bool 											Sign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(input, output);
			}

			/**
			 * @brief Sign data from input buffer to output buffer.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @return true if signing was successful, false otherwise.
			 */
			inline bool 											Sign(const Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(const_cast<Buffer::ReadOnly&>(input), output, ReadMode::Copy);
			}

			/**
			 * @brief Sign data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @return true if signing was successful, false otherwise.
			 */
			inline bool 											Sign(Buffer::ReadOnly& input, Buffer::WriteOnly& output) const noexcept {
				return DoSign(input, output, ReadMode::Move);
			}

			/**
			 * @brief Sign data from a Consumer buffer.
			 * @param consumer The Consumer buffer to sign.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the signed data.
			 */
			inline Buffer::Consumer 								Sign(Buffer::Consumer consumer, ReadMode mode = ReadMode::Move) const noexcept {
				return DoSign(consumer, mode);
			}

			/**
			 * @brief Verify data from input span to output buffer.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			inline bool 											Verify(std::span<const std::byte> input, const std::string& signature) const noexcept {
				return DoVerify(input, signature);
			}

			/**
			 * @brief Verify data from input buffer to output buffer.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			inline bool 											Verify(const Buffer::ReadOnly& input, const std::string& signature) const noexcept {
				return DoVerify(const_cast<Buffer::ReadOnly&>(input), signature, ReadMode::Copy);
			}

			/**
			 * @brief Verify data from input buffer to output buffer, moving the input data.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			inline bool 											Verify(Buffer::ReadOnly& input, const std::string& signature) const noexcept {
				return DoVerify(input, signature, ReadMode::Move);
			}

			/**
			 * @brief Verify data from a Consumer buffer.
			 * @param consumer The Consumer buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the verified data.
			 */
			inline bool 											Verify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode = ReadMode::Move) const noexcept {
				return DoVerify(consumer, signature, mode);
			}

		protected:
			enum Type m_type;										///< The type of signer
			KeyPair::Generic::PointerType m_keypair;				///< The password used for asymmetric encryption

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Generic(enum Type type, KeyPair::Generic::PointerType keypair):
			m_type(type), m_keypair(keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Generic(enum Type type, const KeyPair::Generic& keypair):
			m_type(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param type The type of signer.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Generic(enum Type type, KeyPair::Generic&& keypair):
			m_type(type), m_keypair(keypair.Move()) {}

		private:
			/**
			 * @brief Implementation of the signing logic.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if signing was successful, false otherwise.
			 */
			bool 													DoSign(Buffer::ReadOnly& input, Buffer::WriteOnly& output, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the signing logic.
			 * @param input The input buffer to sign.
			 * @param output The output buffer to write the signed data to.
			 * @param mode The read mode indicating copy or move.
			 * @return true if signing was successful, false otherwise.
			 */
			virtual bool 											DoSign(std::span<const std::byte> input, Buffer::WriteOnly& output) const noexcept = 0;

			/**
			 * @brief Implementation of the signing logic for Consumer buffers.
			 * @param consumer The Consumer buffer to sign.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the signed data.
			 */
			virtual Buffer::Consumer 								DoSign(Buffer::Consumer consumer, ReadMode mode) const noexcept = 0;

			/**
			 * @brief Implementation of the verification logic.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return true if verification was successful, false otherwise.
			 */
			bool 													DoVerify(Buffer::ReadOnly& input, const std::string& signature, ReadMode mode) const noexcept;

			/**
			 * @brief Implementation of the verification logic.
			 * @param input The input buffer to verify.
			 * @param signature The signature to verify against.
			 * @return true if verification was successful, false otherwise.
			 */
			virtual bool 											DoVerify(std::span<const std::byte> input, const std::string& signature) const noexcept = 0;

			/**
			 * @brief Implementation of the verification logic for Consumer buffers.
			 * @param consumer The Consumer buffer to verify.
			 * @param signature The signature to verify against.
			 * @param mode The read mode indicating copy or move.
			 * @return A Consumer buffer containing the verified data.
			 */
			virtual bool 											DoVerify(Buffer::Consumer consumer, const std::string& signature, ReadMode mode) const noexcept = 0;
	};

	/**
	 * @brief Creates a signer of the specified type using the provided keypair.
	 * @param type The type of signer to create.
	 * @param keypair The keypair to use for the signer.
	 * @return A pointer to the created Generic signer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;
	
	/**
	 * @brief Creates a signer of the specified type using the provided keypair.
	 * @param type The type of signer to create.
	 * @param keypair The keypair to use for the signer.
	 * @return A pointer to the created Generic signer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, const KeyPair::Generic& keypair) noexcept;
	/**
	 * @brief Creates a signer of the specified type using the provided keypair.
	 * @param type The type of signer to create.
	 * @param keypair The keypair to use for the signer.
	 * @return A pointer to the created Generic signer.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
}