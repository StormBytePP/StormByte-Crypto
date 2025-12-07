#pragma once

#include <StormByte/crypto/crypter/generic.hxx>
#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace Crypter
 * @brief The namespace containing all the crypter-related classes.
 */
namespace StormByte::Crypto::Crypter {
	/**
	 * @class Asymmetric
	 * @brief A generic asymmetric crypter class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Asymmetric: public Generic {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Asymmetric crypter to copy from.
			 */
			Asymmetric(const Asymmetric& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Asymmetric crypter to move from.
			 */
			Asymmetric(Asymmetric&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Asymmetric() noexcept 							= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Asymmetric crypter to copy from.
			 * @return Reference to this Asymmetric crypter.
			 */
			Asymmetric& operator=(const Asymmetric& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Asymmetric crypter to move from.
			 * @return Reference to this Asymmetric crypter.
			 */
			Asymmetric& operator=(Asymmetric&& other) noexcept		= default;

			/**
			 * @brief Gets the keypair used for asymmetric encryption.
			 * @return The keypair.
			 */
			KeyPair::Generic::PointerType 							KeyPair() const noexcept {
				return m_keypair;
			}

		protected:
			KeyPair::Generic::PointerType m_keypair;				///< The password used for asymmetric encryption

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Asymmetric(enum Type type, KeyPair::Generic::PointerType keypair):
			Generic(type), m_keypair(keypair) {}

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Asymmetric(enum Type type, const KeyPair::Generic& keypair):
			Generic(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param type The type of crypter.
			 * @param keypair The keypair used for asymmetric encryption.
			 */
			inline 													Asymmetric(enum Type type, KeyPair::Generic&& keypair):
			Generic(type), m_keypair(keypair.Move()) {}
	};

	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;
	
	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, const KeyPair::Generic& keypair) noexcept;

	/**
	 * @brief Creates an Asymmetric crypter of the specified type using the provided keypair.
	 * @param type The type of crypter to create.
	 * @param keypair The keypair to use for the crypter.
	 * @return A pointer to the created Asymmetric crypter.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 					Create(enum Type type, KeyPair::Generic&& keypair) noexcept;
}