#pragma once

#include <StormByte/crypto/keypair/generic.hxx>

/**
 * @namespace Secret
 * @brief The namespace containing all the secret-related classes.
 */
namespace StormByte::Crypto::Secret {
	/**
	 * @enum Type
	 * @brief The types of secrets available.
	 */
	enum class Type {
		ECDH,													///< Elliptic Curve Diffie-Hellman
		X25519,													///< X25519 Elliptic Curve Diffie-Hellman
	};

	/**
	 * @class Generic
	 * @brief A generic secret class.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Generic: public StormByte::Clonable<Generic> {
		public:
			/**
			 * @brief Copy constructor
			 * @param other The other Generic secret to copy from.
			 */
			Generic(const Generic& other)						= default;

			/**
			 * @brief Move constructor
			 * @param other The other Generic secret to move from.
			 */
			Generic(Generic&& other) noexcept					= default;

			/**
			 * @brief Virtual destructor
			 */
			virtual ~Generic() noexcept 						= default;

			/**
			 * @brief Copy assignment operator
			 * @param other The other Generic secret to copy from.
			 * @return Reference to this Generic secret.
			 */
			Generic& operator=(const Generic& other)			= default;

			/**
			 * @brief Move assignment operator
			 * @param other The other Generic secret to move from.
			 * @return Reference to this Generic secret.
			 */
			Generic& operator=(Generic&& other) noexcept		= default;

			/**
			 * @brief Gets the keypair used for secret sharing
			 * @return The keypair.
			 */
			KeyPair::Generic::PointerType 						KeyPair() const noexcept {
				return m_keypair;
			}

			/**
			 * @brief Gets the type of the secret share generator used for secret sharing
			 * @return The type of the secret share generator.
			 */
			enum Type											Type() const noexcept {
				return m_type;
			}

			/**
			 * @brief Shares the secret with a peer using their public key.
			 * @param peerPublicKey The peer's public key.
			 * @return An optional string containing the shared secret, or std::nullopt on failure.
			 */
			inline std::optional<std::string>					Share(const std::string& peerPublicKey) const noexcept {
				return DoShare(peerPublicKey);
			}

		protected:
			enum Type m_type;									///< The type of secret generator
			KeyPair::Generic::PointerType m_keypair;			///< The keypair used for secret sharing

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												Generic(enum Type type, KeyPair::Generic::PointerType keypair):
			m_type(type), m_keypair(keypair) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												Generic(enum Type type, const KeyPair::Generic& keypair):
			m_type(type), m_keypair(keypair.Clone()) {}

			/**
			 * @brief Constructor
			 * @param keypair The keypair used for secret sharing.
			 */
			inline 												Generic(enum Type type, KeyPair::Generic&& keypair):
			m_type(type), m_keypair(keypair.Move()) {}

		private:
			/**
			 * @brief Shares the secret with a peer using their public key.
			 * @param peerPublicKey The peer's public key.
			 * @return An optional string containing the shared secret, or std::nullopt on failure.
			 */
			virtual std::optional<std::string>					DoShare(const std::string& peerPublicKey) const noexcept = 0;
	};

	/**
	 * @brief Creates a secret share generator based on the type.
	 * @param type The type of secret share generator.
	 * @param keypair The keypair used for secret sharing.
	 * @return A pointer to the created secret share generator.
	 */
	STORMBYTE_CRYPTO_PUBLIC Generic::PointerType 				Create(enum Type type, KeyPair::Generic::PointerType keypair) noexcept;
}