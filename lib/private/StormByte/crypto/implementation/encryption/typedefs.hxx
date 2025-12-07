#pragma once

#include <StormByte/crypto/exception.hxx>
#include <StormByte/crypto/implementation/typedefs.hxx>

/**
 * @namespace Encryption
 * @brief The namespace containing Encryption functions
 */
namespace StormByte::Crypto::Implementation::Encryption {
	/**
	 * @struct KeyPair
	 * @brief The struct containing private and public keys
	 */
	struct STORMBYTE_CRYPTO_PRIVATE KeyPair {
		std::string Private;														///< The private key.
		std::string Public;															///< The public key.
	};

	using ExpectedCryptoBuffer = StormByte::Expected<Buffer::FIFO, Exception>;		///< The expected crypto buffer type.
	using ExpectedCryptoString = StormByte::Expected<std::string, Exception>;		///< The expected crypto string type.
	using ExpectedKeyPair = StormByte::Expected<KeyPair, Exception>;				///< The expected key pair type.
}