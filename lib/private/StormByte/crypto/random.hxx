#pragma once

#include <StormByte/crypto/visibility.h>

#include <osrng.h>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @brief Get the global RNG instance.
	 * @return Reference to the global AutoSeededRandomPool instance.
	 */
	STORMBYTE_CRYPTO_PRIVATE CryptoPP::AutoSeededRandomPool& RNG();
}