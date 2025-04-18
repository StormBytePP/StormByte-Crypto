#pragma once

#include <StormByte/crypto/visibility.h>

/**
 * @namespace Algorithm
 * @brief The namespace containing cryptographic algorithms.
 */
namespace StormByte::Crypto::Algorithm {
	/**
	 * @enum Asymmetric
	 * @brief Enum representing the type of asymmetric encryption algorithms.
	 */
	enum class STORMBYTE_CRYPTO_PUBLIC Asymmetric {
		ECC,				///> Elliptic Curve Cryptography (ECC) encryption
		RSA,				///> RSA encryption
	};

	/**
	 * @enum Symmetric
	 * @brief Enum representing the type of symmetric encryption algorithms.
	 */
	enum class STORMBYTE_CRYPTO_PUBLIC Symmetric {
		None = 0,			///> No encryption
		AES,				///> AES encryption
	};

	/**
	 * @enum Compress
	 * @brief Enum representing the type of compression algorithms.
	 */
	enum class STORMBYTE_CRYPTO_PUBLIC Compress {
		None = 0,			///> No compression
		Bzip2,				///> Bzip2 compression
		Gzip,				///> Gzip compression
	};

	/**
	 * @enum Hash
	 * @brief Enum representing the type of hash algorithms.
	 */
	enum class STORMBYTE_CRYPTO_PUBLIC Hash {
		Blake2b,			///> Blake2b hash algorithm
		Blake2s,			///> Blake2s hash algorithm
		SHA256,				///> SHA256 hash algorithm
		SHA512,				///> SHA512 hash algorithm
	};

	/**
	 * @enum Sign
	 * @brief Enum representing the type of signing algorithms.
	 */
	enum class STORMBYTE_CRYPTO_PUBLIC Sign {
		DSA,				///> Digital Signature Algorithm (DSA)
	};
}