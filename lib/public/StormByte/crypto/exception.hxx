#pragma once

#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Exception
	 * @brief The class representing an exception in the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
		public:
			/**
			 * Constructor
			 */
			using StormByte::Exception::Exception;
	};
}