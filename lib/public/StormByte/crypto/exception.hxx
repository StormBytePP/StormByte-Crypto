#pragma once

#include <StormByte/crypto/visibility.h>
#include <StormByte/exception.hxx>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Exception
	 * @brief A class representing an exception in the crypto module.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Exception: public StormByte::Exception {
		public:
			/**
			 * @brief Constructor
			 * @param message The exception message.
			 */
			using StormByte::Exception::Exception;
	};
}