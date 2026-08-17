#pragma once

#include <StormByte/buffer/generic.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <memory>

/**
 * @namespace Crypto
 * @brief The namespace containing all the cryptographic-related classes.
 */
namespace StormByte::Crypto {
	class Password;
	
	/**
	 * @enum ReadMode
	 * @brief The types of data operations.
	 */
	enum class ReadMode: unsigned short {
		Copy,											///< Indicates a copy operation
		Move											///< Indicates a move operation
	};

	using ExpectedPassword = StormByte::Expected<Password, Exception>;
}