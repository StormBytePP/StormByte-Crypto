#pragma once

#include <StormByte/buffers/consumer.hxx>
#include <StormByte/crypto/algorithm.hxx>
#include <StormByte/crypto/exception.hxx>
#include <StormByte/expected.hxx>

#include <string>

/**
 * @namespace Crypto
 * @brief The namespace containing all cryptographic-related classes.
 */
namespace StormByte::Crypto {
	/**
	 * @class Hasher
	 * @brief A class for managing hashing operations.
	 *
	 * This class provides methods for hashing data using various hashing algorithms.
	 */
	class STORMBYTE_CRYPTO_PUBLIC Hasher final {
		public:
			/**
			 * @brief Initializes a Hasher instance with the specified hashing algorithm.
			 * @param algorithm The hashing algorithm to use.
			 */
			explicit Hasher(const Algorithm::Hash& algorithm) noexcept;

			/**
			 * @brief Copy constructor for the Hasher class.
			 * @param hasher The Hasher instance to copy.
			 */
			Hasher(const Hasher& hasher) 					= default;

			/**
			 * @brief Move constructor for the Hasher class.
			 * @param hasher The Hasher instance to move.
			 */
			Hasher(Hasher&& hasher) noexcept 				= default;

			/**
			 * @brief Destructor for the Hasher class.
			 */
			~Hasher() noexcept 								= default;

			/**
			 * @brief Copy assignment operator for the Hasher class.
			 * @param hasher The Hasher instance to copy.
			 * @return A reference to the updated Hasher instance.
			 */
			Hasher& operator=(const Hasher& hasher) 		= default;

			/**
			 * @brief Move assignment operator for the Hasher class.
			 * @param hasher The Hasher instance to move.
			 * @return A reference to the updated Hasher instance.
			 */
			Hasher& operator=(Hasher&& hasher) noexcept 	= default;

			/**
			 * @brief Hashes a string input using the specified hashing algorithm.
			 * @param input The string to hash.
			 * @return An Expected containing the hashed string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception>				Hash(const std::string& input) const noexcept;

			/**
			 * @brief Hashes a buffer using the specified hashing algorithm.
			 * @param buffer The buffer to hash.
			 * @return An Expected containing the hashed string or an error.
			 */
			[[nodiscard]]
			Expected<std::string, Exception>				Hash(const Buffers::Simple& buffer) const noexcept;

			/**
			 * @brief Hashes data asynchronously using a Consumer/Producer model.
			 * @param consumer The Consumer buffer containing the input data.
			 * @return A Consumer buffer containing the hashed data.
			 */
			[[nodiscard]]
			Buffers::Consumer 								Hash(const Buffers::Consumer consumer) const noexcept;

		private:
			const Algorithm::Hash m_algorithm; ///< The hashing algorithm to use.
	};
}