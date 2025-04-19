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
	class STORMBYTE_CRYPTO_PUBLIC Hasher final {
		public:
			/**
			 * @brief Initializes a Hasher instance with the specified hashing algorithm.
			 * @param algorithm The hashing algorithm to use
			 */
			explicit Hasher(const Algorithm::Hash& algorithm) noexcept;

			Hasher(const Hasher& hasher) 					= default;

			Hasher(Hasher&& hasher) noexcept 				= default;

			~Hasher() noexcept 								= default;

			Hasher& operator=(const Hasher& hasher) 		= default;

			Hasher& operator=(Hasher&& hasher) noexcept 	= default;

			Expected<std::string, Exception>				Hash(const std::string& input) const noexcept;

			Expected<std::string, Exception>				Hash(const Buffers::Simple& buffer) const noexcept;

			Buffers::Consumer 								Hash(const Buffers::Consumer consumer) const noexcept;

		private:
			const Algorithm::Hash m_algorithm;
	};
}